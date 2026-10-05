// Copyright (c) 2021 Kata Maintainers
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(not(target_arch = "s390x"))]
use crate::linux_abi::{create_pci_root_bus_path, pcipath_from_dev_tree_path, SYSFS_DIR};
#[cfg(not(target_arch = "s390x"))]
use crate::{device::pcipath_to_sysfs, pci};
use anyhow::{anyhow, Context, Result};
// Slog-style logger scope. Mirrors the per-module sl() pattern used
// across the kata-agent (rpc.rs, metrics.rs, etc.) — gives nearby
// info!() calls a scope without forcing every caller of update_interface
// to thread a logger through their signatures.
#[allow(dead_code)]
fn sl() -> slog::Logger {
    slog_scope::logger()
}

/// How the kernel answered one SOCK_DESTROY request — the nlmsgerr code of
/// the NLM_F_ACK'd reply. Netlink only reports success when an ACK is
/// requested, so without reading these replies a "destroyed" count reflects
/// sends, not kills. Pure classification so unit tests cover the protocol
/// logic without a netlink socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestroyReply {
    /// nlmsgerr code 0: the kernel ACKed the destroy.
    Confirmed,
    /// ENOENT: the socket vanished between the dump and the destroy.
    AlreadyGone,
    /// EOPNOTSUPP: the guest kernel was built without
    /// CONFIG_INET_DIAG_DESTROY — no destroy will EVER succeed on this
    /// kernel, so callers must stop and log loudly instead of pretending.
    Unsupported,
    /// Any other errno (negative code preserved for the log).
    Failed(i32),
}

fn classify_destroy_reply(code: i32) -> DestroyReply {
    if code == 0 {
        return DestroyReply::Confirmed;
    }
    match -code {
        libc::ENOENT => DestroyReply::AlreadyGone,
        libc::EOPNOTSUPP => DestroyReply::Unsupported,
        _ => DestroyReply::Failed(code),
    }
}

/// Best-effort: destroy the guest's own TCP and UDP sockets still bound to
/// `ip` after that address has been removed from the interface during a
/// live-migration renumber (spec 022 FR-059 / FR-062c).
///
/// The workload's pre-existing external connections (e.g. a DB pool) read
/// ESTABLISHED but their wire path is dead once the source pod IP is gone —
/// the guest would otherwise hoard them across every hop, and the matching
/// half-open peers (e.g. an RDS instance) accumulate as zombies until their
/// own keepalive reaps them, eventually exhausting the database. SOCK_DESTROY
/// closes them locally so the pool reconnects promptly over the new address.
/// Connected UDP sockets bound to the removed address would keep transmitting
/// from a stale source address indefinitely, so they are destroyed too.
///
/// Every destroy requests an NLM_F_ACK and the reply is read back, so the
/// summary log reports CONFIRMED kills vs attempts — a kernel without
/// CONFIG_INET_DIAG_DESTROY is detected (EOPNOTSUPP) and warned about loudly
/// instead of logging a success that never happened.
///
/// STRICTLY best-effort: every error is logged and swallowed. Callers MUST
/// invoke this fire-and-forget (e.g. `spawn_blocking`) so it can never block
/// or fail the renumber, even if the netlink call misbehaves.
/// What one reap did, per protocol summed together. Returned rather than only
/// logged: a caller that cannot see the agent's log still needs to know
/// whether anything was actually closed (spec 022 FR-062c).
#[derive(Debug, Default, Clone, Copy)]
pub struct DestroySummary {
    /// Sockets the dump found bound to the removed address.
    pub attempted: usize,
    /// Destroys the kernel acknowledged.
    pub confirmed: usize,
    /// Sockets that had already gone between the dump and the destroy.
    pub already_gone: usize,
    /// Destroys that were sent but not acknowledged.
    pub failed: usize,
    /// The dump itself errored — the kernel cannot enumerate sockets, so
    /// nothing can ever be reaped on it.
    pub dump_failed: bool,
    /// The kernel answered EOPNOTSUPP: built without CONFIG_INET_DIAG_DESTROY.
    pub unsupported: bool,
}

impl DestroySummary {
    /// True when this reap cannot have helped: either it could not look, or it
    /// looked, found work, and closed none of it.
    fn ineffective(&self) -> bool {
        self.dump_failed || self.unsupported || (self.attempted > 0 && self.confirmed == 0)
    }
}

fn destroy_stale_sockets_bound_to(ip: IpAddr) -> DestroySummary {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_sock_diag::{
        constants::{AF_INET, AF_INET6, IPPROTO_TCP},
        inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
        SockDiagMessage,
    };
    use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
    use std::os::unix::io::AsRawFd;

    // SOCK_DESTROY message type (linux/sock_diag.h); not always re-exported.
    const SOCK_DESTROY: u16 = 21;
    // IPPROTO_UDP (the sock-diag crate only re-exports IPPROTO_TCP).
    const PROTO_UDP: u8 = 17;

    // Which families can hold a socket bound to this address, and what the
    // address looks like in each.
    //
    // A v4 address is not only in the v4 table: a dual-stack listener binds
    // `::` and every connection it accepts lives in the AF_INET6 table as
    // ::ffff:a.b.c.d. Dumping AF_INET alone finds nothing for exactly the
    // workloads that matter — measured on a migrated JVM whose /proc/net/tcp
    // was empty while /proc/net/tcp6 held the lot (spec 022 FR-059).
    let families: Vec<(u8, SocketId, IpAddr)> = match ip {
        IpAddr::V4(v4) => vec![
            (AF_INET, SocketId::new_v4(), ip),
            (AF_INET6, SocketId::new_v6(), IpAddr::V6(v4.to_ipv6_mapped())),
        ],
        IpAddr::V6(_) => vec![(AF_INET6, SocketId::new_v6(), ip)],
    };

    let mut socket = match Socket::new(NETLINK_SOCK_DIAG) {
        Ok(s) => s,
        Err(e) => {
            warn!(sl(), "sock-destroy: open NETLINK_SOCK_DIAG failed — no stale socket can be reaped";
                "err" => format!("{:?}", e));
            return DestroySummary { dump_failed: true, ..Default::default() };
        }
    };
    if socket.bind_auto().is_err() || socket.connect(&SocketAddr::new(0, 0)).is_err() {
        warn!(sl(), "sock-destroy: bind/connect failed — no stale socket can be reaped");
        return DestroySummary { dump_failed: true, ..Default::default() };
    }

    // Bound every recv so a missing/garbled DUMP reply can NEVER hang this
    // blocking task forever (which would leak agent blocking-pool threads and
    // can wedge other agent RPCs such as exec). SO_RCVTIMEO makes recv return
    // an error after the deadline; the recv loop below already breaks on a recv
    // error. If we cannot set the timeout we MUST NOT proceed to the blocking
    // recv — bail entirely instead.
    {
        let tv = libc::timeval {
            tv_sec: 3,
            tv_usec: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            warn!(sl(), "sock-destroy: SO_RCVTIMEO set failed; skipping to avoid an unbounded recv");
            return DestroySummary { dump_failed: true, ..Default::default() };
        }
    }

    let started = std::time::Instant::now();
    let mut total = DestroySummary::default();
    let mut recv_buf = vec![0u8; 32 * 1024];
    let mut seq: u32 = 0;
    let mut kernel_unsupported = false;

    for (family, dump_sid, want) in &families {
      let (family, dump_sid, want) = (*family, dump_sid.clone(), *want);
      for proto in [IPPROTO_TCP, PROTO_UDP] {
        let proto_name = if proto == IPPROTO_TCP { "tcp" } else { "udp" };

        // 1) DUMP all sockets of this protocol/family; collect those bound
        //    to `ip`.
        seq += 1;
        let mut req = NetlinkMessage::from(SockDiagMessage::InetRequest(InetRequest {
            family,
            protocol: proto,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id: dump_sid.clone(),
        }));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.header.sequence_number = seq;
        req.finalize();
        let mut buf = vec![0u8; req.buffer_len()];
        req.serialize(&mut buf[..]);
        if socket.send(&buf[..], 0).is_err() {
            warn!(sl(), "sock-destroy: dump send failed"; "proto" => proto_name);
            total.dump_failed = true;
            continue;
        }

        let mut targets: Vec<SocketId> = Vec::new();
        let mut recv_iters = 0usize;
        'recv: loop {
            // Hard cap on iterations as a second backstop to the recv timeout,
            // so the dump can never spin indefinitely even if recv keeps
            // returning.
            recv_iters += 1;
            if recv_iters > 1024 {
                break;
            }
            let n = match socket.recv(&mut &mut recv_buf[..], 0) {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            let mut offset = 0;
            while offset < n {
                let rx = match NetlinkMessage::<SockDiagMessage>::deserialize(&recv_buf[offset..n])
                {
                    Ok(m) => m,
                    Err(_) => break 'recv,
                };
                let len = rx.header.length as usize;
                match rx.payload {
                    NetlinkPayload::Done(_) => break 'recv,
                    NetlinkPayload::Error(e) => {
                        // A dump-level error means the kernel cannot even
                        // enumerate sockets — most likely CONFIG_INET_DIAG
                        // is not set, in which case the whole reap is a
                        // no-op every migration. That MUST be loud: this
                        // exact failure was silent in production while
                        // stale sockets leaked to external peers on every
                        // hop (spec 022 FR-066b).
                        let code = e.code.map(|c| c.get()).unwrap_or(0);
                        if code != 0 {
                            total.dump_failed = true;
                            warn!(sl(), "sock-destroy: socket-diag DUMP failed — kernel likely lacks CONFIG_INET_DIAG; \
                                stale sockets bound to removed IPs CANNOT be reaped and will leak to peers every migration";
                                "proto" => proto_name, "code" => code);
                        }
                        break 'recv;
                    }
                    NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                        if resp.header.socket_id.source_address == want {
                            targets.push(resp.header.socket_id.clone());
                        }
                    }
                    _ => {}
                }
                if len == 0 {
                    break 'recv;
                }
                offset += len;
            }
        }

        // 2) SOCK_DESTROY each matching socket by its exact id (incl. cookie),
        //    requesting an ACK so the kernel reports the outcome — netlink is
        //    silent on success otherwise, and a send-count would claim kills
        //    that never happened (e.g. CONFIG_INET_DIAG_DESTROY missing).
        let attempted = targets.len();
        let mut confirmed = 0usize;
        let mut already_gone = 0usize;
        let mut failed = 0usize;
        'destroy: for sid in targets {
            seq += 1;
            let mut d = NetlinkMessage::from(SockDiagMessage::InetRequest(InetRequest {
                family,
                protocol: proto,
                extensions: ExtensionFlags::empty(),
                states: StateFlags::all(),
                socket_id: sid,
            }));
            d.header.flags = NLM_F_REQUEST | NLM_F_ACK;
            d.header.sequence_number = seq;
            d.finalize();
            d.header.message_type = SOCK_DESTROY; // override after finalize
            let mut dbuf = vec![0u8; d.buffer_len()];
            d.serialize(&mut dbuf[..]);
            if socket.send(&dbuf[..], 0).is_err() {
                failed += 1;
                continue;
            }
            // One request in flight at a time on a connected socket: the next
            // message is this destroy's nlmsgerr reply (code 0 = ACK).
            // Bounded by the SO_RCVTIMEO set above.
            let n = match socket.recv(&mut &mut recv_buf[..], 0) {
                Ok(n) if n > 0 => n,
                _ => {
                    failed += 1;
                    continue;
                }
            };
            let reply = match NetlinkMessage::<SockDiagMessage>::deserialize(&recv_buf[..n]) {
                Ok(rx) => match rx.payload {
                    NetlinkPayload::Error(e) => {
                        classify_destroy_reply(e.code.map(|c| c.get()).unwrap_or(0))
                    }
                    // Anything else is an unexpected reply shape; count it as
                    // unconfirmed rather than guessing.
                    _ => DestroyReply::Failed(0),
                },
                Err(_) => DestroyReply::Failed(0),
            };
            match reply {
                DestroyReply::Confirmed => confirmed += 1,
                DestroyReply::AlreadyGone => already_gone += 1,
                DestroyReply::Unsupported => {
                    kernel_unsupported = true;
                    break 'destroy;
                }
                DestroyReply::Failed(code) => {
                    failed += 1;
                    info!(sl(), "sock-destroy: destroy not acked";
                        "proto" => proto_name, "code" => code);
                }
            }
        }

        total.attempted += attempted;
        total.confirmed += confirmed;
        total.already_gone += already_gone;
        total.failed += failed;

        if attempted > 0 && confirmed == 0 {
            // Had work and did none of it. This is the shape the leak takes:
            // the peer keeps its half open, and the next hop adds another set.
            warn!(sl(), "sock-destroy: found stale sockets and closed NONE of them";
                "ip" => ip.to_string(),
                "proto" => proto_name,
                "attempted" => attempted,
                "already_gone" => already_gone,
                "failed" => failed,
                "elapsed_ms" => started.elapsed().as_millis() as u64,
            );
        } else if attempted > 0 {
            info!(sl(), "sock-destroy: reaped stale workload sockets bound to removed source IP";
                "ip" => ip.to_string(),
                "proto" => proto_name,
                "attempted" => attempted,
                "confirmed" => confirmed,
                "already_gone" => already_gone,
                "failed" => failed,
                "elapsed_ms" => started.elapsed().as_millis() as u64,
            );
        }

        if kernel_unsupported {
            total.unsupported = true;
            // No destroy will EVER succeed on this kernel; warn once, loudly,
            // instead of silently accumulating connection zombies every hop.
            warn!(sl(), "sock-destroy: guest kernel lacks CONFIG_INET_DIAG_DESTROY (EOPNOTSUPP) — \
                stale sockets bound to removed IPs CANNOT be reaped; external connection zombies \
                will accumulate across migrations until peers reap them";
                "ip" => ip.to_string());
            break;
        }
      }
      if kernel_unsupported {
          break;
      }
    }

    // The same summary as a file, beside the demote markers written above.
    // Every log channel out of a guest is optional — this one is not, and a
    // reap that quietly did nothing is the failure being guarded against.
    let _ = std::fs::write(
        format!("/tmp/kata-agent-sock-destroy-{}", ip),
        format!(
            "ip={} attempted={} confirmed={} already_gone={} failed={} dump_failed={} unsupported={} elapsed_ms={}\n",
            ip,
            total.attempted,
            total.confirmed,
            total.already_gone,
            total.failed,
            total.dump_failed,
            total.unsupported,
            started.elapsed().as_millis() as u64,
        ),
    );

    total
}

use futures::{future, StreamExt, TryStreamExt};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::neighbour::NeighbourFlags;
use netlink_packet_route::route::{RouteHeader, RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    route::RouteMetric,
};
use netlink_packet_route::{
    neighbour::NeighbourState,
    route::{RouteAddress, RouteAttribute, RouteMessage},
};
use nix::errno::Errno;
use protocols::types::{ARPNeighbor, IPAddress, IPFamily, Interface, Route};
use rtnetlink::{new_connection, IpVersion, LinkUnspec, RouteMessageBuilder};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str::{self, FromStr};

/// Search criteria to use when looking for a link in `find_link`.
#[derive(Clone, Copy)]
pub enum LinkFilter<'a> {
    /// Find by link name.
    Name(&'a str),
    /// Find by link index.
    Index(u32),
    /// Find by MAC address.
    Address(&'a str),
}

impl fmt::Display for LinkFilter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkFilter::Name(name) => write!(f, "Name: {name}"),
            LinkFilter::Index(idx) => write!(f, "Index: {idx}"),
            LinkFilter::Address(addr) => write!(f, "Address: {addr}"),
        }
    }
}

const ALL_RULE_FLAGS: NeighbourFlags = NeighbourFlags::all();

/// A filter to query addresses.
pub enum AddressFilter {
    /// Return addresses that belong to the given interface.
    LinkIndex(u32),
    /// Get addresses with the given prefix.
    #[allow(dead_code)]
    IpAddress(IpAddr),
}

/// A high level wrapper for netlink (and `rtnetlink` crate) for use by the Agent's RPC.
/// It is expected to be consumed by the `AgentService`, so it operates with protobuf
/// structures directly for convenience.
#[derive(Debug)]
pub struct Handle {
    handle: rtnetlink::Handle,
}

impl Handle {
    pub(crate) fn new() -> Result<Handle> {
        let (conn, handle, _) = new_connection()?;
        tokio::spawn(conn);

        Ok(Handle { handle })
    }

    pub async fn update_interface(&mut self, iface: &Interface) -> Result<()> {
        // The reliable way to find link is using hardware address
        // as filter. However, hardware filter might not be supported
        // by netlink, we may have to dump link list and then find the
        // target link. filter using name or family is supported, but
        // we cannot use that to find target link.
        // let's try if hardware address filter works. -_-
        //
        // A NIC captured in a VM template is the exception. VMMs without
        // device hot-plug -- e.g. Dragonball, whose virtio-mmio transport has
        // no native hot-plug -- cannot attach a fresh NIC to the restored VM
        // per pod, so the NIC is baked into the template. A pod restored from
        // that template keeps the template creator's MAC, frozen in the
        // snapshotted guest RAM, and can never be matched by this pod's MAC.
        // Fall back to finding the interface by its (stable) name and
        // retargeting it to the requested MAC, then look it up again. This
        // assumes a deterministic interface name (true for a single-NIC pod,
        // where both sides use "eth0").
        let link = match self
            .try_find_link(LinkFilter::Address(&iface.hwAddr))
            .await?
        {
            Some(link) => link,
            None => {
                self.set_link_mac_by_name(&iface.name, &iface.hwAddr)
                    .await?;
                self.find_link(LinkFilter::Address(&iface.hwAddr)).await?
            }
        };
        let link_index = link.index();

        // Bring down interface if it is UP
        if link.is_up() {
            self.enable_link(link.index(), false).await?;
        }

        // Get whether the network stack has ipv6 enabled or disabled.
        let supports_ipv6_all = fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        let supports_ipv6_default =
            fs::read_to_string("/proc/sys/net/ipv6/conf/default/disable_ipv6")
                .map(|s| s.trim() == "0")
                .unwrap_or(false);
        let supports_ipv6 = supports_ipv6_default || supports_ipv6_all;

        // Add new ip addresses from request
        for ip_address in &iface.IPAddresses {
            let ip = IpAddr::from_str(ip_address.address())?;
            let mask = ip_address.mask().parse::<u8>()?;

            let net = IpNetwork::new(ip, mask)?;
            if !net.is_ipv4() && !supports_ipv6 {
                // If we're dealing with an ipv6 address, but the stack does not
                // support ipv6, skip adding it otherwise it will lead to an
                // error at the "CreatePodSandbox" time.
                continue;
            }

            self.add_addresses(link.index(), std::iter::once(net))
                .await?;
        }

        // Migration fix: REMOVE any IPv4 address that's currently on
        // the link but ISN'T in the request. Don't re-add — gone for
        // good after this RPC.
        //
        // Background: after QEMU memory migration, the guest's eth0
        // still carries the SOURCE pod's IP (preserved verbatim in
        // the migrated kernel state). The shim's update_interface
        // call from pushDestIPsToGuestAgent sends the DESTINATION
        // pod's CNI IP; add_addresses places it on the interface
        // with NLM_F_REPLACE. Linux source-address selection
        // (inet_select_addr) walks the address list and picks the
        // FIRST address it finds — the source IP — for new outbound
        // packets. Cilium on the destination node doesn't recognize
        // the source IP as belonging to this endpoint (its IPCache
        // identity ledger only has the dest IP, since K8s
        // Pod.status.podIPs holds at most one IPv4) and drops the
        // replies. Symptom: DNS, fresh TCP/UDP connects, every new
        // outbound from the migrated guest hangs.
        //
        // Earlier attempt (del+re-add to demote to secondary) failed
        // observably: on a live kata-migrated guest the post-update
        // ifa_list still showed the source IP first. Either
        // rtnetlink's NEWADDR doesn't append on re-add in this
        // kernel path, or some other side effect put .source back at
        // head. Rather than chase the ordering bug, take the simpler
        // route: outright DELETE the stale source IP. With it gone
        // from ifa_list, Linux must pick the request IP as source
        // for new outbound. Existing TCP connections bound to the
        // old IP keep working at the socket layer (their src is
        // stored in the struct sock); they were already broken at
        // the Cilium egress filter anyway, so removing the local
        // address doesn't make those any worse.
        //
        // Keep IPv6 link-local untouched — needed for ND.
        //
        // No-op on a freshly-created sandbox: nothing else is on
        // the interface, so the list-and-skip pass is empty.
        let mut request_keys: std::collections::HashSet<(IpAddr, u8)> =
            std::collections::HashSet::new();
        for ip_address in &iface.IPAddresses {
            if let (Ok(ip), Ok(mask)) = (
                IpAddr::from_str(ip_address.address()),
                ip_address.mask().parse::<u8>(),
            ) {
                request_keys.insert((ip, mask));
            }
        }
        // DIAG marker A: prove we reached the demote block. Stored
        // in /tmp inside the guest; observable via `kubectl exec`.
        // Remove once we have confirmed the block runs end-to-end.
        let _ = std::fs::write(
            "/tmp/kata-agent-demote-block-entry",
            format!(
                "link_index={} hwaddr={} name={} request_keys_count={}\n",
                link.index(),
                iface.hwAddr,
                iface.name,
                request_keys.len()
            ),
        );

        let current = self
            .list_addresses(AddressFilter::LinkIndex(link.index()))
            .await
            .unwrap_or_default();

        // DIAG marker B: what list_addresses returned. Helps us see
        // whether we even know about the stale address.
        {
            let listing: Vec<String> = current
                .iter()
                .map(|a| format!("{}/{}", a.address(), a.prefix()))
                .collect();
            let _ = std::fs::write(
                "/tmp/kata-agent-demote-current",
                format!(
                    "request_keys={:?}\ncurrent={:?}\n",
                    request_keys, listing
                ),
            );
        }

        for addr in current {
            let ip_str = addr.address();
            let ip = match IpAddr::from_str(&ip_str) {
                Ok(ip) => ip,
                Err(_) => {
                    let _ = std::fs::write(
                        format!(
                            "/tmp/kata-agent-demote-skip-parse-{}",
                            ip_str.replace('/', "_")
                        ),
                        format!("ip_str={} parse_failed=true\n", ip_str),
                    );
                    continue;
                }
            };
            let prefix = addr.prefix();
            if request_keys.contains(&(ip, prefix)) {
                let _ = std::fs::write(
                    format!("/tmp/kata-agent-demote-keep-{}", ip),
                    format!("ip={} prefix={} in_request=true\n", ip, prefix),
                );
                continue;
            }
            let net = match IpNetwork::new(ip, prefix) {
                Ok(n) => n,
                Err(_) => {
                    let _ = std::fs::write(
                        format!("/tmp/kata-agent-demote-net-fail-{}", ip),
                        format!("ip={} prefix={} ipnetwork_new_failed=true\n", ip, prefix),
                    );
                    continue;
                }
            };
            // Skip IPv6 link-local — needed for ND. Match fe80::/10.
            if let IpAddr::V6(v6) = ip {
                let oct = v6.octets();
                if oct[0] == 0xfe && (oct[1] & 0xc0) == 0x80 {
                    let _ = std::fs::write(
                        format!("/tmp/kata-agent-demote-skip-ipv6ll-{}", ip),
                        format!("ip={} prefix={} skipped=ipv6-link-local\n", ip, prefix),
                    );
                    continue;
                }
            }
            // Skip non-IPv4 if IPv6 is disabled (defensive).
            if !net.is_ipv4() && !supports_ipv6 {
                let _ = std::fs::write(
                    format!("/tmp/kata-agent-demote-skip-noipv6-{}", ip),
                    format!("ip={} prefix={} skipped=ipv6-disabled\n", ip, prefix),
                );
                continue;
            }
            // DIAG marker C: pre-del state per address being removed.
            let _ = std::fs::write(
                format!("/tmp/kata-agent-demote-attempt-{}", ip),
                format!("ip={} prefix={} attempting=remove\n", ip, prefix),
            );
            // Reap the workload's sockets on this address BEFORE removing it.
            //
            // The point of the reap is the RST that tells the peer to let go,
            // and a RST from a socket whose local address has already been
            // deleted has no routable source. Measured on a hop that ran the
            // reap afterwards: the guest's own stale sockets cleared within
            // ~15 minutes while the database still held ten connections from
            // the dead pod's address — the guest tidies up, the peer never
            // learns, and the next hop adds another set (spec 022 FR-059).
            //
            // Bounded by construction: the dump uses SO_RCVTIMEO and an
            // iteration cap, every error is swallowed, and the delete below
            // runs regardless of what this returns. spawn_blocking because it
            // is synchronous netlink on an async path.
            {
                let pre = tokio::task::spawn_blocking(move || destroy_stale_sockets_bound_to(ip))
                    .await
                    .unwrap_or_default();
                if pre.ineffective() {
                    warn!(sl(), "update_interface: pre-delete socket reap closed nothing";
                        "ip" => ip.to_string(),
                        "attempted" => pre.attempted,
                        "confirmed" => pre.confirmed,
                        "dump_failed" => pre.dump_failed,
                        "unsupported" => pre.unsupported);
                } else {
                    info!(sl(), "update_interface: pre-delete socket reap";
                        "ip" => ip.to_string(),
                        "attempted" => pre.attempted,
                        "confirmed" => pre.confirmed);
                }
            }
            // Delete the stale address from the interface entirely.
            // Don't re-add — once gone, Linux must pick a request IP
            // as source for new outbound, fixing the post-migration
            // Cilium drop.
            let del_msg = addr.0.clone();
            if let Err(e) = self.handle.address().del(del_msg).execute().await {
                let _ = std::fs::write(
                    format!("/tmp/kata-agent-demote-delerr-{}", ip),
                    format!("ip={} prefix={} del_err={:?}\n", ip, prefix, e),
                );
                info!(
                    sl(),
                    "update_interface: del stale address failed (continuing)";
                    "ip" => ip.to_string(),
                    "prefix" => prefix,
                    "err" => format!("{:?}", e),
                );
                continue;
            }
            let _ = std::fs::write(
                format!("/tmp/kata-agent-demote-ok-{}", ip),
                format!("ip={} prefix={} status=removed\n", ip, prefix),
            );
            // FR-059: the workload's pre-existing TCP/UDP sockets are still
            // bound to this now-removed address; their wire path is dead but
            // they read ESTABLISHED, so the guest would hoard them across every
            // hop and the peers (e.g. RDS) accumulate zombies. Close them so
            // the connection pool reconnects over the new address. Fire-and-
            // forget on a blocking task — strictly best-effort, must never
            // affect the renumber.
            tokio::task::spawn_blocking(move || {
                let s = destroy_stale_sockets_bound_to(ip);
                // Say what the reap achieved on the same path that reported
                // the address removal, so the two are read together. An
                // ineffective reap is a warning: the renumber succeeded and
                // the connections it was supposed to close are still there.
                if s.ineffective() {
                    warn!(sl(), "update_interface: stale sockets were NOT reaped after removing the address";
                        "ip" => ip.to_string(),
                        "attempted" => s.attempted,
                        "confirmed" => s.confirmed,
                        "dump_failed" => s.dump_failed,
                        "unsupported" => s.unsupported);
                } else {
                    info!(sl(), "update_interface: stale sockets reaped after removing the address";
                        "ip" => ip.to_string(),
                        "attempted" => s.attempted,
                        "confirmed" => s.confirmed);
                }
            });
            info!(
                sl(),
                "update_interface: removed stale address from link";
                "ip" => ip.to_string(),
                "prefix" => prefix,
            );
        }

        // we need to update the link's interface name, thus we should rename the existed link whose name
        // is the same with the link's request name, otherwise, it would update the link failed with the
        // name conflicted.
        let mut new_link = None;
        if link.name() != iface.name {
            if let Ok(link) = self.find_link(LinkFilter::Name(iface.name.as_str())).await {
                // Bring down interface if it is UP
                if link.is_up() {
                    self.enable_link(link.index(), false).await?;
                }

                // update the existing interface name with a temporary name, otherwise
                // it would failed to udpate this interface with an existing name.
                let link_name = link.name();
                let temp_name = link_name.clone() + "_temp";
                let msg = LinkUnspec::new_with_index(link.index())
                    .set_header(link.header.clone())
                    .name(temp_name.clone())
                    .build();
                self.handle
                    .link()
                    .change(msg)
                    .execute()
                    .await
                    .map_err(|err| {
                        anyhow!(
                            "Failed to rename interface {} to {}with error: {}",
                            link_name,
                            temp_name,
                            err
                        )
                    })?;

                new_link = Some(link);
            }
        }

        // Update link
        let link = self.find_link(LinkFilter::Address(&iface.hwAddr)).await?;
        let msg = LinkUnspec::new_with_index(link.index())
            .set_header(link.header.clone())
            .mtu(iface.mtu as _)
            .name(iface.name.clone())
            .arp(iface.raw_flags & libc::IFF_NOARP as u32 == 0)
            .up()
            .build();
        self.handle
            .link()
            .change(msg)
            .execute()
            .await
            .map_err(|err| {
                anyhow!(
                    "Failure in LinkSetRequest for interface {}: {}",
                    iface.name.as_str(),
                    err
                )
            })?;

        // swap the updated iface's name.
        if let Some(nlink) = new_link {
            let msg = LinkUnspec::new_with_index(nlink.index())
                .set_header(nlink.header.clone())
                .name(link.name())
                .up()
                .build();
            self.handle
                .link()
                .change(msg)
                .execute()
                .await
                .map_err(|err| {
                    anyhow!(
                        "Error swapping back interface name {} to {}: {}",
                        nlink.name().as_str(),
                        link.name(),
                        err
                    )
                })?;
        }

        // Flush the link's neighbor cache. Load-bearing for live
        // migration: the migrated guest's neighbor table still holds
        // entries from the SOURCE pod-netns (the gateway IP -> source
        // LXC veth peer's MAC). On the destination, the gateway IP
        // is the same but the host-side veth peer has a DIFFERENT
        // MAC. Without a flush, the guest sends packets to the stale
        // MAC and they are dropped at L2 before reaching Cilium TC.
        // Flushing forces a fresh ARP request on the next packet,
        // and the destination netns resolves the correct MAC.
        //
        // Best-effort: if the flush fails, surface the error but do
        // not undo the IP/MAC changes that were already applied.
        if let Err(e) = self.flush_link_neighbors(link_index).await {
            return Err(anyhow!(
                "update_interface: flush_link_neighbors on ifindex={} failed: {:?}",
                link_index,
                e
            ));
        }

        Ok(())
    }

    /// Remove every neighbor entry on the given link. Used to clear
    /// stale ARP entries after live migration so the guest re-resolves
    /// the destination netns's gateway MAC on the next packet.
    ///
    /// Implementation: dumps the full neighbor table, filters to the
    /// target ifindex, then issues a DelNeighbour for each. We dump
    /// across all links and filter in user-space because the dump
    /// request with `ifindex` set is not reliably filtered by every
    /// kernel/rtnetlink version; doing the filter ourselves is cheap
    /// (the neighbor table is small) and avoids version skew.
    ///
    /// Permanent (NUD_PERMANENT) entries created by the agent's
    /// `add_arp_neighbor` are preserved by the kernel: the kernel
    /// refuses DelNeighbour for them and returns EPERM, which we
    /// swallow per entry — the goal is to clear cached learned
    /// entries, not delete static configuration.
    pub async fn flush_link_neighbors(&mut self, link_index: u32) -> Result<()> {
        use libc::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
        use neighbour::{NeighbourHeader, NeighbourMessage};
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use netlink_packet_route::RouteNetlinkMessage as RtnlMessage;

        // Dump request: zero-initialised NeighbourMessage with
        // NLM_F_REQUEST | NLM_F_DUMP yields every neighbor entry
        // across all links and families.
        let dump_msg = NeighbourMessage::default();
        let mut dump_req = NetlinkMessage::from(RtnlMessage::GetNeighbour(dump_msg));
        dump_req.header.flags = (NLM_F_REQUEST | NLM_F_DUMP) as u16;

        let mut to_delete: Vec<NeighbourMessage> = Vec::new();
        let mut resp = self.handle.request(dump_req)?;
        while let Some(message) = resp.next().await {
            match message.payload {
                NetlinkPayload::InnerMessage(RtnlMessage::NewNeighbour(n)) => {
                    if n.header.ifindex == link_index {
                        to_delete.push(n);
                    }
                }
                NetlinkPayload::Error(err) => {
                    return Err(anyhow!("dump neighbors failed: {:?}", err));
                }
                _ => {}
            }
        }

        for entry in to_delete {
            // Build the delete header from the dump entry. The kernel
            // identifies the entry by (ifindex, family, destination
            // address); state/flags are echoed but not required for
            // identification.
            let family = entry.header.family;
            let header = NeighbourHeader {
                family,
                ifindex: entry.header.ifindex,
                state: entry.header.state,
                flags: entry.header.flags.clone(),
                kind: entry.header.kind,
            };
            let mut del_msg = NeighbourMessage::default();
            del_msg.header = header;
            // Preserve the destination IP attribute; everything else
            // can be dropped — the kernel only needs the destination
            // address NLA to identify the entry to delete.
            del_msg.attributes = entry
                .attributes
                .into_iter()
                .filter(|a| matches!(a, NeighbourAttribute::Destination(_)))
                .collect();

            let mut del_req = NetlinkMessage::from(RtnlMessage::DelNeighbour(del_msg));
            del_req.header.flags = (NLM_F_REQUEST | NLM_F_ACK) as u16;

            let mut resp = self.handle.request(del_req)?;
            while let Some(message) = resp.next().await {
                if let NetlinkPayload::Error(_err) = message.payload {
                    // Best-effort: a single stale entry may have
                    // expired between dump and delete, or be a
                    // PERMANENT entry the kernel refuses to remove.
                    // Don't abort the whole flush on one EBUSY/EPERM.
                }
            }
        }

        Ok(())
    }

    pub async fn handle_localhost(&self) -> Result<()> {
        let link = self.find_link(LinkFilter::Name("lo")).await?;
        self.enable_link(link.index(), true).await?;
        Ok(())
    }

    #[cfg(not(target_arch = "s390x"))]
    pub fn netdev_name_from_pci_path(&self, dev_tree_path: &str) -> Result<Option<String>> {
        let (root_complex, pcipath) = pcipath_from_dev_tree_path(dev_tree_path)
            .with_context(|| format!("invalid PCI path for network interface: {dev_tree_path}"))?;
        let root_bus_sysfs = format!("{}{}", SYSFS_DIR, create_pci_root_bus_path(root_complex));
        let sysfs_rel_path = pcilib_to_sysfs_path(&root_bus_sysfs, &pcipath)?;
        let net_dir = format!("{root_bus_sysfs}{sysfs_rel_path}/net");

        let mut entries = match fs::read_dir(&net_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("failed to read net dir {net_dir}")),
        };

        if let Some(entry) = entries.next() {
            let entry = entry.with_context(|| format!("failed to read entry under {net_dir}"))?;
            let name = entry.file_name().into_string().map_err(|non_utf8| {
                anyhow!("non-UTF8 netdev name under {}: {:?}", net_dir, non_utf8)
            })?;
            return Ok(Some(name));
        }

        Ok(None)
    }

    pub async fn set_link_mac_by_name(&self, ifname: &str, mac: &str) -> Result<String> {
        let link = self.find_link(LinkFilter::Name(ifname)).await?;
        let prev_mac = link.address();
        if prev_mac.eq_ignore_ascii_case(mac) {
            return Ok(prev_mac);
        }

        let parsed_mac = parse_mac_address(mac)
            .with_context(|| format!("failed to parse MAC address: {mac}"))?;
        if link.is_up() {
            self.enable_link(link.index(), false).await?;
        }

        let msg = LinkUnspec::new_with_index(link.index())
            .set_header(link.header.clone())
            .address(parsed_mac.to_vec())
            .build();
        self.handle
            .link()
            .change(msg)
            .execute()
            .await
            .with_context(|| format!("failed to set MAC for interface {} to {}", ifname, mac))?;

        if link.is_up() {
            self.enable_link(link.index(), true).await?;
        }

        Ok(prev_mac)
    }

    /// Retireve available network interfaces.
    pub async fn list_interfaces(&self) -> Result<Vec<Interface>> {
        let mut list = Vec::new();

        let links = self.list_links().await?;

        for link in &links {
            let mut iface = Interface {
                name: link.name(),
                hwAddr: link.address(),
                mtu: link.mtu().unwrap_or(0),
                ..Default::default()
            };

            let ips = self
                .list_addresses(AddressFilter::LinkIndex(link.index()))
                .await?
                .into_iter()
                .map(|p| p.try_into())
                .collect::<Result<Vec<IPAddress>>>()?;

            iface.IPAddresses = ips;

            list.push(iface);
        }

        Ok(list)
    }

    async fn find_link(&self, filter: LinkFilter<'_>) -> Result<Link> {
        self.try_find_link(filter)
            .await?
            .ok_or_else(|| anyhow!("Link not found ({})", filter))
    }

    /// Like [`Self::find_link`], but returns `Ok(None)` when the link is not
    /// found instead of an error, so callers can distinguish "not found" from
    /// a genuine netlink/parse failure.
    async fn try_find_link(&self, filter: LinkFilter<'_>) -> Result<Option<Link>> {
        let request = self.handle.link().get();

        let filtered = match filter {
            LinkFilter::Name(name) => request.match_name(name.to_owned()),
            LinkFilter::Index(index) => request.match_index(index),
            _ => request, // Post filters
        };

        let mut stream = filtered.execute();

        let next = if let LinkFilter::Address(addr) = filter {
            use LinkAttribute as Nla;

            let mac_addr = parse_mac_address(addr)
                .with_context(|| format!("Failed to parse MAC address: {addr}"))?;

            // Hardware filter might not be supported by netlink,
            // we may have to dump link list and then find the target link.
            stream
                .try_filter(|f| {
                    let result = f.attributes.iter().any(|n| match n {
                        Nla::Address(data) => data.eq(&mac_addr),
                        _ => false,
                    });

                    future::ready(result)
                })
                .try_next()
                .await?
        } else {
            stream.try_next().await?
        };

        Ok(next.map(|msg| msg.into()))
    }

    async fn list_links(&self) -> Result<Vec<Link>> {
        let result = self
            .handle
            .link()
            .get()
            .execute()
            .try_filter_map(|msg| future::ready(Ok(Some(msg.into())))) // Don't filter, just map
            .try_collect::<Vec<Link>>()
            .await?;
        Ok(result)
    }

    pub async fn enable_link(&self, link_index: u32, up: bool) -> Result<()> {
        let builder = LinkUnspec::new_with_index(link_index);
        let msg = if up { builder.up() } else { builder.down() };
        self.handle.link().change(msg.build()).execute().await?;
        Ok(())
    }

    async fn query_routes(&self, ip_version: Option<IpVersion>) -> Result<Vec<RouteMessage>> {
        let list = if let Some(ip_version) = ip_version {
            let msg = match ip_version {
                IpVersion::V4 => RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
                IpVersion::V6 => RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
            };
            self.handle.route().get(msg).execute().try_collect().await?
        } else {
            // These queries must be executed sequentially, otherwise
            // it'll throw "Device or resource busy (os error 16)"
            let routes4 = self
                .handle
                .route()
                .get(RouteMessageBuilder::<std::net::Ipv4Addr>::new().build())
                .execute()
                .try_collect::<Vec<_>>()
                .await
                .with_context(|| "Failed to query IP v4 routes")?;

            let routes6 = self
                .handle
                .route()
                .get(RouteMessageBuilder::<std::net::Ipv6Addr>::new().build())
                .execute()
                .try_collect::<Vec<_>>()
                .await
                .with_context(|| "Failed to query IP v6 routes")?;

            [routes4, routes6].concat()
        };

        Ok(list)
    }

    pub async fn list_routes(&self) -> Result<Vec<Route>> {
        let mut result = Vec::new();

        for msg in self.query_routes(None).await? {
            // Ignore non-main tables
            if msg.header.table != RouteHeader::RT_TABLE_MAIN {
                continue;
            }

            let mut route = Route {
                scope: u8::from(msg.header.scope) as u32,
                ..Default::default()
            };

            for attribute in &msg.attributes {
                if let RouteAttribute::Destination(dest) = attribute {
                    if let Ok(dest) = parse_route_addr(dest) {
                        route.dest = format!("{}/{}", dest, msg.header.destination_prefix_length);
                    }
                }

                if let RouteAttribute::Source(src) = attribute {
                    if let Ok(src) = parse_route_addr(src) {
                        route.source = format!("{}/{}", src, msg.header.source_prefix_length)
                    }
                }

                if let RouteAttribute::Gateway(g) = attribute {
                    if let Ok(addr) = parse_route_addr(g) {
                        // For gateway, destination is 0.0.0.0
                        if addr.is_ipv4() {
                            route.dest = String::from("0.0.0.0");
                        } else {
                            route.dest = String::from("::1");
                        }
                    }

                    route.gateway = parse_route_addr(g)
                        .map(|g| g.to_string())
                        .unwrap_or_default();
                }

                if let RouteAttribute::Metrics(metrics) = attribute {
                    for m in metrics {
                        if let RouteMetric::Mtu(mtu) = m {
                            route.mtu = *mtu;
                            break;
                        }
                    }
                }

                if let RouteAttribute::Oif(index) = attribute {
                    route.device = match self.find_link(LinkFilter::Index(*index)).await {
                        Ok(link) => link.name(),
                        Err(_) => String::new(),
                    };
                }
            }

            if !route.dest.is_empty() {
                result.push(route);
            }
        }

        Ok(result)
    }

    /// Add a list of routes from iterable object `I`.
    /// If the route existed, then replace it with the latest.
    /// It can accept both a collection of routes or a single item (via `iter::once()`).
    /// It'll also take care of proper order when adding routes (gateways first, everything else after).
    pub async fn update_routes<I>(&mut self, list: I) -> Result<()>
    where
        I: IntoIterator<Item = Route>,
    {
        // Split the list so we add routes with no gateway first.
        // Note: `partition_in_place` is a better fit here, since it reorders things inplace (instead of
        // allocating two separate collections), however it's not yet in stable Rust.
        let (a, b): (Vec<Route>, Vec<Route>) = list.into_iter().partition(|p| p.gateway.is_empty());
        let list = a.iter().chain(&b);

        for route in list {
            let link = self.find_link(LinkFilter::Name(&route.device)).await?;

            const MAIN_TABLE: u32 = libc::RT_TABLE_MAIN as u32;
            let uni_cast: RouteType = RouteType::from(libc::RTN_UNICAST);
            let boot_prot: RouteProtocol = RouteProtocol::from(libc::RTPROT_BOOT);

            let scope = RouteScope::from(route.scope as u8);

            use RouteAttribute as Nla;

            // `rtnetlink` offers a separate request builders for different IP versions (IP v4 and v6).
            // This if branch is a bit clumsy because it does almost the same.
            if route.family() == IPFamily::v6 {
                let dest_addr = if !route.dest.is_empty() {
                    Ipv6Network::from_str(&route.dest)?
                } else {
                    Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)?
                };

                // Build IP v6 request
                let mut v6_builder = RouteMessageBuilder::<Ipv6Addr>::new()
                    .table_id(MAIN_TABLE)
                    .kind(uni_cast)
                    .protocol(boot_prot)
                    .scope(scope)
                    .destination_prefix(dest_addr.ip(), dest_addr.prefix())
                    .output_interface(link.index());
                {
                    let message = v6_builder.get_mut();
                    message.header.flags =
                        netlink_packet_route::route::RouteFlags::from_bits_retain(route.flags);
                    if route.mtu != 0 {
                        let route_metrics = vec![RouteMetric::Mtu(route.mtu)];
                        message
                            .attributes
                            .push(RouteAttribute::Metrics(route_metrics));
                    }
                }

                if !route.source.is_empty() {
                    let network = Ipv6Network::from_str(&route.source)?;
                    if network.prefix() > 0 {
                        v6_builder = v6_builder.source_prefix(network.ip(), network.prefix());
                    } else {
                        v6_builder
                            .get_mut()
                            .attributes
                            .push(Nla::PrefSource(RouteAddress::from(network.ip())));
                    }
                }

                if !route.gateway.is_empty() {
                    let ip = Ipv6Addr::from_str(&route.gateway)?;
                    v6_builder = v6_builder.gateway(ip);
                }

                let request = self.handle.route().add(v6_builder.build()).replace();
                if let Err(rtnetlink::Error::NetlinkError(message)) = request.execute().await {
                    if let Some(code) = message.code {
                        if Errno::from_raw(code.get()) != Errno::EEXIST {
                            return Err(anyhow!(
                                "Failed to add IP v6 route (src: {}, dst: {}, gtw: {},Err: {})",
                                route.source(),
                                route.dest(),
                                route.gateway(),
                                message
                            ));
                        }
                    }
                }
            } else {
                let dest_addr = if !route.dest.is_empty() {
                    Ipv4Network::from_str(&route.dest)?
                } else {
                    Ipv4Network::new(Ipv4Addr::new(0, 0, 0, 0), 0)?
                };

                // Build IP v4 request
                let mut v4_builder = RouteMessageBuilder::<Ipv4Addr>::new()
                    .table_id(MAIN_TABLE)
                    .kind(uni_cast)
                    .protocol(boot_prot)
                    .scope(scope)
                    .destination_prefix(dest_addr.ip(), dest_addr.prefix())
                    .output_interface(link.index());
                {
                    let message = v4_builder.get_mut();
                    message.header.flags =
                        netlink_packet_route::route::RouteFlags::from_bits_retain(route.flags);
                    if route.mtu != 0 {
                        let route_metrics = vec![RouteMetric::Mtu(route.mtu)];
                        message
                            .attributes
                            .push(RouteAttribute::Metrics(route_metrics));
                    }
                }

                if !route.source.is_empty() {
                    // Fork: always set RTA_PREFSRC so the route's `src` hint steers
                    // source-address selection for new outbound connections —
                    // the live-migration renumber depends on it. source_prefix()
                    // would set RTA_SRC, a source-routing match, which is a
                    // different feature. Accept a bare IP or a CIDR.
                    let ip = if let Ok(addr) = Ipv4Addr::from_str(&route.source) {
                        addr
                    } else {
                        Ipv4Network::from_str(&route.source)?.ip()
                    };
                    v4_builder
                        .get_mut()
                        .attributes
                        .push(RouteAttribute::PrefSource(RouteAddress::from(ip)));
                }

                if !route.gateway.is_empty() {
                    let ip = Ipv4Addr::from_str(&route.gateway)?;
                    v4_builder = v4_builder.gateway(ip);
                }

                let request = self.handle.route().add(v4_builder.build()).replace();
                if let Err(rtnetlink::Error::NetlinkError(message)) = request.execute().await {
                    if let Some(code) = message.code {
                        if Errno::from_raw(code.get()) != Errno::EEXIST {
                            return Err(anyhow!(
                                "Failed to add IP v4 route (src: {}, dst: {}, gtw: {},Err: {})",
                                route.source(),
                                route.dest(),
                                route.gateway(),
                                message
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn list_addresses<F>(&self, filter: F) -> Result<Vec<Address>>
    where
        F: Into<Option<AddressFilter>>,
    {
        let mut request = self.handle.address().get();

        if let Some(filter) = filter.into() {
            request = match filter {
                AddressFilter::LinkIndex(index) => request.set_link_index_filter(index),
                AddressFilter::IpAddress(addr) => request.set_address_filter(addr),
            };
        };

        let list = request
            .execute()
            .try_filter_map(|msg| future::ready(Ok(Some(Address(msg))))) // Map message to `Address`
            .try_collect()
            .await?;
        Ok(list)
    }

    // add the addresses to the specified interface, if the addresses existed,
    // replace it with the latest one.
    async fn add_addresses<I>(&mut self, index: u32, list: I) -> Result<()>
    where
        I: IntoIterator<Item = IpNetwork>,
    {
        for net in list.into_iter() {
            self.handle
                .address()
                .add(index, net.ip(), net.prefix())
                .replace()
                .execute()
                .await
                .map_err(|err| anyhow!("Failed to add address {}: {:?}", net.ip(), err))?;
        }

        Ok(())
    }

    pub async fn add_arp_neighbors<I>(&mut self, list: I) -> Result<()>
    where
        I: IntoIterator<Item = ARPNeighbor>,
    {
        for neigh in list.into_iter() {
            self.add_arp_neighbor(&neigh).await.map_err(|err| {
                anyhow!(
                    "Failed to add ARP neighbor {}: {:?}",
                    neigh.toIPAddress().address(),
                    err
                )
            })?;
        }

        Ok(())
    }

    /// Adds an ARP neighbor.
    /// TODO: `rtnetlink` has no neighbours API, remove this after https://github.com/little-dude/netlink/pull/135
    async fn add_arp_neighbor(&mut self, neigh: &ARPNeighbor) -> Result<()> {
        let ip_address = neigh
            .toIPAddress
            .as_ref()
            .map(|to| to.address.as_str()) // Extract address field
            .and_then(|addr| if addr.is_empty() { None } else { Some(addr) }) // Make sure it's not empty
            .ok_or_else(|| anyhow!("Unable to determine ip address of ARP neighbor"))?;

        let ip = IpAddr::from_str(ip_address)
            .map_err(|e| anyhow!("Failed to parse IP {}: {:?}", ip_address, e))?;

        let link = self.find_link(LinkFilter::Name(&neigh.device)).await?;

        let flags = ALL_RULE_FLAGS & NeighbourFlags::from_bits_retain(neigh.flags as u8);
        let state = if neigh.state == 0 {
            NeighbourState::Permanent
        } else {
            (neigh.state as u16).into()
        };
        let mut req = self
            .handle
            .neighbours()
            .add(link.index(), ip)
            .state(state)
            .flags(flags)
            .replace();
        if !neigh.lladdr.is_empty() {
            let lladdr = parse_mac_address(&neigh.lladdr).context("parsing lladdr")?;
            req = req.link_layer_address(&lladdr);
        }
        req.execute().await.context("executing NeighbourAddRequest")
    }
}

#[cfg(not(target_arch = "s390x"))]
fn pcilib_to_sysfs_path(root_bus_sysfs: &str, pcipath: &pci::Path) -> Result<String> {
    pcipath_to_sysfs(root_bus_sysfs, pcipath)
}

fn format_address(data: &[u8]) -> Result<String> {
    match data.len() {
        4 => {
            // IP v4
            Ok(format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]))
        }
        6 => {
            // Mac address
            Ok(format!(
                "{:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}:{:0>2X}",
                data[0], data[1], data[2], data[3], data[4], data[5]
            ))
        }
        16 => {
            // IP v6
            let octets = <[u8; 16]>::try_from(data)?;
            Ok(Ipv6Addr::from(octets).to_string())
        }
        _ => Err(anyhow!("Unsupported address length: {}", data.len())),
    }
}

fn parse_mac_address(addr: &str) -> Result<[u8; 6]> {
    let mut split = addr.splitn(6, ':');

    // Parse single Mac address block
    let mut parse_next = || -> Result<u8> {
        let v = u8::from_str_radix(
            split
                .next()
                .ok_or_else(|| anyhow!("Invalid MAC address {}", addr))?,
            16,
        )?;
        Ok(v)
    };

    // Parse all 6 blocks
    let arr = [
        parse_next()?,
        parse_next()?,
        parse_next()?,
        parse_next()?,
        parse_next()?,
        parse_next()?,
    ];

    Ok(arr)
}

/// Wraps external type with the local one, so we can implement various extensions and type conversions.
struct Link(LinkMessage);

impl Link {
    /// If name.
    fn name(&self) -> String {
        use LinkAttribute as Nla;
        self.attributes
            .iter()
            .find_map(|n| {
                if let Nla::IfName(name) = n {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Extract Mac address.
    fn address(&self) -> String {
        use LinkAttribute as Nla;
        self.attributes
            .iter()
            .find_map(|n| {
                if let Nla::Address(data) = n {
                    format_address(data).ok()
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Returns whether the link is UP
    fn is_up(&self) -> bool {
        self.header.flags.contains(LinkFlags::Up)
    }

    fn index(&self) -> u32 {
        self.header.index
    }

    fn mtu(&self) -> Option<u64> {
        use LinkAttribute as Nla;
        self.attributes.iter().find_map(|n| {
            if let Nla::Mtu(mtu) = n {
                Some(*mtu as u64)
            } else {
                None
            }
        })
    }
}

impl From<LinkMessage> for Link {
    fn from(msg: LinkMessage) -> Self {
        Link(msg)
    }
}

impl Deref for Link {
    type Target = LinkMessage;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct Address(AddressMessage);

impl TryFrom<Address> for IPAddress {
    type Error = anyhow::Error;

    fn try_from(value: Address) -> Result<Self, Self::Error> {
        let family = if value.is_ipv6() {
            IPFamily::v4
        } else {
            IPFamily::v6
        };

        let mut address = value.address();
        if address.is_empty() {
            address = value.local();
        }

        let mask = format!("{}", value.0.header.prefix_len);

        Ok(IPAddress {
            family: family.into(),
            address,
            mask,
            ..Default::default()
        })
    }
}

impl Address {
    fn is_ipv6(&self) -> bool {
        u8::from(self.0.header.family) == libc::AF_INET6 as u8
    }

    #[allow(dead_code)]
    fn prefix(&self) -> u8 {
        self.0.header.prefix_len
    }

    fn address(&self) -> String {
        use AddressAttribute as Nla;
        self.0
            .attributes
            .iter()
            .find_map(|n| {
                if let Nla::Address(data) = n {
                    Some(data.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    fn local(&self) -> String {
        use AddressAttribute as Nla;
        self.0
            .attributes
            .iter()
            .find_map(|n| {
                if let Nla::Local(data) = n {
                    Some(data.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }
}

fn parse_route_addr(ra: &RouteAddress) -> Result<IpAddr> {
    let ipaddr = match ra {
        RouteAddress::Inet6(ipv6_addr) => ipv6_addr.to_canonical(),
        RouteAddress::Inet(ipv4_addr) => IpAddr::from(*ipv4_addr),
        _ => return Err(anyhow!("got invalid route address")),
    };

    Ok(ipaddr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::address::AddressHeader;
    use netlink_packet_route::link::LinkHeader;
    use serial_test::serial;
    use std::iter;
    use std::process::Command;
    use test_utils::skip_if_not_root;

    // Constants for ARP neighbor tests
    const TEST_DUMMY_INTERFACE: &str = "dummy_for_arp";
    const TEST_ARP_IP: &str = "192.0.2.127";

    // FR-062c: SOCK_DESTROY reply classification. The kernel answers each
    // NLM_F_ACK'd destroy with an nlmsgerr whose code decides whether the
    // kill is confirmed, moot, impossible, or failed — and the caller's
    // logging/abort behavior hangs off that split, so pin it here.
    #[test]
    fn test_classify_destroy_reply_ack_is_confirmed() {
        assert_eq!(classify_destroy_reply(0), DestroyReply::Confirmed);
    }

    #[test]
    fn test_classify_destroy_reply_enoent_is_already_gone() {
        assert_eq!(
            classify_destroy_reply(-libc::ENOENT),
            DestroyReply::AlreadyGone
        );
    }

    #[test]
    fn test_classify_destroy_reply_eopnotsupp_is_unsupported() {
        // CONFIG_INET_DIAG_DESTROY missing: the caller must stop retrying
        // and warn loudly — this arm is what prevents "destroyed N" lies.
        assert_eq!(
            classify_destroy_reply(-libc::EOPNOTSUPP),
            DestroyReply::Unsupported
        );
    }

    #[test]
    fn test_classify_destroy_reply_other_errno_is_failed() {
        assert_eq!(
            classify_destroy_reply(-libc::EPERM),
            DestroyReply::Failed(-libc::EPERM)
        );
        // Positive junk codes must not be mistaken for a known outcome.
        assert_eq!(classify_destroy_reply(42), DestroyReply::Failed(42));
    }

    /// Helper function to check if the result is a netlink EACCES error
    fn is_netlink_permission_error<T>(result: &Result<T>) -> bool {
        if let Err(e) = result {
            let error_string = format!("{e:?}");
            if error_string.contains("code: Some(-13)") {
                println!("INFO: skipping test - netlink operations are restricted in this environment (EACCES)");
                return true;
            }
        }
        false
    }

    #[tokio::test]
    async fn find_link_by_name() {
        let message = Handle::new()
            .expect("Failed to create netlink handle")
            .find_link(LinkFilter::Name("lo"))
            .await
            .expect("Loopback not found");

        assert_ne!(message.header, LinkHeader::default());
        assert_eq!(message.name(), "lo");
    }

    #[tokio::test]
    async fn find_link_by_addr() {
        let handle = Handle::new().unwrap();

        let list = handle.list_links().await.unwrap();
        let link = list.first().expect("At least one link required");

        let result = handle
            .find_link(LinkFilter::Address(&link.address()))
            .await
            .expect("Failed to query link by address");

        assert_eq!(result.header.index, link.header.index);
    }

    #[tokio::test]
    #[serial(template_mac_retarget)]
    async fn update_interface_retargets_mac_by_name() {
        skip_if_not_root!();

        const LINK_NAME: &str = "tmpl-mac-test";
        const OLD_MAC: &str = "02:00:00:00:00:01";
        const NEW_MAC: &str = "02:00:00:00:00:02";

        let _ = Command::new("ip")
            .args(["link", "delete", LINK_NAME])
            .output();
        let add_result = Command::new("ip")
            .args([
                "link", "add", LINK_NAME, "address", OLD_MAC, "type", "dummy",
            ])
            .output()
            .expect("failed to run ip link add");
        if !add_result.status.success() {
            println!(
                "INFO: skipping test - cannot create dummy link: {}",
                String::from_utf8_lossy(&add_result.stderr)
            );
            return;
        }
        struct LinkCleanup(&'static str);
        impl Drop for LinkCleanup {
            fn drop(&mut self) {
                let _ = Command::new("ip").args(["link", "delete", self.0]).output();
            }
        }
        let _link_cleanup = LinkCleanup(LINK_NAME);

        let mut handle = Handle::new().unwrap();
        let iface = Interface {
            name: LINK_NAME.to_string(),
            hwAddr: NEW_MAC.to_string(),
            mtu: 1500,
            ..Default::default()
        };

        let update_result = handle.update_interface(&iface).await;
        let observed_mac = handle
            .find_link(LinkFilter::Name(LINK_NAME))
            .await
            .map(|link| link.address());

        update_result.expect("failed to update interface with a restored MAC");
        assert_eq!(observed_mac.unwrap().to_lowercase(), NEW_MAC);
    }

    #[tokio::test]
    async fn link_up() {
        skip_if_not_root!();

        let handle = Handle::new().unwrap();
        let link = handle.find_link(LinkFilter::Name("lo")).await.unwrap();

        handle
            .enable_link(link.header.index, true)
            .await
            .expect("Failed to bring link up");

        assert!(handle
            .find_link(LinkFilter::Name("lo"))
            .await
            .unwrap()
            .is_up());
    }

    #[tokio::test]
    async fn link_ext() {
        let lo = Handle::new()
            .unwrap()
            .find_link(LinkFilter::Name("lo"))
            .await
            .unwrap();

        assert_eq!(lo.name(), "lo");
        assert_ne!(lo.address().len(), 0);
    }

    #[tokio::test]
    #[serial(arp_neighbor_tests)]
    async fn list_routes() {
        clean_env_for_test_add_one_arp_neighbor(TEST_DUMMY_INTERFACE, TEST_ARP_IP);
        let devices: Vec<Interface> = Handle::new().unwrap().list_interfaces().await.unwrap();
        let all = Handle::new()
            .unwrap()
            .list_routes()
            .await
            .context(format!("available devices: {devices:?}"))
            .expect("Failed to list routes");

        assert_ne!(all.len(), 0);
    }

    #[tokio::test]
    async fn list_addresses() {
        let list = Handle::new()
            .unwrap()
            .list_addresses(None)
            .await
            .expect("Failed to list addresses");

        assert_ne!(list.len(), 0);
        for addr in &list {
            assert_ne!(addr.0.header, AddressHeader::default());
        }
    }

    #[tokio::test]
    async fn list_interfaces() {
        let list = Handle::new()
            .unwrap()
            .list_interfaces()
            .await
            .expect("Failed to list interfaces");

        for iface in &list {
            assert_ne!(iface.name.len(), 0);
            assert_ne!(iface.mtu, 0);

            for ip in &iface.IPAddresses {
                assert_ne!(ip.mask.len(), 0);
                assert_ne!(ip.address.len(), 0);
            }
        }
    }

    #[tokio::test]
    async fn add_update_addresses() {
        skip_if_not_root!();

        let list = vec![
            IpNetwork::from_str("169.254.1.1/31").unwrap(),
            IpNetwork::from_str("2001:db8:85a3::8a2e:370:7334/128").unwrap(),
        ];

        let mut handle = Handle::new().unwrap();
        let lo = handle.find_link(LinkFilter::Name("lo")).await.unwrap();

        for network in list {
            let result = handle.add_addresses(lo.index(), iter::once(network)).await;

            // Skip test if netlink operations are restricted (EACCES = -13)
            if is_netlink_permission_error(&result) {
                return;
            }

            result.expect("Failed to add IP");

            // Make sure the address is there
            let result = handle
                .list_addresses(AddressFilter::LinkIndex(lo.index()))
                .await
                .unwrap()
                .into_iter()
                .find(|p| {
                    p.prefix() == network.prefix() && p.address() == network.ip().to_string()
                });

            assert!(result.is_some());

            // Update it
            let result = handle.add_addresses(lo.index(), iter::once(network)).await;

            // Skip test if netlink operations are restricted (EACCES = -13)
            if is_netlink_permission_error(&result) {
                return;
            }

            result.expect("Failed to delete address");
        }
    }

    #[test]
    fn format_addr() {
        let buf = [1u8, 2u8, 3u8, 4u8];
        let addr = format_address(&buf).unwrap();
        assert_eq!(addr, "1.2.3.4");

        let buf = [1u8, 2u8, 3u8, 4u8, 5u8, 10u8];
        let addr = format_address(&buf).unwrap();
        assert_eq!(addr, "01:02:03:04:05:0A");
    }

    #[test]
    fn parse_mac() {
        let bytes = parse_mac_address("AB:0C:DE:12:34:56").expect("Failed to parse mac address");
        assert_eq!(bytes, [0xAB, 0x0C, 0xDE, 0x12, 0x34, 0x56]);
    }

    fn clean_env_for_test_add_one_arp_neighbor(dummy_name: &str, ip: &str) {
        // ip link delete dummy
        Command::new("ip")
            .args(["link", "delete", dummy_name])
            .output()
            .expect("prepare: failed to delete dummy");

        // ip neigh del dev dummy ip
        Command::new("ip")
            .args(["neigh", "del", dummy_name, ip])
            .output()
            .expect("prepare: failed to delete neigh");
    }

    async fn prepare_env_for_test_add_one_arp_neighbor(dummy_name: &str, ip: &str) {
        clean_env_for_test_add_one_arp_neighbor(dummy_name, ip);
        // modprobe dummy
        Command::new("modprobe")
            .arg("dummy")
            .output()
            .expect("failed to run modprobe dummy");

        // ip link add dummy type dummy
        Command::new("ip")
            .args(["link", "add", dummy_name, "type", "dummy"])
            .output()
            .expect("failed to add dummy interface");

        // ip addr add 192.0.2.2/24 dev dummy
        Command::new("ip")
            .args(["addr", "add", "192.0.2.2/24", "dev", dummy_name])
            .output()
            .expect("failed to add ip for dummy");

        // ip link set dummy up;
        Command::new("ip")
            .args(["link", "set", dummy_name, "up"])
            .output()
            .expect("failed to up dummy");

        // Wait briefly to ensure the IP address addition is fully complete
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    #[serial(arp_neighbor_tests)]
    async fn test_add_one_arp_neighbor() {
        skip_if_not_root!();

        let mac = "6a:92:3a:59:70:aa";

        prepare_env_for_test_add_one_arp_neighbor(TEST_DUMMY_INTERFACE, TEST_ARP_IP).await;

        let mut ip_address = IPAddress::new();
        ip_address.set_address(TEST_ARP_IP.to_string());

        let mut neigh = ARPNeighbor::new();
        neigh.set_toIPAddress(ip_address);
        neigh.set_device(TEST_DUMMY_INTERFACE.to_string());
        neigh.set_lladdr(mac.to_string());
        neigh.set_state(0x80);

        Handle::new()
            .unwrap()
            .add_arp_neighbor(&neigh)
            .await
            .expect("Failed to add ARP neighbor");

        // ip neigh show dev dummy ip
        let output = Command::new("ip")
            .args(["neigh", "show", "dev", TEST_DUMMY_INTERFACE, TEST_ARP_IP])
            .output()
            .expect("failed to show neigh");

        let stdout = std::str::from_utf8(&output.stdout).expect("failed to convert stdout");
        let stderr = std::str::from_utf8(&output.stderr).expect("failed to convert stderr");
        assert!(
            output.status.success(),
            "`ip neigh show` returned exit code {:?}. stderr: {:?}",
            output.status.code(),
            stderr
        );
        assert_eq!(
            stdout.trim(),
            format!("{TEST_ARP_IP} lladdr {mac} PERMANENT")
        );

        clean_env_for_test_add_one_arp_neighbor(TEST_DUMMY_INTERFACE, TEST_ARP_IP);
    }

    #[tokio::test]
    #[serial(route_tests)]
    async fn update_routes_ipv4() {
        skip_if_not_root!();

        const IFACE: &str = "dummy_route4";
        const DEST: &str = "198.51.100.0/24";
        const GW: &str = "192.0.2.1";
        const IFACE_ADDR: &str = "192.0.2.2/24";

        // Setup: create dummy interface and assign an address so the gateway
        // is reachable (required for adding a route with a gateway).
        let _ = Command::new("ip").args(["link", "delete", IFACE]).output();
        Command::new("modprobe")
            .arg("dummy")
            .output()
            .expect("modprobe dummy");
        let out = Command::new("ip")
            .args(["link", "add", IFACE, "type", "dummy"])
            .output()
            .expect("ip link add");
        if !out.status.success() {
            println!(
                "INFO: skipping test - cannot create dummy link: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        struct Cleanup(&'static str);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("ip").args(["link", "delete", self.0]).output();
            }
        }
        let _cleanup = Cleanup(IFACE);

        let out = Command::new("ip")
            .args(["addr", "add", IFACE_ADDR, "dev", IFACE])
            .output()
            .expect("ip addr add");
        if !out.status.success() {
            println!(
                "INFO: skipping test - cannot assign address: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        Command::new("ip")
            .args(["link", "set", IFACE, "up"])
            .output()
            .expect("ip link set up");

        let mut handle = Handle::new().unwrap();
        let route = Route {
            dest: DEST.to_string(),
            gateway: GW.to_string(),
            device: IFACE.to_string(),
            ..Default::default()
        };

        let result = handle.update_routes(iter::once(route)).await;
        if is_netlink_permission_error(&result) {
            return;
        }
        result.expect("update_routes IPv4 failed");

        // Verify the route exists via `ip route show`.
        let out = Command::new("ip")
            .args(["route", "show", DEST])
            .output()
            .expect("ip route show");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("198.51.100"),
            "expected route not found in `ip route show` output: {}",
            stdout
        );
    }

    #[tokio::test]
    #[serial(route_tests)]
    async fn update_routes_ipv6() {
        skip_if_not_root!();

        const IFACE: &str = "dummy_route6";
        const DEST: &str = "2001:db8:1::/48";
        const GW: &str = "2001:db8::1";
        const IFACE_ADDR: &str = "2001:db8::2/32";

        let _ = Command::new("ip").args(["link", "delete", IFACE]).output();
        Command::new("modprobe")
            .arg("dummy")
            .output()
            .expect("modprobe dummy");
        let out = Command::new("ip")
            .args(["link", "add", IFACE, "type", "dummy"])
            .output()
            .expect("ip link add");
        if !out.status.success() {
            println!(
                "INFO: skipping test - cannot create dummy link: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        struct Cleanup(&'static str);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("ip").args(["link", "delete", self.0]).output();
            }
        }
        let _cleanup = Cleanup(IFACE);

        let out = Command::new("ip")
            .args(["addr", "add", IFACE_ADDR, "dev", IFACE])
            .output()
            .expect("ip addr add");
        if !out.status.success() {
            println!(
                "INFO: skipping test - cannot assign address: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        Command::new("ip")
            .args(["link", "set", IFACE, "up"])
            .output()
            .expect("ip link set up");

        let mut handle = Handle::new().unwrap();
        let mut route = Route::default();
        route.set_dest(DEST.to_string());
        route.set_gateway(GW.to_string());
        route.set_device(IFACE.to_string());
        route.set_family(IPFamily::v6);

        let result = handle.update_routes(iter::once(route)).await;
        if is_netlink_permission_error(&result) {
            return;
        }
        result.expect("update_routes IPv6 failed");

        // Verify the route exists via `ip -6 route show`.
        let out = Command::new("ip")
            .args(["-6", "route", "show", DEST])
            .output()
            .expect("ip -6 route show");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("2001:db8:1::"),
            "expected route not found in `ip -6 route show` output: {}",
            stdout
        );
    }
}
