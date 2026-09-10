// Copyright (c) 2021 Kata Maintainers
//
// SPDX-License-Identifier: Apache-2.0
//

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

    let (family, dump_sid) = match ip {
        IpAddr::V4(_) => (AF_INET, SocketId::new_v4()),
        IpAddr::V6(_) => (AF_INET6, SocketId::new_v6()),
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
                        if resp.header.socket_id.source_address == ip {
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
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_packet_route::neighbour::{self, NeighbourFlag};
use netlink_packet_route::route::{RouteFlag, RouteHeader, RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    route::RouteMetric,
};
use netlink_packet_route::{
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourState},
    route::{RouteAddress, RouteAttribute, RouteMessage},
    AddressFamily,
};
use nix::errno::Errno;
use protocols::types::{ARPNeighbor, IPAddress, IPFamily, Interface, Route};
use rtnetlink::{new_connection, IpVersion};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str::{self, FromStr};

/// Search criteria to use when looking for a link in `find_link`.
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

const ALL_RULE_FLAGS: [NeighbourFlag; 8] = [
    NeighbourFlag::Use,
    NeighbourFlag::Own,
    NeighbourFlag::Controller,
    NeighbourFlag::Proxy,
    NeighbourFlag::ExtLearned,
    NeighbourFlag::Offloaded,
    NeighbourFlag::Sticky,
    NeighbourFlag::Router,
];

const ALL_ROUTE_FLAGS: [RouteFlag; 16] = [
    RouteFlag::Dead,
    RouteFlag::Pervasive,
    RouteFlag::Onlink,
    RouteFlag::Offload,
    RouteFlag::Linkdown,
    RouteFlag::Unresolved,
    RouteFlag::Trap,
    RouteFlag::Notify,
    RouteFlag::Cloned,
    RouteFlag::Equalize,
    RouteFlag::Prefix,
    RouteFlag::LookupTable,
    RouteFlag::FibMatch,
    RouteFlag::RtOffload,
    RouteFlag::RtTrap,
    RouteFlag::OffloadFailed,
];

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
        // Lookup precedence: hardware address first (most reliable when
        // the link's MAC matches what the caller knows), then fall back
        // to interface name. The fallback exists for live-migration:
        // the destination shim asks the agent to RESET the guest eth0's
        // MAC to the destination veth's MAC, but the guest's current
        // MAC is the SOURCE pod's MAC (carried in QEMU virtio-net state
        // across migration). MAC-based lookup with the desired NEW MAC
        // returns nothing — fall back to name. Once we have the link,
        // we set its MAC to iface.hwAddr unconditionally below; for
        // non-migration callers this is a no-op (set MAC to current
        // value), for migration callers it actually changes the MAC.
        let link = match self.find_link(LinkFilter::Address(&iface.hwAddr)).await {
            Ok(l) => l,
            Err(_) => self
                .find_link(LinkFilter::Name(iface.name.as_str()))
                .await
                .map_err(|e| {
                    anyhow!(
                        "update_interface: lookup failed by hwAddr={} and name={}: {}",
                        iface.hwAddr,
                        iface.name,
                        e
                    )
                })?,
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
                let mut request = self.handle.link().set(link.index());
                request.message_mut().header = link.header.clone();
                let link_name = link.name();
                let temp_name = link_name.clone() + "_temp";

                request
                    .name(temp_name.clone())
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

        // MAC update — done as a SEPARATE netlink request before the
        // mtu/name/arp/up combined call. Observed empirically: when
        // .address() is chained with .up() in a single LinkSet
        // message against a virtio-net device, the netlink syscall
        // hangs (rtnetlink waits for an ACK that never arrives) and
        // the caller times out after 40s. Splitting MAC into its own
        // message — applied while the link is still DOWN from the
        // earlier enable_link(false) call — sidesteps the hang and
        // commits cleanly.
        //
        // Lookup by INDEX (not MAC): if we're about to change the
        // MAC, MAC-based lookup would not find the link reliably.
        // The index is stable across MAC changes.
        let new_mac = parse_mac_address(&iface.hwAddr).map_err(|e| {
            anyhow!(
                "update_interface: cannot parse new hwAddr {:?}: {}",
                iface.hwAddr,
                e
            )
        })?;
        let link = self.find_link(LinkFilter::Index(link_index)).await?;
        // Case-insensitive compare: list_interfaces and the kata-shim
        // historically format MACs in different cases (kata-shim
        // emits lowercase, list_interfaces returns the kernel's
        // uppercase form). A naive equality check would cause every
        // call to issue an unnecessary MAC-set netlink request.
        if link.address().to_lowercase() != iface.hwAddr.to_lowercase() {
            // Only issue the MAC-set netlink call when the MAC is
            // actually changing. For non-migration callers (whose
            // hwAddr matches the link's current MAC) we skip this
            // entirely — saves a netlink roundtrip and avoids any
            // risk of regressing the existing happy path.
            let mut mac_req = self.handle.link().set(link.index());
            mac_req.message_mut().header = link.header.clone();
            mac_req
                .address(new_mac.to_vec())
                .execute()
                .await
                .map_err(|err| {
                    anyhow!(
                        "Failure setting MAC on interface {}: {}",
                        iface.name.as_str(),
                        err
                    )
                })?;
        }

        // Re-fetch the link after the MAC change so subsequent
        // operations see the updated header. Lookup by index since
        // MAC may have just changed.
        let link = self.find_link(LinkFilter::Index(link_index)).await?;
        let mut request = self.handle.link().set(link.index());
        request.message_mut().header = link.header.clone();

        request
            .mtu(iface.mtu as _)
            .name(iface.name.clone())
            .arp(iface.raw_flags & libc::IFF_NOARP as u32 == 0)
            .up()
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
            let mut request = self.handle.link().set(nlink.index());
            request.message_mut().header = nlink.header.clone();

            request
                .name(link.name())
                .up()
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

        next.map(|msg| msg.into())
            .ok_or_else(|| anyhow!("Link not found ({})", filter))
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
        let link_req = self.handle.link().set(link_index);
        let set_req = if up { link_req.up() } else { link_req.down() };
        set_req.execute().await?;
        Ok(())
    }

    async fn query_routes(&self, ip_version: Option<IpVersion>) -> Result<Vec<RouteMessage>> {
        let list = if let Some(ip_version) = ip_version {
            self.handle
                .route()
                .get(ip_version)
                .execute()
                .try_collect()
                .await?
        } else {
            // These queries must be executed sequentially, otherwise
            // it'll throw "Device or resource busy (os error 16)"
            let routes4 = self
                .handle
                .route()
                .get(IpVersion::V4)
                .execute()
                .try_collect::<Vec<_>>()
                .await
                .with_context(|| "Failed to query IP v4 routes")?;

            let routes6 = self
                .handle
                .route()
                .get(IpVersion::V6)
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

            // Build a common indeterminate ip request
            let mut request = self
                .handle
                .route()
                .add()
                .table_id(MAIN_TABLE)
                .kind(uni_cast)
                .protocol(boot_prot)
                .scope(scope);

            let message = request.message_mut();

            // calculate the Flag vec from the u32 flags
            let mut got: u32 = 0;
            let mut flags = Vec::new();
            for flag in ALL_ROUTE_FLAGS {
                if (route.flags & (u32::from(flag))) > 0 {
                    flags.push(flag);
                    got += u32::from(flag);
                }
            }
            if got != route.flags {
                flags.push(RouteFlag::Other(route.flags - got));
            }

            message.header.flags = flags;

            if route.mtu != 0 {
                let route_metrics = vec![RouteMetric::Mtu(route.mtu)];
                message
                    .attributes
                    .push(RouteAttribute::Metrics(route_metrics));
            }

            // `rtnetlink` offers a separate request builders for different IP versions (IP v4 and v6).
            // This if branch is a bit clumsy because it does almost the same.
            if route.family() == IPFamily::v6 {
                let dest_addr = if !route.dest.is_empty() {
                    Ipv6Network::from_str(&route.dest)?
                } else {
                    Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)?
                };

                // Build IP v6 request
                let mut request = request
                    .v6()
                    .destination_prefix(dest_addr.ip(), dest_addr.prefix())
                    .output_interface(link.index())
                    .replace();

                if !route.source.is_empty() {
                    let network = Ipv6Network::from_str(&route.source)?;
                    if network.prefix() > 0 {
                        request = request.source_prefix(network.ip(), network.prefix());
                    } else {
                        request
                            .message_mut()
                            .attributes
                            .push(Nla::PrefSource(RouteAddress::from(network.ip())));
                    }
                }

                if !route.gateway.is_empty() {
                    let ip = Ipv6Addr::from_str(&route.gateway)?;
                    request = request.gateway(ip);
                }

                if let Err(rtnetlink::Error::NetlinkError(message)) = request.execute().await {
                    if let Some(code) = message.code {
                        if Errno::from_i32(code.get()) != Errno::EEXIST {
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
                let mut request = request
                    .v4()
                    .destination_prefix(dest_addr.ip(), dest_addr.prefix())
                    .output_interface(link.index())
                    .replace();

                if !route.source.is_empty() {
                    // Always set RTA_PREFSRC (PrefSource) so the route's
                    // `src` hint steers Linux source-address-selection
                    // for new outbound connections that use this route.
                    //
                    // Previously this branched on prefix: prefix > 0 →
                    // source_prefix() which sets RTA_SRC (source-based
                    // routing match, NOT preferred source). That
                    // semantics is for routing rules conditioned on
                    // source IP and is a different feature entirely.
                    // For the migration-renumber case (and every other
                    // caller in practice) we want the prefsrc hint.
                    //
                    // Accept either bare IP ("10.0.0.1") or CIDR
                    // ("10.0.0.1/32"). Bare IP first since it's the
                    // natural form for an IP hint; fall back to
                    // Ipv4Network for legacy callers that send CIDR.
                    let ip = if let Ok(addr) = Ipv4Addr::from_str(&route.source) {
                        addr
                    } else {
                        Ipv4Network::from_str(&route.source)?.ip()
                    };
                    request
                        .message_mut()
                        .attributes
                        .push(RouteAttribute::PrefSource(RouteAddress::from(ip)));
                }

                if !route.gateway.is_empty() {
                    let ip = Ipv4Addr::from_str(&route.gateway)?;
                    request = request.gateway(ip);
                }

                if let Err(rtnetlink::Error::NetlinkError(message)) = request.execute().await {
                    if let Some(code) = message.code {
                        if Errno::from_i32(code.get()) != Errno::EEXIST {
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

        // Import rtnetlink objects that make sense only for this function
        use libc::{NDA_UNSPEC, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST};
        use neighbour::{NeighbourHeader, NeighbourMessage};
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use netlink_packet_route::RouteNetlinkMessage as RtnlMessage;
        use rtnetlink::Error;

        const IFA_F_PERMANENT: u16 = 0x80; // See https://github.com/little-dude/netlink/blob/0185b2952505e271805902bf175fee6ea86c42b8/netlink-packet-route/src/rtnl/constants.rs#L770
        let state = if neigh.state != 0 {
            neigh.state as u16
        } else {
            IFA_F_PERMANENT
        };

        let link = self.find_link(LinkFilter::Name(&neigh.device)).await?;

        let mut flags = Vec::new();
        for flag in ALL_RULE_FLAGS {
            if (neigh.flags as u8 & (u8::from(flag))) > 0 {
                flags.push(flag);
            }
        }

        let mut message = NeighbourMessage::default();

        message.header = NeighbourHeader {
            family: match ip {
                IpAddr::V4(_) => AddressFamily::Inet,
                IpAddr::V6(_) => AddressFamily::Inet6,
            },
            ifindex: link.index(),
            state: NeighbourState::from(state),
            flags,
            kind: RouteType::from(NDA_UNSPEC as u8),
        };

        let mut nlas = vec![NeighbourAttribute::Destination(match ip {
            IpAddr::V4(ipv4_addr) => NeighbourAddress::from(ipv4_addr),
            IpAddr::V6(ipv6_addr) => NeighbourAddress::from(ipv6_addr),
        })];

        if !neigh.lladdr.is_empty() {
            nlas.push(NeighbourAttribute::LinkLocalAddress(
                parse_mac_address(&neigh.lladdr)?.to_vec(),
            ));
        }

        message.attributes = nlas;

        // Send request and ACK
        let mut req = NetlinkMessage::from(RtnlMessage::NewNeighbour(message));
        req.header.flags = (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE) as u16;

        let mut response = self.handle.request(req)?;
        while let Some(message) = response.next().await {
            if let NetlinkPayload::Error(err) = message.payload {
                return Err(anyhow!(Error::NetlinkError(err)));
            }
        }

        Ok(())
    }
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
        let mut flags: u32 = 0;
        for flag in &self.header.flags {
            flags += u32::from(*flag);
        }

        flags as i32 & libc::IFF_UP > 0
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
}
