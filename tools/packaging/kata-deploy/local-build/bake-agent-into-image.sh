#!/usr/bin/env bash
# Bake a patched kata-agent (and, optionally, a patched
# containerd-shim-kata-v2) INTO a kata-deploy image so the booted guest
# rootfs ships the patched agent by construction.
#
# Why this exists
# ---------------
# The kata-qemu runtime boots the guest from an ext4 rootfs image
# (kata-ubuntu-noble.image), NOT the initrd. The agent inside that ext4
# is what runs as the guest's init. Patching the agent on each node
# after deploy is racy: every kata-deploy extract (rollout, liveness
# restart, node replacement) re-lays the stock ext4 and silently
# reverts the patch. Baking the agent into the ext4 *inside the image*
# makes delivery correct by construction — any extract yields the
# patched agent, with zero node-side action.
#
# The ext4 patch needs a loop mount, which a plain `RUN` cannot do.
# This script uses a BuildKit `RUN --security=insecure` step (requires
# a builder created with the security.insecure entitlement) to loop-
# mount the ext4 inside the build, swap the agent, and unmount — so the
# whole bake is one reproducible image build, usable identically from
# CI and from a developer's machine.
#
# Inputs (env or flags)
# ---------------------
#   BASE_IMAGE     (required) kata-deploy image to layer onto. MUST be a
#                  zstd-QEMU build — this script verifies that and fails
#                  if the QEMU lacks zstd (preserve zstd by construction).
#   AGENT_BINARY   (required) path to the patched kata-agent (linux/amd64).
#   OUTPUT_IMAGE   (required) tag to build and (by default) push.
#   SHIM_BINARY    (optional) path to a patched containerd-shim-kata-v2 to
#                  bake alongside the agent. Omit to inherit the base shim.
#   PUSH           (default 1) push OUTPUT_IMAGE to its registry.
#   REGISTRY_USER  (default anoop2811) docker-login user for ghcr.io pushes.
#   BUILDER_NAME   (default insecure-bake) buildx builder with the
#                  security.insecure entitlement; created if missing.
#   EXT4_OFFSET    (default 3145728) ext4 partition offset in the image
#                  file (kata's standard 6144*512 header).
#
# Brand-neutral by design: this lives in the kata fork and names nothing
# downstream-specific. Callers supply the patched binaries and tags.

set -euo pipefail

BASE_IMAGE="${BASE_IMAGE:-}"
AGENT_BINARY="${AGENT_BINARY:-}"
OUTPUT_IMAGE="${OUTPUT_IMAGE:-}"
SHIM_BINARY="${SHIM_BINARY:-}"
PUSH="${PUSH:-1}"
REGISTRY_USER="${REGISTRY_USER:-${GHCR_USER:-anoop2811}}"
BUILDER_NAME="${BUILDER_NAME:-insecure-bake}"
EXT4_OFFSET="${EXT4_OFFSET:-3145728}"

# Allow positional override: bake-agent-into-image.sh BASE OUTPUT AGENT [SHIM]
[[ -n "${1:-}" ]] && BASE_IMAGE="$1"
[[ -n "${2:-}" ]] && OUTPUT_IMAGE="$2"
[[ -n "${3:-}" ]] && AGENT_BINARY="$3"
[[ -n "${4:-}" ]] && SHIM_BINARY="$4"

die() { echo "ERROR: $*" >&2; exit 1; }
section() { echo; echo "=== $1 ==="; }

[[ -n "$BASE_IMAGE"  ]] || die "BASE_IMAGE is required (a zstd-QEMU kata-deploy image)"
[[ -n "$OUTPUT_IMAGE" ]] || die "OUTPUT_IMAGE is required"
[[ -n "$AGENT_BINARY" && -s "$AGENT_BINARY" ]] || die "AGENT_BINARY must point to a non-empty patched kata-agent"
[[ -z "$SHIM_BINARY" || -s "$SHIM_BINARY" ]] || die "SHIM_BINARY is set but empty/missing: $SHIM_BINARY"

# ELF e_machine sanity: refuse a non-amd64 agent (a recurring Mac-host footgun).
e_machine=$(dd if="$AGENT_BINARY" bs=1 skip=18 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
[[ "$e_machine" == "3e00" ]] || die "AGENT_BINARY e_machine=$e_machine; expected 3e00 (x86_64)"

CTX="$(mktemp -d -t kata-bake-XXXXXX)"
trap 'rm -rf "$CTX"' EXIT
cp "$AGENT_BINARY" "$CTX/kata-agent"
if [[ -n "$SHIM_BINARY" ]]; then
  cp "$SHIM_BINARY" "$CTX/containerd-shim-kata-v2"
  SHIM_COPY='COPY containerd-shim-kata-v2 /opt/kata-artifacts/opt/kata/bin/containerd-shim-kata-v2'
else
  SHIM_COPY='# (no SHIM_BINARY — inherit shim from BASE_IMAGE)'
fi

section "Context"
echo "BASE_IMAGE=$BASE_IMAGE"
echo "OUTPUT_IMAGE=$OUTPUT_IMAGE"
echo "AGENT_BINARY=$AGENT_BINARY ($(stat -c%s "$AGENT_BINARY") bytes)"
echo "SHIM_BINARY=${SHIM_BINARY:-<none>}"
echo "EXT4_OFFSET=$EXT4_OFFSET  PUSH=$PUSH  BUILDER=$BUILDER_NAME"

# The bake (loop mount + zstd verify) runs in an ubuntu tooling stage that
# has util-linux/e2fsprogs/binutils, so the minimal kata-deploy base needs
# no tools. The patched ext4 and verified-zstd assertion both come out of
# that stage; the final stage is byte-identical to base except for the
# patched ext4 and (optional) shim.
cat > "$CTX/Dockerfile" <<DOCKERFILE
# syntax=docker/dockerfile:1
ARG BASE_IMAGE
FROM \${BASE_IMAGE} AS base

FROM ubuntu:24.04 AS patcher
ARG EXT4_OFFSET
RUN apt-get update \\
 && apt-get install -y --no-install-recommends util-linux e2fsprogs binutils file \\
 && rm -rf /var/lib/apt/lists/*
# Discover the ext4 rootfs and qemu inside the base; copy them out to patch
# and verify. The rootfs is resolved via the kata-containers.img symlink —
# i.e. the image the standard runtime actually boots — NOT a glob+head-1,
# which alphabetically selects kata-ubuntu-noble-confidential.image
# ('-' < '.') and would (a) patch the wrong image, leaving the real one
# stale, and (b) corrupt the confidential image's dm-verity hash.
COPY --from=base /opt/kata-artifacts /opt/kata-artifacts
COPY kata-agent /work/kata-agent-new
RUN --security=insecure set -eu; \\
    EXT4=\$(readlink -f /opt/kata-artifacts/opt/kata/share/kata-containers/kata-containers.img 2>/dev/null); \\
    { [ -n "\$EXT4" ] && [ -f "\$EXT4" ]; } || EXT4=\$(ls /opt/kata-artifacts/opt/kata/share/kata-containers/kata-ubuntu-*.image 2>/dev/null | grep -vE 'confidential|nvidia' | head -1); \\
    [ -n "\$EXT4" ] && [ -f "\$EXT4" ] || { echo "FAIL: no standard kata rootfs (kata-containers.img target) under /opt/kata-artifacts"; ls -lR /opt/kata-artifacts/opt/kata/share/kata-containers 2>/dev/null | head; exit 1; }; \\
    echo "ext4: \$EXT4"; \\
    mkdir -p /mnt/r; \\
    mount -o loop,offset=${EXT4_OFFSET} "\$EXT4" /mnt/r; \\
    [ -f /mnt/r/usr/bin/kata-agent ] || { echo "FAIL: no /usr/bin/kata-agent in ext4"; ls -la /mnt/r/usr/bin 2>/dev/null | head; umount /mnt/r; exit 1; }; \\
    cp /work/kata-agent-new /mnt/r/usr/bin/kata-agent; chmod 0755 /mnt/r/usr/bin/kata-agent; \\
    if [ -e /mnt/r/sbin/init ]; then cp /work/kata-agent-new /mnt/r/sbin/init; chmod 0755 /mnt/r/sbin/init; fi; \\
    sync; umount /mnt/r; \\
    echo "agent baked in place at \$EXT4"
# zstd verification (preserve zstd by construction — fail the build otherwise).
RUN set -eu; \\
    Q=\$(ls /opt/kata-artifacts/opt/kata/bin/qemu-system-* 2>/dev/null | head -1); \\
    [ -n "\$Q" ] || { echo "FAIL: no qemu-system-* under /opt/kata-artifacts/opt/kata/bin"; exit 1; }; \\
    echo "qemu: \$Q"; \\
    if readelf -d "\$Q" 2>/dev/null | grep -qi 'libzstd'; then echo "zstd OK: NEEDED libzstd"; \\
    elif strings "\$Q" | grep -qi 'multifd-zstd\\|multifd.*zstd\\|zstd'; then echo "zstd OK: zstd strings present"; \\
    else echo "FR-002 FAIL: QEMU \$Q has no zstd (base is not a zstd build)"; exit 1; fi

FROM base AS final
# The kata-deploy base is distroless (no /bin/sh), so the final stage must be
# shell-free — COPY, never RUN. The patcher baked the agent into the ext4 in
# place under share/kata-containers, so copy that dir (carries the patched
# kata-ubuntu-*.image + initrd) back over the base's.
COPY --from=patcher /opt/kata-artifacts/opt/kata/share/kata-containers /opt/kata-artifacts/opt/kata/share/kata-containers
${SHIM_COPY}
DOCKERFILE

echo "----- Dockerfile -----"; cat -n "$CTX/Dockerfile"; echo "-----"

section "Ensure buildx builder with security.insecure entitlement ($BUILDER_NAME)"
if ! docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER_NAME" --driver docker-container \
    --buildkitd-flags '--allow-insecure-entitlement security.insecure' >/dev/null
fi
docker buildx use "$BUILDER_NAME"

if [[ "$PUSH" == "1" && "$OUTPUT_IMAGE" == ghcr.io/* ]]; then
  section "Login to ghcr.io as $REGISTRY_USER"
  gh auth token | docker login ghcr.io -u "$REGISTRY_USER" --password-stdin
fi

if [[ "$PUSH" == "1" ]]; then section "Build + push $OUTPUT_IMAGE"; else section "Build (--load, no push) $OUTPUT_IMAGE"; fi
build_args=(
  buildx build
  --allow security.insecure
  --platform=linux/amd64
  --build-arg "BASE_IMAGE=$BASE_IMAGE"
  --build-arg "EXT4_OFFSET=$EXT4_OFFSET"
  -t "$OUTPUT_IMAGE"
  -f "$CTX/Dockerfile"
)
if [[ "$PUSH" == "1" ]]; then build_args+=(--push); else build_args+=(--load); fi
docker "${build_args[@]}" "$CTX"

section "Done"
echo "Baked image: $OUTPUT_IMAGE"
echo "  - patched kata-agent inside kata-ubuntu-*.image (ext4)"
[[ -n "$SHIM_BINARY" ]] && echo "  - patched containerd-shim-kata-v2"
echo "  - zstd QEMU verified present"
