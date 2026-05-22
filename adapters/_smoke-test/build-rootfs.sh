#!/usr/bin/env bash
# Build the smoke-test rootfs ext4 image.
#
# Prerequisites (Linux):
#   - Docker with buildx
#   - e2tools (e2cp, e2mkdir) or genext2fs, OR a loop device + root
#     (this script uses a Docker export + genext2fs for root-free operation)
#   - The crucible-init binary compiled for x86_64-unknown-linux-musl
#
# Usage (from repo root):
#   ./adapters/_smoke-test/build-rootfs.sh [output.ext4]
#
# Output defaults to: target/smoke-rootfs.ext4

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT="${1:-${REPO_ROOT}/target/smoke-rootfs.ext4}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

CRUCIBLE_INIT="${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/crucible-init"

die() { echo "build-rootfs: error: $*" >&2; exit 1; }
info() { echo "build-rootfs: $*"; }

# ── Verify prerequisites ──────────────────────────────────────────────────────

[[ -f "$CRUCIBLE_INIT" ]] || die \
    "crucible-init not found at $CRUCIBLE_INIT\n" \
    "Build it first:\n" \
    "  cargo build --release -p crucible-init --target x86_64-unknown-linux-musl"

command -v docker &>/dev/null || die "docker is required"

# ── Build the Docker image ────────────────────────────────────────────────────

info "building Docker image…"
docker buildx build \
    --platform linux/amd64 \
    --build-arg "CRUCIBLE_INIT=${CRUCIBLE_INIT}" \
    --output "type=tar,dest=${TMPDIR}/rootfs.tar" \
    "${REPO_ROOT}/adapters/_smoke-test"

info "extracting rootfs tar…"
mkdir -p "${TMPDIR}/rootfs"
tar -xf "${TMPDIR}/rootfs.tar" -C "${TMPDIR}/rootfs"

# ── Convert to ext4 ──────────────────────────────────────────────────────────

mkdir -p "$(dirname "$OUTPUT")"

info "creating ext4 image…"
if command -v genext2fs &>/dev/null; then
    # Root-free path: genext2fs
    genext2fs -b 262144 -d "${TMPDIR}/rootfs" "$OUTPUT"
    # Convert ext2 to ext4 in-place.
    if command -v tune2fs &>/dev/null; then
        tune2fs -O extent,uninit_bg,dir_index,filetype,has_journal "$OUTPUT" 2>/dev/null || true
    fi
elif [[ "$(id -u)" -eq 0 ]]; then
    # Root path: loop device
    dd if=/dev/zero of="$OUTPUT" bs=1M count=256
    mkfs.ext4 -q "$OUTPUT"
    LOOP="$(losetup -f --show "$OUTPUT")"
    MNTDIR="${TMPDIR}/mnt"
    mkdir -p "$MNTDIR"
    mount "$LOOP" "$MNTDIR"
    cp -a "${TMPDIR}/rootfs/." "$MNTDIR/"
    umount "$MNTDIR"
    losetup -d "$LOOP"
else
    die "either genext2fs or root access is required to create the ext4 image"
fi

info "rootfs ready: $OUTPUT"
info "  size: $(du -h "$OUTPUT" | cut -f1)"
