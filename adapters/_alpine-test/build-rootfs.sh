#!/usr/bin/env bash
# Build the alpine-test rootfs ext4 image.
#
# Sibling of adapters/_smoke-test/build-rootfs.sh. Builds a rootfs from
# alpine:3.19 with apk-installed git and bunsen-init as PID 1, used by
# the egress acceptance suite to exercise the enforcer against a real
# OCI-derived rootfs (vs. the busybox-static smoke rootfs).
#
# Usage (from repo root):
#   ./adapters/_alpine-test/build-rootfs.sh [output.ext4]
#
# Output defaults to: target/alpine-rootfs.ext4

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT="${1:-${REPO_ROOT}/target/alpine-rootfs.ext4}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

BUNSEN_INIT="${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/bunsen-init"

die() { echo "build-rootfs: error: $*" >&2; exit 1; }
info() { echo "build-rootfs: $*"; }

# ── Verify prerequisites ──────────────────────────────────────────────────────

[[ -f "$BUNSEN_INIT" ]] || die \
    "bunsen-init not found at $BUNSEN_INIT — build it first:
  cargo build --release -p bunsen-init --target x86_64-unknown-linux-musl"

command -v docker &>/dev/null || die "docker is required"

# ── Assemble build context in TMPDIR ─────────────────────────────────────────
# Docker COPY can only reach files inside the build context directory.

cp "${REPO_ROOT}/adapters/_alpine-test/Dockerfile" "$TMPDIR/Dockerfile"
cp "$BUNSEN_INIT" "$TMPDIR/bunsen-init"

# ── Build Docker image ────────────────────────────────────────────────────────

IMAGE="bunsen-alpine-rootfs-$$"
info "building Docker image…"
docker buildx build \
    --platform linux/amd64 \
    --output "type=tar,dest=${TMPDIR}/rootfs.tar" \
    --tag "$IMAGE" \
    "$TMPDIR"

# ── Extract rootfs ────────────────────────────────────────────────────────────

info "extracting rootfs tar…"
mkdir -p "${TMPDIR}/rootfs"
tar -xf "${TMPDIR}/rootfs.tar" -C "${TMPDIR}/rootfs"

# ── Convert to ext4 ──────────────────────────────────────────────────────────

mkdir -p "$(dirname "$OUTPUT")"

info "creating ext4 image…"
if command -v genext2fs &>/dev/null; then
    genext2fs -b 262144 -d "${TMPDIR}/rootfs" "$OUTPUT"
    if command -v tune2fs &>/dev/null; then
        tune2fs -O extent,uninit_bg,dir_index,filetype,has_journal "$OUTPUT" 2>/dev/null || true
    fi
elif [[ "$(id -u)" -eq 0 ]]; then
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
