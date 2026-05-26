#!/usr/bin/env bash
# Download a Firecracker-blessed vmlinux to the local cache and verify its SHA-256.
#
# Usage:
#   ./kernel/fetch-vmlinux.sh          # download if not already cached
#   ./kernel/fetch-vmlinux.sh --check  # exit 0 if cache matches, non-zero otherwise
#
# The cached kernel lands at:
#   ${XDG_CACHE_HOME:-~/.cache}/crucible/kernel/vmlinux-<VERSION>
# and is symlinked as:
#   ${XDG_CACHE_HOME:-~/.cache}/crucible/kernel/vmlinux  (the default for builds)
#
# Host architecture is detected from `uname -m`; the constants below must agree
# with crucible-core/src/kernel.rs (KERNEL_VERSION / KERNEL_URL / KERNEL_SHA256)
# so the two implementations share a cache.

set -euo pipefail

# ── Pinned kernel ────────────────────────────────────────────────────────────
# Firecracker-CI guest kernel. CI_VERSION tracks the matching Firecracker
# release line; see:
#   https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md
CI_VERSION="v1.15"
KERNEL_VERSION="6.1.155"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)
        KERNEL_SHA256="e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2"
        KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/${CI_VERSION}/x86_64/vmlinux-${KERNEL_VERSION}"
        ;;
    aarch64|arm64)
        # Linux reports aarch64; macOS reports arm64. Both map to the same
        # Firecracker aarch64 image — but Firecracker only runs on Linux, so
        # the macOS case is only useful for `--check`-style smoke tests.
        KERNEL_SHA256="e3544b10603acbf3db492cb52e000d22ba202cb4b63b9add027565683e11c591"
        KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/${CI_VERSION}/aarch64/vmlinux-${KERNEL_VERSION}"
        ;;
    *)
        echo "fetch-vmlinux: error: unsupported architecture: $ARCH (expected x86_64 or aarch64)" >&2
        exit 1
        ;;
esac

CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/crucible/kernel"
DEST="${CACHE_DIR}/vmlinux-${KERNEL_VERSION}"
LINK="${CACHE_DIR}/vmlinux"

# ── Helpers ──────────────────────────────────────────────────────────────────

die() { echo "fetch-vmlinux: error: $*" >&2; exit 1; }
info() { echo "fetch-vmlinux: $*"; }

sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "no sha256sum or shasum found"
    fi
}

verify() {
    local file="$1"
    local want="$2"
    local got
    got=$(sha256_of "$file")
    if [[ "$got" != "$want" ]]; then
        echo "fetch-vmlinux: SHA-256 mismatch" >&2
        echo "  expected: $want" >&2
        echo "  got:      $got" >&2
        return 1
    fi
    return 0
}

# ── --check mode ──────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--check" ]]; then
    if [[ ! -f "$DEST" ]]; then
        echo "fetch-vmlinux: not cached at $DEST" >&2
        exit 1
    fi
    if verify "$DEST" "$KERNEL_SHA256"; then
        info "cached vmlinux matches pinned SHA-256 ($ARCH) ✓"
        exit 0
    else
        exit 1
    fi
fi

# ── Download ──────────────────────────────────────────────────────────────────

mkdir -p "$CACHE_DIR"

if [[ -f "$DEST" ]]; then
    if verify "$DEST" "$KERNEL_SHA256"; then
        info "already cached ($ARCH): $DEST"
        ln -sf "$DEST" "$LINK"
        exit 0
    else
        info "cached file is corrupt — re-downloading"
        rm -f "$DEST"
    fi
fi

info "downloading vmlinux-${KERNEL_VERSION} for $ARCH…"
info "  from: $KERNEL_URL"
info "  to:   $DEST"

if command -v curl &>/dev/null; then
    curl -fsSL -o "$DEST.tmp" "$KERNEL_URL"
elif command -v wget &>/dev/null; then
    wget -q -O "$DEST.tmp" "$KERNEL_URL"
else
    die "curl or wget required"
fi

info "verifying SHA-256…"
verify "$DEST.tmp" "$KERNEL_SHA256" || {
    rm -f "$DEST.tmp"
    die "SHA-256 verification failed — download may be corrupt"
}

mv "$DEST.tmp" "$DEST"
ln -sf "$DEST" "$LINK"
info "vmlinux ready at $LINK"
