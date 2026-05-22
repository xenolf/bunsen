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

set -euo pipefail

# ── Pinned kernel ────────────────────────────────────────────────────────────
# Firecracker v1.7.0 guest kernel (x86_64).
# Source: https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md
KERNEL_VERSION="6.1.102"
KERNEL_SHA256="7c6d47f09f98d6e8da4dd0ef2a5d3edfb6f1a7f9c5a9e8b3d2e1f0a4c7b6d5e2"
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.7/x86_64/vmlinux-${KERNEL_VERSION}"
# ─────────────────────────────────────────────────────────────────────────────
# NOTE: Replace KERNEL_SHA256 with the actual SHA-256 from the Firecracker
# release notes before using this script in production.
# ─────────────────────────────────────────────────────────────────────────────

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
        info "cached vmlinux matches pinned SHA-256 ✓"
        exit 0
    else
        exit 1
    fi
fi

# ── Download ──────────────────────────────────────────────────────────────────

mkdir -p "$CACHE_DIR"

if [[ -f "$DEST" ]]; then
    if verify "$DEST" "$KERNEL_SHA256"; then
        info "already cached: $DEST"
        ln -sf "$DEST" "$LINK"
        exit 0
    else
        info "cached file is corrupt — re-downloading"
        rm -f "$DEST"
    fi
fi

info "downloading vmlinux-${KERNEL_VERSION}…"
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
