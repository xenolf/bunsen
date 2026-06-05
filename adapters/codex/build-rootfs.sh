#!/usr/bin/env bash
# Build the codex adapter rootfs ext4 image and push to GHCR.
#
# The resulting image provides Node.js, npm, and the OpenAI Codex CLI on top
# of bunsen-base (Alpine + git + bunsen-init). bunsen-init is already baked
# into the base image — no cross-compilation step is needed here.
#
# Usage (from repo root):
#   ./adapters/codex/build-rootfs.sh [--push]
#
# Without --push the image is built locally only (useful for smoke-testing).
# With --push the image is pushed to GHCR and the digest is printed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REGISTRY="ghcr.io/xenolf/bunsen"
IMAGE_NAME="bunsen-adapter-codex"
TAG="dev"
PUSH=false

die()  { echo "build-rootfs: error: $*" >&2; exit 1; }
info() { echo "build-rootfs: $*"; }

for arg in "$@"; do
    case "$arg" in
        --push) PUSH=true ;;
        *) die "unknown argument: $arg" ;;
    esac
done

command -v docker &>/dev/null || die "docker is required"

FULL_TAG="${REGISTRY}/${IMAGE_NAME}:${TAG}"

info "building ${FULL_TAG} for linux/amd64…"
docker buildx build \
    --platform linux/amd64 \
    --tag "${FULL_TAG}" \
    "${REPO_ROOT}/adapters/codex"

if $PUSH; then
    info "pushing ${FULL_TAG}…"
    PUSH_OUTPUT="$(docker push "${FULL_TAG}" 2>&1)"
    echo "$PUSH_OUTPUT"

    # Extract the digest from the push output (format: "digest: sha256:<hex>")
    DIGEST="$(echo "$PUSH_OUTPUT" | grep -oP 'sha256:[0-9a-f]{64}' | tail -1)"
    if [[ -z "$DIGEST" ]]; then
        die "could not extract digest from docker push output — pin manually"
    fi

    PINNED_REF="${REGISTRY}/${IMAGE_NAME}@${DIGEST}"
    info "pinned ref: ${PINNED_REF}"
    info ""
    info "Update OCI_IMAGE in bunsen-core/src/codex_adapter.rs:"
    info "  pub const OCI_IMAGE: &str = \"${PINNED_REF}\";"
else
    info "image built locally (pass --push to publish and pin the digest)"
fi
