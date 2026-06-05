#!/usr/bin/env bash
# Build and publish the pi adapter OCI image.
#
# Builds a linux/amd64 image containing Node.js and the pi coding agent on
# top of the bunsen base image, pushes to GHCR, and prints the digest to
# pin in bunsen-core/src/pi_adapter.rs as OCI_IMAGE.
#
# Usage (from repo root):
#   ./adapters/pi/build-rootfs.sh [--push]
#
# Flags:
#   --push   Push to ghcr.io/xenolf/bunsen/bunsen-adapter-pi after build.
#            Without this flag the image is built but not pushed.
#
# Prerequisites:
#   - Docker with buildx support
#   - Authenticated to ghcr.io (docker login ghcr.io) when using --push

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REGISTRY="ghcr.io/xenolf/bunsen"
IMAGE_NAME="bunsen-adapter-pi"
IMAGE="${REGISTRY}/${IMAGE_NAME}"
PUSH=0

die()  { echo "build-rootfs: error: $*" >&2; exit 1; }
info() { echo "build-rootfs: $*"; }

for arg in "$@"; do
    case "$arg" in
        --push) PUSH=1 ;;
        *) die "unknown argument: $arg" ;;
    esac
done

# ── Verify prerequisites ──────────────────────────────────────────────────────

command -v docker &>/dev/null || die "docker is required"
docker buildx version &>/dev/null || die "docker buildx is required"

# ── Build Docker image ────────────────────────────────────────────────────────

DOCKERFILE="${REPO_ROOT}/adapters/pi/Dockerfile"
[[ -f "$DOCKERFILE" ]] || die "Dockerfile not found at $DOCKERFILE"

info "building Docker image for linux/amd64…"

if [[ "$PUSH" -eq 1 ]]; then
    # Build and push; capture the digest from the push output.
    DIGEST_OUTPUT="$(
        docker buildx build \
            --platform linux/amd64 \
            --tag "${IMAGE}:latest" \
            --push \
            --metadata-file /tmp/pi-buildx-metadata.json \
            --file "$DOCKERFILE" \
            "${REPO_ROOT}/adapters/pi" 2>&1
    )"
    info "$DIGEST_OUTPUT"

    if [[ -f /tmp/pi-buildx-metadata.json ]]; then
        DIGEST="$(python3 -c "import json,sys; d=json.load(open('/tmp/pi-buildx-metadata.json')); print(d['containerimage.digest'])" 2>/dev/null || true)"
        if [[ -n "$DIGEST" ]]; then
            info "digest: $DIGEST"
            info ""
            info "Pin this in bunsen-core/src/pi_adapter.rs:"
            info "  pub const OCI_IMAGE: &str = \"${IMAGE}@${DIGEST}\";"
        else
            info "Could not extract digest from metadata. Run:"
            info "  docker inspect --format='{{index .RepoDigests 0}}' ${IMAGE}:latest"
        fi
        rm -f /tmp/pi-buildx-metadata.json
    fi
else
    docker buildx build \
        --platform linux/amd64 \
        --tag "${IMAGE}:dev" \
        --load \
        --file "$DOCKERFILE" \
        "${REPO_ROOT}/adapters/pi"

    info "image built locally as ${IMAGE}:dev (not pushed)"
    info "Re-run with --push to publish and get the digest."
fi
