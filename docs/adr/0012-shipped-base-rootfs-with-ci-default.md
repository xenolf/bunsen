# Shipped base rootfs image with CI-built default

A minimal Alpine-based rootfs image (`bunsen-base`) is built by CI, published to GHCR as a multi-arch image, and pinned by digest as the default rootfs in `bunsen-core`. Users who supply neither `--rootfs` nor `oci-image` in their run spec get this image automatically.

## Why

- **Zero-config first run.** Without a shipped default, every new user must produce or source an ext4 image before running anything. The kernel is already fetched automatically; the rootfs gap was the remaining friction.
- **Base-only, not agent-specific.** A pre-installed Claude Code or aider image would be larger, harder to keep current, and would bake in assumptions about what the user wants. A minimal Alpine image (git + bunsen-init) is the lowest-common-denominator guest that users can extend via their own Dockerfile.
- **apk must work at runtime.** Alpine's package manager is the extension mechanism. The image ships with apk installed (Alpine base) and ca-certificates (also Alpine base) so HTTPS works. Users add `dl-cdn.alpinelinux.org` to their Egress Policy when they need `apk add` inside a Run.
- **Digest pin is a code change.** Consistent with ADR-0008: the default is a `const DEFAULT_ROOTFS_IMAGE` in `oci_cache.rs` pinned by digest, not by tag. When CI publishes a new image it opens an automated PR updating this constant. No human has to remember to do it; no merge happens without a code review surface.

## Considered Options

- **Agent-specific image as the default.** A Claude Code image (Node + claude-code + bunsen-init) would let users run without any configuration at all. Rejected: it decides which agent the user wants, balloons the image, and ties the default to a specific agent's release cadence.
- **Documented starting point only.** Publish the image but leave `--rootfs` required. Rejected: a user still has to find the right digest and wire it up. Eliminates the friction only partially.
- **`BUNSEN_ROOTFS` environment variable.** Following the `BUNSEN_KERNEL` pattern, an env var could override the default without a CLI flag. Rejected: `--rootfs` and `oci-image` in the run spec already cover the override cases. A third path adds surface area without filling a gap.

## Consequences

- **Image**: `ghcr.io/xenolf/bunsen/bunsen-base`, Alpine 3.23 + git + bunsen-init. Multi-arch manifest (linux/amd64 + linux/arm64).
- **Tags**: `latest` + git SHA short hash. Code always pins by digest, never by tag.
- **CI trigger**: push to `main` filtered to the base image Dockerfile path, plus `workflow_dispatch`. Decoupled from the wheel release tag so kernel/rootfs and Python package lifecycles stay independent.
- **bunsen-init**: cross-compiled for both targets (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) inside the image CI workflow. Not reused from the release workflow — self-contained.
- **Auto-PR**: after pushing the image, the CI workflow extracts the multi-arch manifest digest and opens a PR updating `DEFAULT_ROOTFS_IMAGE` in `oci_cache.rs`. Requires `packages: write` and `pull-requests: write` on the workflow.
- **Fallback resolution order** (when kernel is resolved and no `--rootfs` flag):
  1. `oci-image` in run spec → pulled and cached as before (ADR-0008).
  2. `DEFAULT_ROOTFS_IMAGE` const → pulled and cached on first use.
