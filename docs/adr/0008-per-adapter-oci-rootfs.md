# Per-Adapter OCI rootfs, one shared kernel

Each Adapter declares an OCI image reference for the guest rootfs. On first use, `bunsen-core` pulls the image, flattens it to an ext4 file, and caches it on disk; boots from the cache thereafter. One shared vmlinux (vendored from Firecracker upstream) is used across all Adapters.

## Why

- **Per-agent runtime divergence.** Coding agents have wildly different runtime requirements: Claude Code wants Node + npm + the `@anthropic-ai/claude-code` package; aider wants Python + the `aider-chat` package; black-box agents want whatever the user uses. A single canonical rootfs that satisfies the union of every supported agent's dependencies would balloon in size and put bunsen in the package-manager business.
- **OCI is the universal Linux distribution format.** Adapter authors can build images using existing tooling (Dockerfile, buildah, nix-to-OCI, whatever) and publish them to existing registries. Bunsen doesn't reinvent rootfs distribution — it consumes a built image.
- **Caching by digest gives reproducibility for free.** Two bunsen installations referencing the same image digest boot identical guests, regardless of when they pulled.
- **The kernel is uniform.** Nothing about the kernel needs to differ between Adapters; one vendored vmlinux suffices and removes a degree of freedom that wasn't doing useful work.

## Considered Options

- **One canonical rootfs with all built-in agents pre-installed.** Smaller surface for Adapter authors, but the rootfs balloons, and bunsen inherits the maintenance burden of the union of every supported agent's dependencies. Rejected.
- **User-supplied rootfs as the primary path.** Maximum flexibility, maximum friction. Rejected as the primary path; kept as an escape hatch via `--rootfs`.
- **Per-Adapter Dockerfile-build-on-first-use.** Adapter ships a Dockerfile, bunsen builds the rootfs locally on first Run. Rejected: requires Docker (or another OCI builder) on every contributor's machine plus the full agent toolchain at build time. Defeats the "consume a built image" property.
- **Per-Adapter custom kernel.** Rejected — no Adapter has a need for a custom kernel today, and the cost of letting Adapters express kernel choice is real (build matrix, security review surface).

## Consequences

- Adapter authors are responsible for producing and publishing an OCI image. Built-in Adapters publish to a public registry (GHCR for v1).
- OCI image references in code are pinned by **digest**, not tag. Bumping the digest is a code change — the right surface area for "we changed what runs in the sandbox".
- First-Run latency includes a one-time pull + ext4 conversion (~30–90s for a typical image). Cached after that. The user sees explicit progress.
- The `--rootfs /path/to/custom.ext4` and `--kernel /path/to/vmlinux` overrides on `bunsen-core` give users an escape hatch for custom guest environments without forking bunsen.
- The init binary lives at a fixed path inside every image (e.g., `/sbin/bunsen-init`). Adapter image authors follow this convention; documented in the Adapter contract.
- The shared vmlinux is fetched lazily on first `run()` by `bunsen-core`, not at package install time and not vendored in git. We pin a Firecracker-upstream-blessed build by URL + SHA-256; `bunsen-core` verifies the checksum and caches the result under `~/.cache/bunsen/kernel/`. Cutting over to a custom kernel build is a future arc when we need a feature outside the upstream defconfig.
