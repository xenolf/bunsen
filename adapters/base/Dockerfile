# Canonical bunsen base rootfs.
#
# Minimal Alpine guest published as ghcr.io/xenolf/bunsen/bunsen-base by
# .github/workflows/images.yml and pinned by digest as DEFAULT_ROOTFS_IMAGE
# in bunsen-core. Contains: Alpine base (busybox, apk, ca-certificates),
# git, and bunsen-init. Users extend it via their own Dockerfile.
#
# See docs/adr/0012-shipped-base-rootfs-with-ci-default.md and
# docs/adapter-contract.md (§OCI image) for the guest contract.

FROM alpine:3.23

RUN apk add --no-cache git
RUN rm -f /sbin/init
RUN mkdir -p /workspace /run/bunsen /proc /sys /dev /tmp

# Bind-mount target for the resolv.conf installed by bunsen-init at boot.
# Alpine's minimal base doesn't ship /etc/resolv.conf because Docker normally
# writes it at container start; we boot under Firecracker with a read-only
# rootfs, so the file must exist up-front for `mount --bind` to succeed.
# Docker bind-mounts the host's /etc/resolv.conf during every `RUN` step,
# making it impossible to create the file via `RUN`. `COPY` operates on the
# layer's filesystem directly, bypassing the bind-mount.
COPY <<EOF /etc/resolv.conf
# placeholder for bunsen-init bind-mount
EOF

# bunsen-init is cross-compiled and copied into the build context by the
# images CI workflow (or a local build-rootfs.sh wrapper).
COPY bunsen-init /sbin/bunsen-init
RUN chmod 755 /sbin/bunsen-init && ln -sf /sbin/bunsen-init /sbin/init
