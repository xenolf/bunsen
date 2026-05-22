# Build the smoke-test rootfs.
#
# The image contains:
#   - Alpine Linux base (musl libc, BusyBox)
#   - crucible-init at /sbin/crucible-init (the guest PID-1 binary, statically linked)
#
# The kernel boots with init=/sbin/crucible-init, which reads the spec from
# the kernel cmdline (crucible_spec=<base64-json>), forks the agent, and
# plumbs stdout/stderr/control over vsock.
#
# Build:
#   docker buildx build --platform linux/amd64 \
#     --build-arg CRUCIBLE_INIT=../../target/x86_64-unknown-linux-musl/release/crucible-init \
#     -t crucible-smoke-rootfs .
#
# Then convert to ext4 with build-rootfs.sh.

FROM alpine:3.19

ARG CRUCIBLE_INIT=../../target/x86_64-unknown-linux-musl/release/crucible-init

# Minimal runtime packages only — the agent inside the smoke test is just sh.
RUN apk add --no-cache busybox-static

# Clear the default init (we provide our own).
RUN rm -f /sbin/init

COPY ${CRUCIBLE_INIT} /sbin/crucible-init
RUN chmod 755 /sbin/crucible-init

# /workspace is the mount point for the workspace ext4 block device (/dev/vdb).
RUN mkdir -p /workspace /run/crucible /proc /sys /dev /tmp

# Kernel expects /sbin/init or whatever init= points to.
RUN ln -sf /sbin/crucible-init /sbin/init
