# Build the smoke-test rootfs.
# build-rootfs.sh sets up a temp context with this file + the bunsen-init binary.

FROM alpine:3.19

RUN apk add --no-cache busybox-static git
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

# bunsen-init is copied into the build context by build-rootfs.sh
COPY bunsen-init /sbin/bunsen-init
RUN chmod 755 /sbin/bunsen-init && ln -sf /sbin/bunsen-init /sbin/init
