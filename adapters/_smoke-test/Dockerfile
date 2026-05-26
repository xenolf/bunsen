# Build the smoke-test rootfs.
# build-rootfs.sh sets up a temp context with this file + the crucible-init binary.

FROM alpine:3.19

RUN apk add --no-cache busybox-static git
RUN rm -f /sbin/init
RUN mkdir -p /workspace /run/crucible /proc /sys /dev /tmp
# Bind-mount target for the resolv.conf installed by crucible-init at boot.
# Alpine's minimal base doesn't ship /etc/resolv.conf because Docker normally
# writes it at container start; we boot under Firecracker with a read-only
# rootfs, so the file must exist up-front for `mount --bind` to succeed.
# Docker bind-mounts the host's /etc/resolv.conf during every `RUN` step,
# making it impossible to create the file via `RUN`. `COPY` operates on the
# layer's filesystem directly, bypassing the bind-mount.
COPY <<EOF /etc/resolv.conf
# placeholder for crucible-init bind-mount
EOF

# crucible-init is copied into the build context by build-rootfs.sh
COPY crucible-init /sbin/crucible-init
RUN chmod 755 /sbin/crucible-init && ln -sf /sbin/crucible-init /sbin/init
