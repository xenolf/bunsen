# Build the alpine-test rootfs.
#
# Variant of adapters/_smoke-test/Dockerfile that uses Alpine's stock
# binaries (apk-managed git, BusyBox from the base image) instead of the
# bundled busybox-static blob. Exercises the egress enforcer against a
# closer approximation of a real OCI agent image: dynamically-linked
# binaries, full /etc layout, and an apk-installed `git` for AC7.
#
# build-rootfs.sh sets up a temp context with this file + the crucible-init binary.

FROM alpine:3.19

# Alpine ships BusyBox at /bin/busybox with wget / nslookup / nc applets;
# `git` is the only extra binary the acceptance suite needs.
RUN apk add --no-cache git
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
