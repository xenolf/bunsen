# Build the smoke-test rootfs.
# build-rootfs.sh sets up a temp context with this file + the crucible-init binary.

FROM alpine:3.19

RUN apk add --no-cache busybox-static
RUN rm -f /sbin/init
RUN mkdir -p /workspace /run/crucible /proc /sys /dev /tmp

# crucible-init is copied into the build context by build-rootfs.sh
COPY crucible-init /sbin/crucible-init
RUN chmod 755 /sbin/crucible-init && ln -sf /sbin/crucible-init /sbin/init
