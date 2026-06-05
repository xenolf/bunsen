# Build the pi adapter rootfs.
#
# Extends the bunsen base image with Node.js and the pi coding agent.
# The base image already provides: Alpine, git, bunsen-init as PID 1,
# /workspace and /run/bunsen directories, and the /etc/resolv.conf placeholder.
#
# build-rootfs.sh pushes this to ghcr.io/xenolf/bunsen/bunsen-adapter-pi.

FROM ghcr.io/xenolf/bunsen/bunsen-base@sha256:4b8bd93732bae93a0448bd019583a47b249db6197cd1331d1ddaaa0b16b19b36

RUN apk add --no-cache nodejs npm
RUN npm install -g @mariozechner/pi-coding-agent
