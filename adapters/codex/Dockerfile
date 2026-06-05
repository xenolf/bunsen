# Build the codex adapter rootfs.
#
# Extends the canonical bunsen-base with Node.js, npm, and the OpenAI Codex CLI.
# bunsen-base already provides: Alpine, git, workspace directories,
# /etc/resolv.conf placeholder, and /sbin/bunsen-init as PID 1.
#
# Rebuild and re-pin OCI_IMAGE in bunsen-core/src/codex_adapter.rs whenever
# the agent version or its dependencies change.

FROM ghcr.io/xenolf/bunsen/bunsen-base@sha256:4b8bd93732bae93a0448bd019583a47b249db6197cd1331d1ddaaa0b16b19b36

RUN apk add --no-cache nodejs npm
RUN npm install -g @openai/codex
