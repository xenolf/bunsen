# Adapter runs host-side; guest-side init is dumb

The Adapter runs in the `bunsen-core` host process, parsing raw stdout/stderr bytes that arrive over vsock from the guest. The guest-side init binary is a small static Rust binary that does PID 1 work, exec's the agent, and pipes raw bytes up the vsock — it has no Adapter-specific knowledge.

## Why

- **Iteration speed.** Adapter parsing logic changes when agents change their output formats. If the Adapter lives in the guest rootfs, every change to claude-code's output format means rebuilding and redistributing the rootfs image. Host-side Adapters mean the rootfs is essentially frozen and Adapters change at Rust-build cadence.
- **Testing.** Adapters can be tested with captured fixture bytes and zero VM machinery — exactly the testing strategy already in the PRD ("captured samples live as test fixtures so the tests remain stable when the agent's runtime is unavailable").
- **Crash isolation.** An Adapter parsing bug shouldn't be able to wedge the guest VM. Host-side Adapters can panic or exit without taking the agent down with them; the supervisor just records the failure and moves on.
- **Rootfs simplicity.** Per-Adapter OCI images (ADR-0008) need to ship the agent binary and its runtime. Adding the Adapter Rust binary on top blurs the distribution boundary — the rootfs becomes "agent stuff + bunsen stuff" instead of "agent stuff and a tiny init".

## Considered Options

- **Adapter in guest.** Each Adapter rootfs ships the Adapter Rust code; guest emits pre-typed events directly over vsock. Rejected because of the iteration, testing, crash-isolation, and distribution costs above.
- **Hybrid (event extraction in guest, post-processing on host).** Some Adapter logic in guest, some on host. Worst of both worlds — same rootfs-versioning headache, plus a split parsing surface that's harder to reason about.

## Consequences

- The vsock surface carries raw bytes, not typed events. Slightly more bandwidth than typed events would, but negligible at the throughput coding agents produce.
- The Run Supervisor must fuse guest-derived events (parsed from raw bytes by the Adapter) with host-derived events (`EgressDenied` from the L7 proxy) into a coherent, host-timestamped timeline.
- The guest init binary stays tiny (~200 lines) and is built/distributed once per bunsen-core release, decoupled from Adapter changes.
- An Adapter that wants to read native agent history files (e.g., Claude Code's `.claude/`) does so by reading them out of the persisted Workspace at Run end, not by reaching into the guest mid-run.
