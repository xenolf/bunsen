# Rust CLI binary + Python wrapper, not PyO3

The Rust core is a CLI binary; the Python library spawns it as a subprocess and parses its NDJSON event stream into a Pythonic API. We rejected PyO3 / a native Python extension even though Python is the primary User Script language.

## Why subprocess won

- **The Rust core is intrinsically a long-lived supervisor** — it owns a Firecracker microVM, network plumbing, and the Coding Agent's stream. That's a process whether we want one or not. PyO3 would force all of it into the Python interpreter's process and entangle it with the GIL.
- **Crash isolation.** A Rust panic, a sandbox misbehaviour, or a User Script crash doesn't take the other side down.
- **Shell support comes free.** The same binary that the Python library subprocesses is what shell users invoke directly. No duplicated surface.
- **PyO3 + tokio + GIL + microVM lifecycle is too many moving parts** to share one address space.

## Consequences

Adapters live in the Rust core (so shell users get the same structured events Python users do). The Python library is a thin wrapper, not a parser of agent-specific output formats.

If we ever need finer-grained Python integration (zero-copy event objects, in-process control), we can add a PyO3 layer over the same Rust core later — the seam doesn't preclude it.
