# bunsen

A Python library for orchestrating Coding Agent **Runs** inside Firecracker microVMs. Bunsen launches an agent (Claude Code, aider, …) inside a sandbox, streams its output as a normalised event stream, and enforces a default-deny network egress policy.

See `CONTEXT.md` for the domain glossary and `docs/adr/` for the architectural decisions behind v1.

## Status

v1 runs on **Linux + KVM**. Apple Silicon developers should SSH to a remote Linux box — see `docs/macos.md` for setup notes.

## Requirements

- **OS:** Linux x86_64 with `/dev/kvm` accessible to the running user
- **Tools:** `firecracker` (≥ v1.15), `nftables`, `iptables`, `systemd-journald` (for `journalctl -k`), `docker` (for building rootfs images), `curl` or `wget`
- **Toolchain:** Rust ≥ 1.74 with the `x86_64-unknown-linux-musl` target installed (`rustup target add x86_64-unknown-linux-musl`)
- **Python:** 3.11+

A Hetzner CCX13 (or any cloud instance that exposes nested virtualization) is enough for a Run.

## Install

```sh
git clone https://github.com/<you>/bunsen.git
cd bunsen

# 1. Build the host binary and the in-guest init
cargo build --release
cargo build --release -p bunsen-init --target x86_64-unknown-linux-musl

# 2. Fetch the pinned Firecracker guest kernel (~30 MB, cached at
#    ${XDG_CACHE_HOME:-~/.cache}/bunsen/kernel/vmlinux).
./kernel/fetch-vmlinux.sh

# 3. Install the Python library (editable install from repo root; maturin backend)
python -m venv .venv && source .venv/bin/activate
pip install -e .

# 4. (Optional) build the smoke-test rootfs so you can run end-to-end
#    without pulling an OCI image.
./adapters/_smoke-test/build-rootfs.sh
```

After step 4, the rootfs lives at `target/smoke-rootfs.ext4`.

### `bunsen-core` discovery

The Python library finds the `bunsen-core` host binary in this order:

1. `BUNSEN_CORE_BIN` environment variable (a full argv string, space-separated)
2. `bunsen/bin/bunsen-core` adjacent to the installed `bunsen/` package (the published-wheel layout)
3. `target/release/bunsen-core` walking up from the installed `bunsen/` package (cargo dev build)
4. `bunsen-core` on `$PATH`

If none match, `bunsen.run(...)` raises `FileNotFoundError` with all four options.

## First Run

```python
import asyncio, bunsen

async def main():
    spec = {
        "adapter": "black-box",
        "cmd": ["sh", "-c", "echo hello from inside the sandbox"],
        "workspace-disk-mb": 128,
    }
    async with bunsen.run(spec) as r:
        async for event in r.events:
            print(event)

asyncio.run(main())
```

To run it under a real Firecracker sandbox, point `BUNSEN_CORE_BIN` at the binary plus the kernel/rootfs flags:

```sh
export BUNSEN_CORE_BIN="$(pwd)/target/release/bunsen-core \
    --kernel ${XDG_CACHE_HOME:-$HOME/.cache}/bunsen/kernel/vmlinux \
    --rootfs $(pwd)/target/smoke-rootfs.ext4"
python examples/hello.py
```

On a stock Ubuntu host with UFW enabled, also pass `manage_firewall=True` so bunsen can install a per-TAP allow rule for the lifetime of the Run:

```python
async with bunsen.run(spec, manage_firewall=True) as r:
    ...
```

A Run's outputs land under `${XDG_RUNTIME_DIR:-/tmp}/bunsen/runs/<run_id>/`: the normalised transcript (`transcript.jsonl`), the materialised workspace (`workspace/`), and any agent-native history files (`agent-history/`).

## Running the tests

```sh
cargo test                              # host-side Rust + bunsen-init unit tests
cargo check --target x86_64-unknown-linux-musl -p bunsen-core   # cross-check
pip install -e '.[dev]' && pytest -q python/tests                  # Python unit tests

# Acceptance suite (Linux + KVM required)
BUNSEN_KERNEL=~/.cache/bunsen/kernel/vmlinux \
BUNSEN_ROOTFS=$(pwd)/target/smoke-rootfs.ext4 \
pytest -v python/tests/test_egress_acceptance.py
```

## Inspecting a Pool ref

After a Session runs an agent, the agent's commits live in the Session's
Pool — a bare git repo at `~/.local/share/bunsen/sessions/<id>/pool/`.
There is no host-side workspace tree under `runs/<run-id>/` to browse
(see ADR-0010). To inspect files at a Pool ref (an audit ref like
`runs/<run-id>`, or the user-named `output_branch`):

```bash
SESSION_DIR=~/.local/share/bunsen/sessions/<session-id>
git -C "$SESSION_DIR/pool" worktree add /tmp/inspect-<run-id> runs/<run-id>
# ...inspect files under /tmp/inspect-<run-id>...
git -C "$SESSION_DIR/pool" worktree remove /tmp/inspect-<run-id>
```

A `bunsen inspect <run-id>` ergonomic wrapper is intentionally not built
— see the PRD's "Out of Scope" section.

## Documentation

- `CONTEXT.md` — domain glossary
- `docs/adr/` — architectural decisions (ADR-0001…0011)
- `docs/adapter-contract.md` — how to implement a new Adapter
- `docs/macos.md` — macOS / remote Linux setup
