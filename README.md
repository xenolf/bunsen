# crucible

A Python library for orchestrating Coding Agent **Runs** inside Firecracker microVMs. Crucible launches an agent (Claude Code, aider, …) inside a sandbox, streams its output as a normalised event stream, and enforces a default-deny network egress policy.

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
git clone https://github.com/<you>/crucible.git
cd crucible

# 1. Build the host binary and the in-guest init
cargo build --release
cargo build --release -p crucible-init --target x86_64-unknown-linux-musl

# 2. Fetch the pinned Firecracker guest kernel (~30 MB, cached at
#    ${XDG_CACHE_HOME:-~/.cache}/crucible/kernel/vmlinux).
./kernel/fetch-vmlinux.sh

# 3. Install the Python library (editable install from repo root; maturin backend)
python -m venv .venv && source .venv/bin/activate
pip install -e .

# 4. (Optional) build the smoke-test rootfs so you can run end-to-end
#    without pulling an OCI image.
./adapters/_smoke-test/build-rootfs.sh
```

After step 4, the rootfs lives at `target/smoke-rootfs.ext4`.

### `crucible-core` discovery

The Python library finds the `crucible-core` host binary in this order:

1. `CRUCIBLE_CORE_BIN` environment variable (a full argv string, space-separated)
2. `crucible/bin/crucible-core` adjacent to the installed `crucible/` package (the published-wheel layout)
3. `target/release/crucible-core` walking up from the installed `crucible/` package (cargo dev build)
4. `crucible-core` on `$PATH`

If none match, `crucible.run(...)` raises `FileNotFoundError` with all four options.

## First Run

```python
import asyncio, crucible

async def main():
    spec = {
        "adapter": "black-box",
        "cmd": ["sh", "-c", "echo hello from inside the sandbox"],
        "workspace-disk-mb": 128,
    }
    async with crucible.run(spec) as r:
        async for event in r.events:
            print(event)

asyncio.run(main())
```

To run it under a real Firecracker sandbox, point `CRUCIBLE_CORE_BIN` at the binary plus the kernel/rootfs flags:

```sh
export CRUCIBLE_CORE_BIN="$(pwd)/target/release/crucible-core \
    --kernel ${XDG_CACHE_HOME:-$HOME/.cache}/crucible/kernel/vmlinux \
    --rootfs $(pwd)/target/smoke-rootfs.ext4"
python examples/hello.py
```

On a stock Ubuntu host with UFW enabled, also pass `manage_firewall=True` so crucible can install a per-TAP allow rule for the lifetime of the Run:

```python
async with crucible.run(spec, manage_firewall=True) as r:
    ...
```

A Run's outputs land under `${XDG_RUNTIME_DIR:-/tmp}/crucible/runs/<run_id>/`: the normalised transcript (`transcript.jsonl`), the materialised workspace (`workspace/`), and any agent-native history files (`agent-history/`).

## Running the tests

```sh
cargo test                              # host-side Rust + crucible-init unit tests
cargo check --target x86_64-unknown-linux-musl -p crucible-core   # cross-check
pip install -e '.[dev]' && pytest -q python/tests                  # Python unit tests

# Acceptance suite (Linux + KVM required)
CRUCIBLE_KERNEL=~/.cache/crucible/kernel/vmlinux \
CRUCIBLE_ROOTFS=$(pwd)/target/smoke-rootfs.ext4 \
pytest -v python/tests/test_egress_acceptance.py
```

## Documentation

- `CONTEXT.md` — domain glossary
- `docs/adr/` — architectural decisions (ADR-0001…0008)
- `docs/adapter-contract.md` — how to implement a new Adapter
- `docs/macos.md` — macOS / remote Linux setup
