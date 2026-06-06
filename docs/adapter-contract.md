# Adapter Contract

An Adapter lets bunsen launch a Coding Agent and turn its output into a structured event stream. This document specifies what an Adapter author must implement.

See ADR-0004 (adapter contract with black-box fallback) and ADR-0007 (adapter runs host-side) and ADR-0008 (per-adapter OCI rootfs).

## Adapter identity

Each Adapter has a string name (e.g. `"claude-code"`, `"aider"`, `"codex"`, `"pi"`, `"black-box"`). The User Script sets `adapter` in the RunSpec JSON to select one.

## Invocation

The Adapter is invoked as a subprocess. `cmd` in the RunSpec is the full argv. For claude-code:

```json
{
  "adapter": "claude-code",
  "cmd": ["claude", "--output-format", "stream-json", "--prompt", "your task here"],
  "env": { "ANTHROPIC_API_KEY": "..." }
}
```

For codex:

```json
{
  "adapter": "codex",
  "cmd": ["codex", "exec", "--json", "--ephemeral", "your task here"],
  "env": { "OPENAI_API_KEY": "..." }
}
```

For pi (the adapter automatically injects `PI_CODING_AGENT_DIR=/workspace/.pi` into env):

```json
{
  "adapter": "pi",
  "cmd": ["pi", "--mode", "json", "--model", "anthropic/claude-sonnet-4-6", "-p", "your task here"],
  "env": { "ANTHROPIC_API_KEY": "..." }
}
```

The subprocess runs with:
- `cwd` set to the materialised Workspace path
- stdout/stderr piped to bunsen-core for parsing
- stdin closed (control commands arrive on bunsen-core's own stdin)

## Output parsing

An Adapter's parser reads the agent's stdout line by line and produces a sequence of typed events emitted to the transcript.

### Event types

| Event type | When emitted | Key payload fields |
|---|---|---|
| `turn_start` | Start of each model response | `turn_id` |
| `tool_call` | Each tool invocation in a model response | `tool_call_id`, `name`, `input` |
| `turn_end` | End of each model response | `turn_id`, `model?`, `stop_reason?` |
| `tool_result` | Each tool result returned to the model | `tool_call_id`, `content`, `is_error?` |
| `model_usage` | Per-turn or end-of-run usage summary | `model?`, `input_tokens`, `output_tokens`, `cache_read_tokens?`, `cache_write_tokens?`, `cost_usd?` |
| `output` | Agent text response, error messages, and unparseable lines | `stream` (`"agent"`, `"stdout"`, or `"stderr"`), `text` |

The `stream` field distinguishes the source of an `output` event:
- `"agent"` — text content from the model's response (parsed from the structured protocol)
- `"stderr"` — error messages surfaced by the adapter (e.g. Claude Code's `result.is_error` message) or raw stderr lines from the agent process
- `"stdout"` — unparseable stdout lines (e.g. banner text, progress output not recognised by the parser)

Stderr lines from the agent process always produce `output` events with `stream: "stderr"` regardless of adapter.

### Tool-call pairing

Every `tool_call` is followed by exactly one `tool_result` with the same `tool_call_id`. Orphans (no matching result when the Run ends mid-call) are tolerated.

For the `codex` adapter, all item types except `agent_message` and `reasoning` are surfaced as `tool_call`/`tool_result` pairs keyed by `item.id`. `agent_message` items become `output` events; `reasoning` items are dropped.

### model_usage cadence

Adapters may emit `model_usage` per-turn, once at end-of-run, or both — depending on what the agent's protocol exposes:

| Adapter | Cadence |
|---|---|
| `claude-code` | Once at end-of-run (from the `result` event) |
| `aider` | Per-turn (from the `Cost:` line that closes each turn) |
| `codex` | Per-turn (from `turn.completed.usage`); `reasoning_output_tokens` is folded into `output_tokens` |
| `pi` | Per-turn (from `turn_end.message.usage`) **and** once at end-of-run with accumulated session totals (from `agent_end`) |

### Black-box fallback

When `adapter` is `"black-box"` or unknown, all stdout/stderr lines become `output` events.

## Native history preservation

After the agent process exits, bunsen copies the agent's native history directory from inside the Workspace to `${run_dir}/agent-history/`.

| Adapter | Native history path (inside Workspace) |
|---|---|
| `claude-code` | `.claude/` (whole directory copied recursively) |
| `aider` | `.aider.chat.history.md`, `.aider.input.history`, `.aider.llm.history` (top-level files copied individually; `.aider.tags.cache.*` and other cache state are skipped) |
| `pi` | `.pi/agent/sessions/` (session tree only — `auth.json`/`settings.json` are deliberately excluded; the adapter injects `PI_CODING_AGENT_DIR=/workspace/.pi` so pi writes here instead of `~/.pi/agent/`) |
| `codex` | none — codex is invoked with `--ephemeral`; the normalised transcript is the sole record |

The copy is best-effort: if no source files exist, no error is raised and `agent-history/` is not created.

## Declared egress endpoints

Each Adapter declares the network endpoints it requires. These form the base Egress Policy for a Run (Slice 10 enforces them). Additional domains can be added per-Run by the User Script via the `egress-endpoints` field on the RunSpec.

The effective Egress Policy is the case-insensitive union of the adapter's declared endpoints and the user-script additions. Matching is exact-FQDN (no wildcards in v1) — a Run that needs `api.github.com` must list it explicitly.

| Adapter | Required endpoints |
|---|---|
| `claude-code` | `api.anthropic.com` |
| `aider` | derived from the `--model X` / `--model=X` value in `cmd`: `claude-*` / `anthropic/*` → `api.anthropic.com`; `gpt-*` / `o1*` / `o3*` / `openai/*` → `api.openai.com`; `gemini-*` → `generativelanguage.googleapis.com`; otherwise nothing declared (user script must supply the allowlist) |
| `codex` | `api.openai.com` (codex is OpenAI-only) |
| `pi` | derived from `cmd`: `--model <provider>/<model>` (primary) or `--provider <name>` (fallback); `anthropic` → `api.anthropic.com`; `openai` / `openai-codex` / `azure-openai-responses` → `api.openai.com`; `google` / `google-vertex` → `generativelanguage.googleapis.com`; local providers (`ollama`, etc.) or unrecognised → nothing declared |

Composition is implemented by `RunSpec::effective_egress_policy()` (see `bunsen-core/src/egress.rs`).

When a Run attempts a destination outside the policy, the enforcer emits an `egress_denied` event:

```json
{"type": "egress_denied", "destination": "github.com", "protocol": "https", "reason": "not in allowlist"}
```

`protocol` is one of `http`, `https`, `raw_tcp` (L3 nftables drop), or `dns`. The four enforcement paths attribute as follows:

| Origin | `protocol` | `destination` shape | Typical `reason` |
|---|---|---|---|
| L7 proxy `CONNECT` rejected (port 443) | `https` | `<host>` | `not in allowlist` |
| L7 proxy `CONNECT` rejected (port 80) | `http` | `<host>` | `not in allowlist` |
| L7 proxy `CONNECT` to any other port | `raw_tcp` | `<host>` | `not in allowlist` |
| L3 nftables drop on the TAP | `raw_tcp` | `<ip>:<port>` (or bare `<ip>` for ICMP) | `dropped at l3 (PROTO=TCP)` |
| DNS resolver REFUSED | `dns` | `<qname>` | `qtype A` / `qtype AAAA` / … |

Per ADR-0003 these events do *not* terminate the Run; the agent receives a normal network error and decides what to do. User Scripts that want hard-fail subscribe to `EgressDenied` and call `run.stop()`.

## OCI image

Each Adapter is paired with a digest-pinned OCI image that provides the agent runtime environment. The image is pulled lazily on first use (`oci_cache::resolve_rootfs`), flattened to an ext4 file, and cached at `${XDG_CACHE_HOME:-~/.cache}/bunsen/rootfs/<digest>.ext4`. One shared `vmlinux` (fetched by `kernel/fetch-vmlinux.sh`) boots every image — Adapters do not ship kernels.

### What the image must contain

- The agent binary and all of its runtime dependencies (interpreter, libraries, default config).
- `/sbin/bunsen-init` — the in-guest PID 1 built from `bunsen-init/`. The host wires it in as the kernel's `init=`. It mounts `/proc`, `/sys`, `/run`, `/tmp`, brings up `eth0` from the spec's `network` block, installs `/etc/resolv.conf` over a bind mount, then `execve`s the agent.
- `/etc/resolv.conf` must exist as a regular file (even empty). Bunsen bind-mounts a per-Run file over it; the rootfs is otherwise read-only, so the target inode must be pre-created. Alpine bases ship without it — see `adapters/_smoke-test/Dockerfile` for the placeholder pattern.
- A standard `$PATH` containing `sh`, `wget` or `curl`, and whatever the agent shells out to. (BusyBox is fine.)

### Build and publish

Adapter images are built from a small Dockerfile in `adapters/<name>/`. The `adapters/_smoke-test/` and `adapters/_alpine-test/` directories are working references — Alpine base, the musl-built `bunsen-init` copied into `/sbin/`, `apk add` for the agent's runtime, the `resolv.conf` placeholder.

Reference invocation:

```sh
cargo build --release -p bunsen-init --target x86_64-unknown-linux-musl
docker buildx build --platform linux/amd64 --tag ghcr.io/<org>/bunsen-adapter-<name>:dev adapters/<name>
docker push ghcr.io/<org>/bunsen-adapter-<name>:dev
# Take the digest reported by `docker push` and use it as the pinned ref.
```

The Adapter declaration **must** reference the image by digest, never by tag:

```text
ghcr.io/<org>/bunsen-adapter-<name>@sha256:<64 hex chars>
```

`oci_cache::OciImageRef::parse` enforces this — tags are rejected. Rebuild and re-pin the digest whenever the agent version or its dependencies change.

### Image resolution

When a sandbox boots, the guest rootfs is chosen by this precedence (see `RunSpec::resolve_oci_image` in `run_spec.rs`):

1. `--rootfs /path/to/custom.ext4` (host CLI) — wins outright when supplied.
2. The RunSpec `oci-image` field — resolved through the OCI cache.
3. The **Adapter's declared default image** — `adapter_default_image(&spec.adapter)` maps the adapter name to its `OCI_IMAGE` constant (e.g. `codex` boots the codex rootfs), so selecting an adapter that ships an image needs no explicit `oci-image`.
4. The base default `DEFAULT_ROOTFS_IMAGE` (CLI) — adapters that declare no image (black-box, claude-code, aider) fall through to the bare base; the Session path instead errors if nothing resolves.

This precedence governs *which* image boots, not *whether* a sandbox is used — sandbox intent is still driven by an explicit kernel/rootfs/`oci-image`. Local development typically uses `--rootfs` pointing at `target/<name>-rootfs.ext4` built by the adapter's `build-rootfs.sh`.

## Implementing a custom Adapter

1. Choose an adapter name (lowercase, hyphen-separated).
2. Implement a line parser in `bunsen-core/src/<name>_adapter.rs` following the `ClaudeCodeParser` or `AiderParser` pattern. Aider's is the closer template if your agent emits plain text rather than a structured stream. For agents with a structured JSON stream (like codex or pi), follow the `ClaudeCodeParser` pattern — each line is parsed as JSON and matched on a `type` field.
3. Add an `AdapterParser` variant in `supervisor.rs` and dispatch on the `spec.adapter` string at the top of `supervisor::run`.
4. Wire native-history preservation into `supervisor::copy_agent_history` — an explicit allowlist of paths is preferred over a glob.
5. Declare a `pub const EGRESS_ENDPOINTS: &[&str]`. If endpoints are model-derived, expose an `egress_endpoints_for_model(&str) -> &[&str]` helper and add the dispatch branch in `RunSpec::effective_egress_policy` (`run_spec.rs`).
6. Build and publish an OCI image as above; record the digest-pinned reference. Declare it as `pub const OCI_IMAGE: &str` in `<name>_adapter.rs` and add the dispatch branch in `adapter_default_image` (`run_spec.rs`) so the adapter resolves to its own rootfs without an explicit `oci-image`.
7. Capture an output fixture under `bunsen-core/src/testdata/<name>_fixture.txt` and assert the expected event sequence in unit tests.

See `bunsen-core/src/claude_code_adapter.rs` and `bunsen-core/src/aider_adapter.rs` for complete reference implementations.
