# Adapter Contract

An Adapter lets crucible launch a Coding Agent and turn its output into a structured event stream. This document specifies what an Adapter author must implement.

See ADR-0004 (adapter contract with black-box fallback) and ADR-0007 (adapter runs host-side) and ADR-0008 (per-adapter OCI rootfs).

## Adapter identity

Each Adapter has a string name (e.g. `"claude-code"`, `"aider"`, `"black-box"`). The User Script sets `adapter` in the RunSpec JSON to select one.

## Invocation

The Adapter is invoked as a subprocess. `cmd` in the RunSpec is the full argv. For claude-code:

```json
{
  "adapter": "claude-code",
  "cmd": ["claude", "--output-format", "stream-json", "--prompt", "your task here"],
  "env": { "ANTHROPIC_API_KEY": "..." }
}
```

The subprocess runs with:
- `cwd` set to the materialised Workspace path
- stdout/stderr piped to crucible-core for parsing
- stdin closed (control commands arrive on crucible-core's own stdin)

## Output parsing

An Adapter's parser reads the agent's stdout line by line and produces a sequence of typed events emitted to the transcript.

### Event types

| Event type | When emitted | Key payload fields |
|---|---|---|
| `turn_start` | Start of each model response | `turn_id` |
| `tool_call` | Each tool invocation in a model response | `tool_call_id`, `name`, `input` |
| `turn_end` | End of each model response | `turn_id`, `model?`, `stop_reason?` |
| `tool_result` | Each tool result returned to the model | `tool_call_id`, `content`, `is_error?` |
| `model_usage` | End-of-run usage summary | `model?`, `input_tokens`, `output_tokens`, `cache_read_tokens?`, `cache_write_tokens?`, `cost_usd?` |
| `output` | Unparseable or non-structured lines | `stream` (`"stdout"` or `"stderr"`), `text` |

Stderr lines always produce `output` events regardless of adapter.

### Tool-call pairing

Every `tool_call` is followed by exactly one `tool_result` with the same `tool_call_id`. Orphans (no matching result when the Run ends mid-call) are tolerated.

### Black-box fallback

When `adapter` is `"black-box"` or unknown, all stdout/stderr lines become `output` events.

## Native history preservation

After the agent process exits, crucible copies the agent's native history directory from inside the Workspace to `${run_dir}/agent-history/`.

| Adapter | Native history path (inside Workspace) |
|---|---|
| `claude-code` | `.claude/` |
| `aider` | `.aider.chat.history.md` (and similar) |

The copy is best-effort: if the directory doesn't exist, no error is raised.

## Declared egress endpoints

Each Adapter declares the network endpoints it requires. These form the base Egress Policy for a Run (Slice 10 enforces them). Additional domains can be added per-Run by the User Script.

| Adapter | Required endpoints |
|---|---|
| `claude-code` | `api.anthropic.com` |
| `aider` | depends on configured model |

## OCI image

Each Adapter declares a digest-pinned OCI image reference that provides the agent runtime environment. The image is pulled from a registry (e.g. GHCR) and cached locally as an ext4 rootfs.

The image must:
- Contain the agent binary and all runtime dependencies
- Be published to GHCR as `ghcr.io/org/crucible-adapter-<name>@sha256:<hex64>`
- Be rebuilt and the digest updated in the Adapter declaration when dependencies change

## Implementing a custom Adapter

1. Choose an adapter name (lowercase, hyphen-separated).
2. Implement a line parser in `crucible-core/src/<name>_adapter.rs` following the `ClaudeCodeParser` pattern.
3. Add a dispatch branch in `supervisor.rs` for the adapter name.
4. Declare `EGRESS_ENDPOINTS` as a `&[&str]` constant.
5. Build and publish an OCI image; record the digest-pinned reference.
6. Add captured output fixtures and tests under `src/testdata/`.

See `crucible-core/src/claude_code_adapter.rs` for a complete reference implementation.
