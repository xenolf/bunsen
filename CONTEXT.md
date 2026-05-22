# Context

Glossary of domain terms used in crucible. Use these terms — and only these terms — when naming things in code, issues, ADRs, and conversation.

## Glossary

### Run

A single observable execution of a Coding Agent inside a Sandbox. A Run is long-lived: events stream out (model turns, tool calls, output) and the User Script can subscribe and react. Orchestration happens *between* Runs, not inside one — the User Script does not drive the agent's internal turns.

A Run terminates when the agent exits, the Sandbox is signalled to stop, or the Sandbox times out.

### User Script

The Python (or shell) program that orchestrates Runs. Selects agent, model, and prompt; configures Sandbox restrictions; launches Runs; consumes their event streams; decides what to do next. The User Script is the consumer of crucible — crucible's library/CLI is what it calls into.

### Sandbox

The isolated environment a Run executes inside. Provides filesystem isolation, restricted network egress, and bounded resource usage. The host kernel and User Script are outside the Sandbox.

### Sandbox Provider

The pluggable implementation of a Sandbox. Firecracker (microVM, strong isolation) is the v1 provider. Bubblewrap (namespaces, fast) and others may follow. Choice of provider is a Run-time configuration — the Run primitive is provider-agnostic.

### Coding Agent

A program that talks to a model and edits code — Claude Code, aider, codex, and so on. Crucible interacts with a Coding Agent through an Adapter; it does not embed agent logic itself.

### Adapter

The contract that lets crucible launch a Coding Agent and turn its output into a structured event stream. Adapters know an agent's invocation, its stdout/stderr format (or its event protocol if it has one), and the location and shape of its conversation history.

Crucible ships built-in Adapters for Claude Code and aider in v1. Users can register their own. When no Adapter matches, crucible falls back to black-box behaviour: events are opaque output lines and conversation history is "whatever the agent wrote into the workspace".

### Branching Strategy

How the Workspace is materialised at the start of a Run. The strategy decides what tree the agent sees, where it sits relative to the host repo, and (optionally) what git ref it's anchored to.

A Branching Strategy may set up a git worktree or branch as part of materialisation — e.g. "fresh clone of `main` into a new worktree on branch `crucible/run-<id>`". Crucible itself does not produce commits. If commits happen, they are made by the Coding Agent during the Run, not by crucible at Run end.

Fan-out (running N Runs in parallel from the same starting point) is *not* a Branching Strategy — it is a higher-level operation the User Script composes from multiple Runs.

### Workspace

The directory tree the Coding Agent operates on inside the Sandbox. Mounted at a fixed path inside the guest (`/workspace`). Materialised by the Branching Strategy at Run start; persisted on the host after the Run ends, accessible via the Run handle. Each Run has its own Workspace — Workspaces are not shared between Runs.

Crucible does not auto-commit, auto-archive, or otherwise mutate the Workspace at Run end. Whatever the agent left behind is what the User Script gets.

### Egress Policy

The set of network destinations a Run is permitted to reach. Enforced at two layers: an L3 default-deny on the Sandbox's network interface, and an L7 proxy (the only outbound route) that enforces a domain allowlist. Bypass at L7 is blocked by L3; convenience at L7 lets users say "allow github.com" instead of "allow these IP ranges".

By default, an Egress Policy permits only the endpoints the Run's Adapter declares as required (e.g. `api.anthropic.com` for the Claude Code Adapter). The User Script can extend the policy per-Run with additional allowed domains; deny-by-default applies to anything not declared.

### Conversation History

The structured record of a Run's interaction with the model — turns, tool calls, tool results, model usage. Produced by the Run's Adapter as it parses the Coding Agent's output. Two outputs from one pipeline:

- A **live event stream** the User Script subscribes to during the Run.
- A **persistent transcript** in crucible's normalised format, written to a known path, available after the Run ends.

The agent's native history files (e.g. Claude Code's `.claude/`) are preserved alongside the normalised transcript, untouched. The normalised format is what the User Script should rely on for cross-Adapter comparison; native files are an escape hatch.

### Secret

A credential the Coding Agent needs to do its work — `ANTHROPIC_API_KEY`, GitHub PAT, registry tokens, etc. The User Script declares Secrets explicitly per Run; crucible delivers them into the Sandbox as env vars on the agent process and redacts their values from the event stream and persistent transcript. Crucible never logs secrets and the User Script's library API never echoes their values back.

A future evolution (the Credential Broker) keeps Secrets entirely outside the Sandbox by injecting them at the L7 proxy. Not in v1.

### Resource Limits

The bounds crucible enforces on a Run's compute and storage footprint: wall-clock timeout, guest memory, guest vCPU count, Workspace disk size. Each has a default; each is overridable per-Run. Enforced by the Sandbox Provider (the kernel cgroups for memory/CPU, Firecracker config for VM sizing, the wall clock by crucible itself).

Token / cost budgets are *not* a Resource Limit — they are not enforceable at the Sandbox layer (only the Adapter sees model usage). Users who want a token budget subscribe to model-usage events in their User Script and call `stop` themselves.
