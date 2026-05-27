# Context

Glossary of domain terms used in bunsen. Use these terms — and only these terms — when naming things in code, issues, ADRs, and conversation.

## Glossary

### Run

A single observable execution of a Coding Agent inside a Sandbox. A Run is long-lived: events stream out (model turns, tool calls, output) and the User Script can subscribe and react. Orchestration happens *between* Runs, not inside one — the User Script does not drive the agent's internal turns.

A Run terminates when the agent exits, the Sandbox is signalled to stop, or the Sandbox times out.

### User Script

The Python (or shell) program that orchestrates Runs. Selects agent, model, and prompt; configures Sandbox restrictions; launches Runs; consumes their event streams; decides what to do next. The User Script is the consumer of bunsen — bunsen's library/CLI is what it calls into.

### Sandbox

The isolated environment a Run executes inside. Provides filesystem isolation, restricted network egress, and bounded resource usage. The host kernel and User Script are outside the Sandbox.

### Sandbox Provider

The pluggable implementation of a Sandbox. Firecracker (microVM, strong isolation) is the v1 provider. Bubblewrap (namespaces, fast) and others may follow. Choice of provider is a Run-time configuration — the Run primitive is provider-agnostic.

### Coding Agent

A program that talks to a model and edits code — Claude Code, aider, codex, and so on. Bunsen interacts with a Coding Agent through an Adapter; it does not embed agent logic itself.

### Adapter

The contract that lets bunsen launch a Coding Agent and turn its output into a structured event stream. Adapters know an agent's invocation, its stdout/stderr format (or its event protocol if it has one), and the location and shape of its conversation history.

Bunsen ships built-in Adapters for Claude Code and aider in v1. Users can register their own. When no Adapter matches, bunsen falls back to black-box behaviour: events are opaque output lines and conversation history is "whatever the agent wrote into the workspace".

### Branching Strategy

How the Workspace is materialised at the start of a Run. The strategy decides what refs the agent sees, what HEAD points to, and (for reconciliation Runs) what additional refs are imported so the agent can merge them.

A Run's materialisation source is the Session's [[branch-pool]], not the host repo directly — even the first Run in a Session reads from the Pool, which mirrors the relevant host refs at Session open. This keeps the materialiser source-uniform and means the host repo is untouched during the Session.

Bunsen itself does not produce commits. If commits happen, they are made by the Coding Agent during the Run, not by bunsen at Run end.

Fan-out (running N Runs in parallel from the same starting point) is *not* a Branching Strategy — it is a higher-level operation the User Script composes from multiple Runs.

### Workspace

The git repository the Coding Agent operates on inside the Sandbox. Mounted at a fixed path inside the guest (`/workspace`). The agent edits the working tree and commits its work. Materialised by the Branching Strategy at Run start; each Run has its own Workspace — Workspaces are not shared between Runs.

The Workspace exists only inside the Sandbox. There is no host-side workspace directory after Run end — the agent's output crystallises into refs in the [[branch-pool]] (via `git fetch` from the guest's .git) and the ext4 image is discarded. Users who want to inspect files create a worktree from a Pool ref on demand.

Git commits are the only data channel between the Workspace and the host. Untracked or uncommitted files in the Workspace do not survive Run end — if the agent didn't commit it, it isn't part of the Run's output. The agent's native history files (see [[conversation-history]]) are the one exception: they are extracted via a separate, narrow file-copy path because conversation history isn't meaningfully committable.

Bunsen does not auto-commit on the agent's behalf. If commits exist, the agent made them.

### Session

A bounded orchestration context over a single host repo. A Session has an explicit lifecycle: **open** (relevant host-repo refs are mirrored into the Session's [[branch-pool]]), **runs happen** (one or many Runs, possibly in parallel, sharing branches through the Pool), **close** (chosen Pool refs are synced back to the host repo, audit state is retained or discarded).

A Session is persistent and machine-identified: it lives on disk across User Script processes, machine restarts, and the gap between orchestration steps. The User Script may attach to an existing Session from any later invocation. The User Script may also attach free-form labels for human-friendly listing — labels are metadata on top of the canonical Session ID, never the identity itself.

The host repo is not touched between open and close. All cross-Run branch sharing happens inside the Session via its Pool. Multiple Sessions can target the same host repo concurrently — each has its own Pool and does not see the others' refs.

### Branch Pool

The git store owned by a [[session]] where the refs produced by that Session's Runs live between the Run that creates a branch and the Run (or close-time sync) that consumes it. The Pool is bunsen-managed, separate from the user's host repo: agent commits land here via `git fetch` from the guest, downstream Runs use the Pool as their clone source, and the user's host repo is only touched at Session close.

The Pool decouples "the agent made commits" from "those commits are in my repo". A Session's Pool exists for the lifetime of that Session and is the storage substrate that makes cross-Run branch sharing possible without polluting the host repo with intermediate work.

### Egress Policy

The set of network destinations a Run is permitted to reach. Enforced at two layers: an L3 default-deny on the Sandbox's network interface, and an L7 proxy (the only outbound route) that enforces a domain allowlist. Bypass at L7 is blocked by L3; convenience at L7 lets users say "allow github.com" instead of "allow these IP ranges".

By default, an Egress Policy permits only the endpoints the Run's Adapter declares as required (e.g. `api.anthropic.com` for the Claude Code Adapter). The User Script can extend the policy per-Run with additional allowed domains; deny-by-default applies to anything not declared.

### Conversation History

The structured record of a Run's interaction with the model — turns, tool calls, tool results, model usage. Produced by the Run's Adapter as it parses the Coding Agent's output. Two outputs from one pipeline:

- A **live event stream** the User Script subscribes to during the Run.
- A **persistent transcript** in bunsen's normalised format, written to a known path, available after the Run ends.

The agent's native history files (e.g. Claude Code's `.claude/`) are preserved alongside the normalised transcript, untouched. The normalised format is what the User Script should rely on for cross-Adapter comparison; native files are an escape hatch.

### Secret

A credential the Coding Agent needs to do its work — `ANTHROPIC_API_KEY`, GitHub PAT, registry tokens, etc. The User Script declares Secrets explicitly per Run; bunsen delivers them into the Sandbox as env vars on the agent process and redacts their values from the event stream and persistent transcript. Bunsen never logs secrets and the User Script's library API never echoes their values back.

A future evolution (the Credential Broker) keeps Secrets entirely outside the Sandbox by injecting them at the L7 proxy. Not in v1.

### Resource Limits

The bounds bunsen enforces on a Run's compute and storage footprint: wall-clock timeout, guest memory, guest vCPU count, Workspace disk size. Each has a default; each is overridable per-Run. Enforced by the Sandbox Provider (the kernel cgroups for memory/CPU, Firecracker config for VM sizing, the wall clock by bunsen itself).

Token / cost budgets are *not* a Resource Limit — they are not enforceable at the Sandbox layer (only the Adapter sees model usage). Users who want a token budget subscribe to model-usage events in their User Script and call `stop` themselves.
