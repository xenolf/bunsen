# A Run is observed, not driven turn-by-turn

A Run streams events out and accepts coarse control signals (`stop`, `kill`, `pause`, `resume`) but does *not* allow the User Script to inject prompts, intercept tool calls, or otherwise drive the Coding Agent's internal turns. Orchestration happens *between* Runs.

## Why

- The "branch the conversation and reprompt" use case is expressed as a *new* Run with a Branching Strategy that forks from the prior Run's state — not as mutation of a live Run.
- Driving an agent turn-by-turn requires the agent to expose pause/intercept hooks. Most CLI agents do not. Coupling bunsen's primitive to that capability would make the supported-agent set tiny and brittle.
- Keeping the Run primitive narrow means Adapters need to do less; black-box fallback is meaningful.

## Considered Options

- **Single-shot, terminal Run** (`subprocess.run`-style) — too thin for a Rust core to add value.
- **Streamed observable Run** (chosen) — events stream, control signals coarse, agent runs unsupervised internally.
- **Interactive interruptible Run** — User Script can veto tool calls, inject prompts, etc. Couples bunsen to specific agents' internals; rejected.

## Consequences

There is no `inject` control signal in v1 and no plan to add one without a strong agent-protocol story. Egress Policy violations produce a `EgressDenied` event but do not terminate the Run by default — the agent sees a normal network error and decides what to do. Users who want hard-fail subscribe to the event and call `stop` themselves.
