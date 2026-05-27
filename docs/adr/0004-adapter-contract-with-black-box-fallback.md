# Adapter contract with built-in adapters and black-box fallback

A Coding Agent is integrated through an Adapter — a Rust-side component that knows how to launch the agent, parse its output into structured events, and locate its native conversation history. Bunsen ships Adapters for Claude Code and aider in v1. Users can register their own. When no Adapter matches, bunsen falls back to black-box behaviour: events are opaque output lines and conversation history is "whatever's in the Workspace".

## Why not pure black-box

Without Adapters, every User Script would have to know each agent's stdout format, history file location, and model-flag conventions. Cross-agent comparison ("did Claude Code and aider produce different solutions to this prompt?") would be impossible without normalised events.

## Why not fully embedded per-agent

Hard-coding "this is the Claude Code path, this is the aider path" into the core makes adding a new agent a Rust-core change. The Adapter abstraction lets new agents land as plugins without touching the rest of the system.

## Consequences

The Adapter is also where Egress Policy defaults come from (each Adapter declares the endpoints its agent needs) and where Conversation History normalisation is implemented. Adapters break when agents change their output formats — that is a known maintenance cost.
