# Secrets passed as declared env vars, protected by redaction

Secrets are declared explicitly per Run by the User Script and delivered into the Sandbox as env vars on the Coding Agent process. Crucible redacts known Secret values from the live event stream and the persistent transcript by byte-pattern replacement. The Sandbox itself sees the real Secret value — only the User Script's view is redacted.

## Why not the Credential Broker (yet)

The strong-isolation answer is to keep Secrets entirely outside the Sandbox: the L7 proxy holds them and rewrites outbound `Authorization` headers, so the agent never has the real key to leak. We did not ship this in v1 because it requires per-endpoint logic (which header pattern means "auth", how OAuth flows interact with the proxy, etc) that is meaningful to get right. The Credential Broker is on the roadmap as a follow-up evolution of the L7 proxy from ADR-0005.

## Why redaction is enough for v1

Redaction catches the common leak modes: agent prints env to stderr on crash, agent writes config file with the key into the Workspace, agent's output stream contains the key verbatim. It does *not* catch base64-encoded leaks, reversed strings, or other obfuscation — those are out of scope until the Credential Broker exists.

## Consequences

The User Script API never echoes Secret values back. Crucible never logs Secret values at any log level. Adapters that legitimately need to see a Secret value (e.g. to build an `Authorization` header) get it through a typed parameter that bypasses redaction at construction time, not by reading it back from the event stream.
