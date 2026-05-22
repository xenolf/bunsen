# Dual-layer egress: L3 default-deny + L7 domain proxy

Network egress from a Sandbox is enforced at two layers: an L3 (nftables) default-deny on the Sandbox's network interface that allows only outbound traffic to the L7 proxy, and an L7 proxy that enforces a domain allowlist. The default Egress Policy permits only the endpoints the Run's Adapter declares as required.

## Why both layers

- **L3 alone** is unbypassable but coarse — users have to express policy as IP ranges, which is hostile to "allow github.com".
- **L7 alone** lets users say "allow github.com" but a hostile agent can ignore the proxy and connect to a raw IP. Useless against the threat model that motivated Firecracker (ADR-0001).
- **L3 + L7 together** gives you the unbypassable boundary *and* the domain-level convenience. Cost: a proxy in the data path and per-Adapter endpoint declarations. Acceptable.

## Why default-deny driven by Adapter declarations

A pure default-deny default would surprise first-time users (their agent can't reach `api.anthropic.com`). A pure default-allow default would be a footgun. Tying defaults to Adapter declarations means the Run "just works" for the agent's actual needs and the User Script extends the allowlist for its specific use case.

## Consequences

The L7 proxy must not itself be in the allowlist as a destination — otherwise an agent could tunnel to arbitrary domains via the proxy. v1 ships nftables for L3 and a small purpose-built proxy for L7; choice of proxy implementation is not architectural and can change.

A future Credential Broker (see ADR-0006) lives in the L7 proxy.
