//! Egress Policy data model.
//!
//! Per ADR-0005 the effective Egress Policy of a Run is the union of:
//!   1. The Adapter's declared required endpoints (e.g. claude-code →
//!      `api.anthropic.com`).
//!   2. The User-Script-supplied additions (`spec.egress_endpoints`).
//!
//! Endpoints are FQDN allowlists (no wildcards in v1). The L7 proxy IP is
//! reserved by the enforcer and is never a valid policy entry — composition
//! here doesn't know about that, the enforcer enforces it at runtime.
//!
//! `Protocol` mirrors the four shapes of denial the enforcer surfaces:
//! L7 → `http`/`https`, L3 nftables drop → `raw_tcp`, DNS resolver → `dns`.

use serde::Serialize;
use serde_json::{json, Value};

/// The wire-level `type` discriminator emitted on the event stream.
pub const EVENT_TYPE: &str = "egress_denied";

/// Build the payload for an `egress_denied` event. The Run Supervisor passes
/// this to `Encoder::emit(EVENT_TYPE, payload)`. Per ADR-0003 it does not
/// terminate the Run; users wanting hard-fail subscribe and call `stop()`.
pub fn denied_payload(destination: &str, protocol: Protocol, reason: &str) -> Value {
    json!({
        "destination": destination,
        "protocol": protocol.as_str(),
        "reason": reason,
    })
}

/// Wire-level discriminator for an `egress_denied` event's `protocol` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Http,
    Https,
    RawTcp,
    Dns,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::RawTcp => "raw_tcp",
            Protocol::Dns => "dns",
        }
    }
}

/// Composed Egress Policy: adapter-declared endpoints unioned with
/// user-script additions, deduplicated, lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    allowed: Vec<String>,
}

impl EgressPolicy {
    /// Compose `adapter_declared` ∪ `user_added`.
    /// Hostnames are normalized to lowercase and deduplicated; order of first
    /// occurrence is preserved (adapter declarations first).
    pub fn compose(adapter_declared: &[&str], user_added: &[String]) -> Self {
        let mut seen = std::collections::HashSet::<String>::new();
        let mut allowed = Vec::new();
        for s in adapter_declared.iter().copied() {
            let norm = s.trim().to_ascii_lowercase();
            if !norm.is_empty() && seen.insert(norm.clone()) {
                allowed.push(norm);
            }
        }
        for s in user_added {
            let norm = s.trim().to_ascii_lowercase();
            if !norm.is_empty() && seen.insert(norm.clone()) {
                allowed.push(norm);
            }
        }
        EgressPolicy { allowed }
    }

    /// Exact-match decision for a destination hostname. v1 has no wildcards
    /// or suffix matching — a Run that wants `api.github.com` must list it.
    pub fn allows(&self, destination: &str) -> bool {
        let norm = destination.trim().to_ascii_lowercase();
        self.allowed.iter().any(|a| a == &norm)
    }

    pub fn as_slice(&self) -> &[String] {
        &self.allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_serializes_snake_case() {
        let v = serde_json::to_value(Protocol::RawTcp).unwrap();
        assert_eq!(v, serde_json::json!("raw_tcp"));
        let v = serde_json::to_value(Protocol::Https).unwrap();
        assert_eq!(v, serde_json::json!("https"));
        let v = serde_json::to_value(Protocol::Dns).unwrap();
        assert_eq!(v, serde_json::json!("dns"));
        let v = serde_json::to_value(Protocol::Http).unwrap();
        assert_eq!(v, serde_json::json!("http"));
    }

    #[test]
    fn compose_unions_adapter_and_user() {
        let p = EgressPolicy::compose(
            &["api.anthropic.com"],
            &vec!["github.com".to_string()],
        );
        assert!(p.allows("api.anthropic.com"));
        assert!(p.allows("github.com"));
        assert!(!p.allows("evil.example"));
    }

    #[test]
    fn compose_dedupes_case_insensitively() {
        let p = EgressPolicy::compose(
            &["API.Anthropic.COM"],
            &vec!["api.anthropic.com".to_string(), " api.anthropic.com ".to_string()],
        );
        assert_eq!(p.as_slice().len(), 1);
        assert_eq!(p.as_slice()[0], "api.anthropic.com");
    }

    #[test]
    fn compose_skips_empty_entries() {
        let p = EgressPolicy::compose(
            &[""],
            &vec!["".to_string(), "  ".to_string(), "github.com".to_string()],
        );
        assert_eq!(p.as_slice(), &["github.com".to_string()]);
    }

    #[test]
    fn allows_is_exact_no_suffix_matching() {
        let p = EgressPolicy::compose(&["github.com"], &vec![]);
        assert!(p.allows("github.com"));
        // Subdomain not implicitly allowed.
        assert!(!p.allows("api.github.com"));
        // Prefix not allowed either.
        assert!(!p.allows("notgithub.com"));
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = EgressPolicy::compose(&[], &vec![]);
        assert!(!p.allows("api.anthropic.com"));
        assert!(p.as_slice().is_empty());
    }

    #[test]
    fn denied_payload_has_required_fields() {
        let p = denied_payload("github.com", Protocol::Https, "not in allowlist");
        assert_eq!(p["destination"], "github.com");
        assert_eq!(p["protocol"], "https");
        assert_eq!(p["reason"], "not in allowlist");
    }

    #[test]
    fn denied_payload_protocol_variants_serialize_correctly() {
        assert_eq!(denied_payload("x", Protocol::Http, "r")["protocol"], "http");
        assert_eq!(denied_payload("x", Protocol::RawTcp, "r")["protocol"], "raw_tcp");
        assert_eq!(denied_payload("x", Protocol::Dns, "r")["protocol"], "dns");
    }

    #[test]
    fn event_type_is_egress_denied() {
        assert_eq!(EVENT_TYPE, "egress_denied");
    }

    #[test]
    fn adapter_endpoints_first_then_user() {
        let p = EgressPolicy::compose(
            &["a.example", "b.example"],
            &vec!["c.example".to_string(), "a.example".to_string()],
        );
        assert_eq!(
            p.as_slice(),
            &["a.example".to_string(), "b.example".to_string(), "c.example".to_string()]
        );
    }
}
