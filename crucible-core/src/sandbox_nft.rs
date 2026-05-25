//! Per-Run L3 nftables ruleset (ADR-0005).
//!
//! The Sandbox's TAP is the only path between the guest and the host kernel.
//! v1 layers a default-deny nftables filter on traffic coming *in* via that
//! TAP: only TCP to the L7 proxy address is allowed; everything else is
//! dropped and logged with a per-Run prefix. A future slice consumes those
//! drop logs and emits `egress_denied(protocol=raw_tcp)` events.
//!
//! This module is platform-independent and ships the ruleset string + a
//! sanitized table name. The Linux-only `nft -f -` shell-out and cleanup live
//! in [`crate::firecracker`] alongside the TAP lifecycle.

use std::net::Ipv4Addr;

/// Derive a deterministic, nft-safe table name from a Run id.
///
/// nftables identifiers may contain `[A-Za-z0-9_-]`; non-conforming characters
/// in `run_id` are mapped to `_` so a hostile or unexpected run id can't break
/// rule loading. Capped to keep the full name short and human-readable in
/// `nft list ruleset` output.
pub fn derive_table_name(run_id: &str) -> String {
    let suffix_len = run_id.len().min(16);
    let suffix: String = run_id[..suffix_len]
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    format!("crucible-{suffix}")
}

/// The log prefix the kernel writes for a dropped packet on this Run's TAP.
///
/// A follow-up slice tails the kernel log and emits an `egress_denied` event
/// for each line carrying this prefix. The prefix embeds the table name (and
/// therefore the run id suffix) so the consumer can correlate the drop with
/// the Run it belongs to.
pub fn drop_log_prefix(table_name: &str) -> String {
    // Limit: nftables log prefix max is 127 chars. Our format stays far below.
    format!("crucible-egress-drop[{table_name}]: ")
}

/// Build the nftables ruleset that allows only TCP to `proxy_host:proxy_port`
/// arriving on `tap` and drops everything else (with logging).
///
/// The ruleset lives in its own `inet` table named `table_name` so multiple
/// concurrent Runs don't interfere — each Run loads + deletes its own table.
/// `input` and `forward` are both hooked because guest traffic to the host's
/// proxy IP lands in `input` and any cross-routed packet would land in
/// `forward` — both must be filtered.
///
/// Drop is logged with [`drop_log_prefix`] so a side-channel reader can emit
/// `egress_denied(protocol=raw_tcp)` events from the kernel log.
pub fn build_ruleset(
    table_name: &str,
    tap: &str,
    proxy_host: Ipv4Addr,
    proxy_port: u16,
) -> String {
    let prefix = drop_log_prefix(table_name);
    format!(
        "table inet {table_name} {{\n\
         \x20   chain input {{\n\
         \x20       type filter hook input priority filter; policy accept;\n\
         \x20       iifname \"{tap}\" jump from-guest\n\
         \x20   }}\n\
         \x20   chain forward {{\n\
         \x20       type filter hook forward priority filter; policy accept;\n\
         \x20       iifname \"{tap}\" jump from-guest\n\
         \x20   }}\n\
         \x20   chain from-guest {{\n\
         \x20       ip daddr {proxy_host} tcp dport {proxy_port} accept\n\
         \x20       log prefix \"{prefix}\" level info\n\
         \x20       counter drop\n\
         \x20   }}\n\
         }}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // ── derive_table_name ──────────────────────────────────────────────────

    #[test]
    fn table_name_uses_first_sixteen_chars_of_run_id() {
        assert_eq!(
            derive_table_name("01HZXMSAMPLERUNID0000000000"),
            "crucible-01HZXMSAMPLERUNI"
        );
    }

    #[test]
    fn table_name_handles_short_run_ids() {
        assert_eq!(derive_table_name("abc"), "crucible-abc");
        assert_eq!(derive_table_name(""), "crucible-");
    }

    #[test]
    fn table_name_sanitizes_non_identifier_chars() {
        // Anything not in [A-Za-z0-9_-] becomes '_'. Periods, slashes, spaces
        // would otherwise break `nft -f` parsing.
        assert_eq!(derive_table_name("a.b/c d"), "crucible-a_b_c_d");
        assert_eq!(derive_table_name("hi!"), "crucible-hi_");
    }

    #[test]
    fn table_name_preserves_dash_and_underscore() {
        assert_eq!(derive_table_name("a-b_c"), "crucible-a-b_c");
    }

    // ── drop_log_prefix ────────────────────────────────────────────────────

    #[test]
    fn drop_log_prefix_embeds_table_name() {
        let p = drop_log_prefix("crucible-abc");
        assert!(p.contains("crucible-abc"));
        // The trailing ": " is what the kernel log parser will split on; keep
        // it stable so the follow-up emitter slice can rely on it.
        assert!(p.ends_with(": "));
    }

    #[test]
    fn drop_log_prefix_under_kernel_limit() {
        // nftables enforces 127 chars max on log prefixes.
        let p = drop_log_prefix(&derive_table_name("01HZXMSAMPLERUNID0000000000"));
        assert!(p.len() <= 127, "prefix too long: {} chars", p.len());
    }

    // ── build_ruleset ──────────────────────────────────────────────────────

    #[test]
    fn ruleset_declares_table_in_inet_family() {
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.1.1"), 8080);
        assert!(r.contains("table inet crucible-tt"));
    }

    #[test]
    fn ruleset_filters_only_traffic_from_tap() {
        // input and forward chains both jump only when iifname matches the
        // TAP; traffic on any other host interface is untouched.
        let r = build_ruleset("crucible-tt", "tap-xyz", ipv4("169.254.1.1"), 8080);
        assert!(r.contains("iifname \"tap-xyz\" jump from-guest"));
        // Both hook chains should jump on iifname; count occurrences.
        let n = r.matches("iifname \"tap-xyz\" jump from-guest").count();
        assert_eq!(n, 2, "expected input + forward both to filter the TAP");
    }

    #[test]
    fn ruleset_accepts_only_tcp_to_proxy_host_and_port() {
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.42.1"), 34567);
        assert!(r.contains("ip daddr 169.254.42.1 tcp dport 34567 accept"));
    }

    #[test]
    fn ruleset_falls_through_to_log_drop() {
        // Order matters: accept first, then log, then drop. nftables
        // evaluates rules top-to-bottom; if accept ever moves below drop the
        // proxy stops working.
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.1.1"), 8080);
        let accept_pos = r.find("accept").expect("accept rule missing");
        let log_pos = r.find("log prefix").expect("log rule missing");
        let drop_pos = r.find("drop").expect("drop rule missing");
        assert!(accept_pos < log_pos, "accept must precede log");
        assert!(log_pos < drop_pos, "log must precede drop");
    }

    #[test]
    fn ruleset_log_prefix_matches_helper() {
        // The log prefix in the ruleset must equal drop_log_prefix() so the
        // future kernel-log emitter and the rule loader agree.
        let table = "crucible-runxyz";
        let r = build_ruleset(table, "tap-runxyz", ipv4("169.254.1.1"), 8080);
        let prefix = drop_log_prefix(table);
        assert!(
            r.contains(&format!("log prefix \"{prefix}\"")),
            "ruleset is missing the log prefix produced by drop_log_prefix: {prefix:?}"
        );
    }

    #[test]
    fn ruleset_default_policy_is_accept_on_hooks() {
        // We do NOT change the host's default chain policy — only Run-specific
        // traffic gets filtered. Otherwise loading the ruleset could break
        // the host's own networking.
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.1.1"), 8080);
        assert!(r.contains("policy accept"));
    }

    #[test]
    fn ruleset_with_different_tap_names_produces_different_text() {
        let r1 = build_ruleset("crucible-a", "tap-a", ipv4("169.254.1.1"), 8080);
        let r2 = build_ruleset("crucible-b", "tap-b", ipv4("169.254.1.1"), 8080);
        assert_ne!(r1, r2);
    }
}
