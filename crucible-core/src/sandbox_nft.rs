//! Per-Run L3 nftables ruleset (ADR-0005).
//!
//! The Sandbox's TAP is the only path between the guest and the host kernel.
//! v1 layers a default-deny nftables filter on traffic coming *in* via that
//! TAP: only TCP to the L7 proxy address is allowed; everything else is
//! dropped and logged with a per-Run prefix. A side-channel reader tails the
//! kernel log, parses lines that carry [`drop_log_prefix`], and emits
//! `egress_denied(protocol=raw_tcp)` events.
//!
//! This module is platform-independent: it ships the ruleset string, the
//! sanitized table name, and the pure parser for drop-log lines. The
//! Linux-only `nft -f -` shell-out, cleanup, and kernel-log tailing live in
//! [`crate::firecracker`] alongside the TAP lifecycle.

use std::net::Ipv4Addr;

use crate::egress::Protocol;

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

/// One parsed kernel-log drop record.
///
/// A side-channel reader tails the kernel log host-wide, runs
/// [`parse_drop_log_line`] on each line, and uses [`DropEvent::table`] to
/// route the event to the correct Run's [`crate::encoder::Encoder`]. Per
/// ADR-0005 every L3 drop surfaces as `protocol=raw_tcp` on the wire — the
/// kernel-reported L4 protocol is kept on [`DropEvent::l4_proto`] for the
/// `reason` field but does not change the event's `protocol` discriminator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropEvent {
    /// Table name embedded in the prefix — used to identify which Run the
    /// drop belongs to.
    pub table: String,
    /// `IP:PORT` for TCP/UDP, bare `IP` for protocols without a port.
    pub destination: String,
    /// Always [`Protocol::RawTcp`] on the wire; carried here for symmetry
    /// with the L7 path so callers can pass the same struct shape to
    /// [`crate::egress::denied_payload`].
    pub protocol: Protocol,
    /// Kernel-reported L4 protocol name (e.g. `"TCP"`, `"UDP"`, `"ICMP"`) —
    /// surfaced in the event's `reason` for triage.
    pub l4_proto: String,
}

/// Parse a kernel-log line carrying an nftables drop emitted by our ruleset.
///
/// Returns `None` if the line does not contain [`drop_log_prefix`]'s
/// `crucible-egress-drop[<table>]: ` marker or if the required `DST=` field
/// is missing. Extra leading content (syslog timestamp, hostname, `kernel:`
/// tag, kernel `[12345.678]` monotonic stamp) is tolerated so the same
/// parser works on raw `dmesg -w`, `journalctl -k`, and `/dev/kmsg` lines.
pub fn parse_drop_log_line(line: &str) -> Option<DropEvent> {
    const MARKER: &str = "crucible-egress-drop[";
    let start = line.find(MARKER)?;
    let after_marker = &line[start + MARKER.len()..];
    let bracket_end = after_marker.find(']')?;
    let table = &after_marker[..bracket_end];
    if table.is_empty() {
        return None;
    }
    let rest = after_marker.get(bracket_end + 1..)?;
    // Tolerate either ":" or ": " right after the bracketed table name.
    let rest = rest.strip_prefix(':').unwrap_or(rest);
    let rest = rest.trim_start();

    let mut dst: Option<&str> = None;
    let mut dpt: Option<&str> = None;
    let mut l4: Option<&str> = None;
    for token in rest.split_ascii_whitespace() {
        if let Some(v) = token.strip_prefix("DST=") {
            dst = Some(v);
        } else if let Some(v) = token.strip_prefix("DPT=") {
            dpt = Some(v);
        } else if let Some(v) = token.strip_prefix("PROTO=") {
            l4 = Some(v);
        }
    }

    let dst = dst?;
    if dst.is_empty() {
        return None;
    }
    let destination = match dpt {
        Some(p) if !p.is_empty() => format!("{dst}:{p}"),
        _ => dst.to_string(),
    };
    let l4_proto = l4.unwrap_or("UNKNOWN").to_string();

    Some(DropEvent {
        table: table.to_string(),
        destination,
        protocol: Protocol::RawTcp,
        l4_proto,
    })
}

/// Build the `reason` field for an `egress_denied` event derived from a
/// parsed [`DropEvent`]. Stable shape so future log parsers (e.g. the DNS
/// denial path) can produce similarly-formatted reasons.
pub fn drop_event_reason(ev: &DropEvent) -> String {
    format!("L3 drop (proto={})", ev.l4_proto)
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

    // ── parse_drop_log_line ────────────────────────────────────────────────

    /// Sample after `dmesg -w` (or `journalctl -k --output=cat`) of an
    /// nftables `log prefix "<our-prefix>" level info` drop. Format is the
    /// standard `LOG` target output: space-separated `KEY=VALUE` tokens.
    const SAMPLE_TCP_DROP: &str = "[12345.678] crucible-egress-drop[crucible-01HXY]: \
        IN=tap-abc OUT= MAC=02:00:00:00:00:01 \
        SRC=169.254.1.2 DST=8.8.8.8 LEN=60 TOS=0x00 PREC=0x00 TTL=64 \
        ID=54321 DF PROTO=TCP SPT=44321 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0";

    #[test]
    fn parse_drop_extracts_table_and_destination() {
        let ev = parse_drop_log_line(SAMPLE_TCP_DROP).expect("must parse");
        assert_eq!(ev.table, "crucible-01HXY");
        assert_eq!(ev.destination, "8.8.8.8:443");
        assert_eq!(ev.l4_proto, "TCP");
        // Wire-level protocol stays raw_tcp regardless of L4 type per ADR-0005.
        assert_eq!(ev.protocol, Protocol::RawTcp);
    }

    #[test]
    fn parse_drop_tolerates_journalctl_prefix() {
        // `journalctl -k` (without --output=cat) prepends a syslog-style
        // header before the kernel message; the parser must still find the
        // marker via `line.find(...)`.
        let line = "May 25 12:34:56 hostname kernel: crucible-egress-drop[crucible-RUN]: \
            IN=tap-x OUT= SRC=169.254.1.2 DST=1.1.1.1 PROTO=TCP SPT=33333 DPT=80";
        let ev = parse_drop_log_line(line).expect("must parse");
        assert_eq!(ev.table, "crucible-RUN");
        assert_eq!(ev.destination, "1.1.1.1:80");
    }

    #[test]
    fn parse_drop_handles_udp_with_port() {
        // UDP also carries DPT — same shape as TCP.
        let line = "crucible-egress-drop[crucible-RUN]: \
            IN=tap-x OUT= SRC=169.254.1.2 DST=8.8.8.8 PROTO=UDP SPT=11111 DPT=53 LEN=40";
        let ev = parse_drop_log_line(line).expect("must parse");
        assert_eq!(ev.destination, "8.8.8.8:53");
        assert_eq!(ev.l4_proto, "UDP");
    }

    #[test]
    fn parse_drop_handles_icmp_without_port() {
        // ICMP has no DPT — destination is the bare IP.
        let line = "crucible-egress-drop[crucible-RUN]: \
            IN=tap-x OUT= SRC=169.254.1.2 DST=10.0.0.5 PROTO=ICMP TYPE=8 CODE=0";
        let ev = parse_drop_log_line(line).expect("must parse");
        assert_eq!(ev.destination, "10.0.0.5");
        assert_eq!(ev.l4_proto, "ICMP");
        assert_eq!(ev.protocol, Protocol::RawTcp);
    }

    #[test]
    fn parse_drop_returns_none_for_unrelated_lines() {
        // Other kernel log lines (e.g. systemd, audit, iptables from
        // elsewhere) must not be mistaken for our drop log.
        assert!(parse_drop_log_line("hostname kernel: usb 1-1: new high-speed USB device").is_none());
        assert!(parse_drop_log_line("audit: type=1400 something").is_none());
        assert!(parse_drop_log_line("").is_none());
    }

    #[test]
    fn parse_drop_requires_dst_field() {
        // A line that carries the marker but is missing DST= can't be turned
        // into a useful event — return None rather than emit `0.0.0.0`.
        let line = "crucible-egress-drop[crucible-RUN]: IN=tap-x OUT= PROTO=TCP DPT=443";
        assert!(parse_drop_log_line(line).is_none());
    }

    #[test]
    fn parse_drop_rejects_empty_table_name() {
        // A malformed/truncated prefix like `crucible-egress-drop[]:` should
        // not produce an event we can route — without a table name there is
        // no Run to attribute the drop to.
        let line = "crucible-egress-drop[]: IN=tap-x DST=8.8.8.8 PROTO=TCP DPT=443";
        assert!(parse_drop_log_line(line).is_none());
    }

    #[test]
    fn parse_drop_table_matches_derive_table_name() {
        // The whole point of embedding the table name in the prefix is to
        // demultiplex across concurrent Runs. Round-trip: derive a name,
        // build a synthetic line, parse it back, and confirm the table name
        // survives intact.
        let table = derive_table_name("01HZXMSAMPLERUNID0000000000");
        let prefix = drop_log_prefix(&table);
        let line = format!("{prefix}IN=tap-x OUT= SRC=169.254.1.2 DST=8.8.8.8 PROTO=TCP DPT=443");
        let ev = parse_drop_log_line(&line).expect("must parse");
        assert_eq!(ev.table, table);
    }

    #[test]
    fn parse_drop_tolerates_missing_proto_field() {
        // If for some reason PROTO is absent, fall back to UNKNOWN rather
        // than dropping the event — the side-channel still wants to surface
        // the drop, just with a less specific reason.
        let line = "crucible-egress-drop[crucible-RUN]: IN=tap-x OUT= DST=8.8.8.8 DPT=443";
        let ev = parse_drop_log_line(line).expect("must parse");
        assert_eq!(ev.l4_proto, "UNKNOWN");
        assert_eq!(ev.destination, "8.8.8.8:443");
    }

    #[test]
    fn parse_drop_handles_ipv6_destination_format() {
        // IPv6 dst appears with colons; we store it verbatim with the port
        // suffix. Bracketed IPv6 host:port shape is the caller's problem —
        // for raw_tcp `destination` is informational, not a URL.
        let line = "crucible-egress-drop[crucible-RUN]: IN=tap-x OUT= \
            SRC=fe80::1 DST=2001:db8::1 PROTO=TCP DPT=443";
        let ev = parse_drop_log_line(line).expect("must parse");
        assert_eq!(ev.destination, "2001:db8::1:443");
    }

    // ── drop_event_reason ──────────────────────────────────────────────────

    #[test]
    fn drop_event_reason_includes_l4_proto() {
        let ev = DropEvent {
            table: "crucible-RUN".into(),
            destination: "8.8.8.8:443".into(),
            protocol: Protocol::RawTcp,
            l4_proto: "TCP".into(),
        };
        let r = drop_event_reason(&ev);
        assert!(r.contains("TCP"), "reason missing L4 proto: {r:?}");
        assert!(r.to_lowercase().contains("l3"), "reason should mention L3 origin: {r:?}");
    }
}
