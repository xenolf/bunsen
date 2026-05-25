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

use std::io;
use std::net::Ipv4Addr;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::mpsc;

use crate::egress::{DenialEvent, Protocol};

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
/// When `dns_port` is `Some(p)`, an additional rule permits UDP to
/// `proxy_host:p` so the host-side DNS listener (slice 10m) is reachable from
/// the guest. When `None`, all UDP from the TAP — including DNS — is dropped
/// (and surfaces as `egress_denied(protocol=raw_tcp)` via the drop-log
/// emitter); this is the right default if the DNS listener failed to bind
/// (e.g. dev box without `CAP_NET_BIND_SERVICE`) because the alternative is
/// to silently forward queries to whatever resolver the guest picks.
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
    dns_port: Option<u16>,
) -> String {
    let prefix = drop_log_prefix(table_name);
    let dns_rule = match dns_port {
        Some(p) => format!(
            "        ip daddr {proxy_host} udp dport {p} accept\n",
        ),
        None => String::new(),
    };
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
         {dns_rule}\
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

/// Drive a side-channel reader: read kernel-log lines from `reader`, parse
/// each with [`parse_drop_log_line`], and forward matches whose
/// [`DropEvent::table`] equals `own_table` as [`DenialEvent`]s on `sender`.
///
/// The Run Supervisor already drains a [`DenialEvent`] channel emitted by the
/// L7 proxy (see [`crate::egress_proxy`]); this lets the L3 path share the
/// same wire so both denial sources fuse into one `egress_denied` stream
/// without changing the supervisor's select-loop shape.
///
/// Filtering by `own_table` is what makes a single host-wide kernel-log tail
/// (e.g. `journalctl -k -f`) safe with concurrent Runs: each Run only emits
/// events whose embedded table name matches its own.
///
/// Returns:
/// - `Ok(())` on EOF (the reader's stream closed).
/// - Early `Ok(())` if `sender` is closed — the consumer is gone, so there
///   is no point continuing to read.
/// - `Err(io::Error)` only on a read failure.
pub async fn pump_drop_log_lines<R>(
    reader: R,
    own_table: &str,
    sender: mpsc::UnboundedSender<DenialEvent>,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let Some(ev) = parse_drop_log_line(&line) else {
            continue;
        };
        if ev.table != own_table {
            continue;
        }
        let denial = DenialEvent {
            destination: ev.destination.clone(),
            protocol: ev.protocol,
            reason: drop_event_reason(&ev),
        };
        if sender.send(denial).is_err() {
            // Receiver dropped — Run is shutting down; stop tailing.
            break;
        }
    }
    Ok(())
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
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.1.1"), 8080, None);
        assert!(r.contains("table inet crucible-tt"));
    }

    #[test]
    fn ruleset_filters_only_traffic_from_tap() {
        // input and forward chains both jump only when iifname matches the
        // TAP; traffic on any other host interface is untouched.
        let r = build_ruleset("crucible-tt", "tap-xyz", ipv4("169.254.1.1"), 8080, None);
        assert!(r.contains("iifname \"tap-xyz\" jump from-guest"));
        // Both hook chains should jump on iifname; count occurrences.
        let n = r.matches("iifname \"tap-xyz\" jump from-guest").count();
        assert_eq!(n, 2, "expected input + forward both to filter the TAP");
    }

    #[test]
    fn ruleset_accepts_only_tcp_to_proxy_host_and_port() {
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.42.1"), 34567, None);
        assert!(r.contains("ip daddr 169.254.42.1 tcp dport 34567 accept"));
    }

    #[test]
    fn ruleset_falls_through_to_log_drop() {
        // Order matters: accept first, then log, then drop. nftables
        // evaluates rules top-to-bottom; if accept ever moves below drop the
        // proxy stops working.
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.1.1"), 8080, None);
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
        let r = build_ruleset(table, "tap-runxyz", ipv4("169.254.1.1"), 8080, None);
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
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.1.1"), 8080, None);
        assert!(r.contains("policy accept"));
    }

    #[test]
    fn ruleset_with_different_tap_names_produces_different_text() {
        let r1 = build_ruleset("crucible-a", "tap-a", ipv4("169.254.1.1"), 8080, None);
        let r2 = build_ruleset("crucible-b", "tap-b", ipv4("169.254.1.1"), 8080, None);
        assert_ne!(r1, r2);
    }

    // ── slice 10m: optional DNS allow rule ─────────────────────────────────

    #[test]
    fn ruleset_no_dns_port_omits_udp_rule() {
        // Default (no DNS listener bound) — UDP from the TAP is dropped along
        // with everything else.
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.1.1"), 8080, None);
        assert!(!r.contains("udp dport"), "no UDP rule should appear when dns_port=None:\n{r}");
    }

    #[test]
    fn ruleset_with_dns_port_accepts_udp_to_proxy_host() {
        // DNS listener bound on port 53 → ruleset must permit UDP to the
        // proxy host on that port. Without this rule, the guest's DNS
        // queries get dropped at L3 before they ever reach the listener.
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.42.1"), 34567, Some(53));
        assert!(
            r.contains("ip daddr 169.254.42.1 udp dport 53 accept"),
            "ruleset missing DNS allow rule:\n{r}"
        );
    }

    #[test]
    fn ruleset_dns_rule_precedes_log_drop() {
        // The accept-then-log-then-drop ordering must hold for the DNS rule
        // too. nftables walks the chain top-to-bottom; if DNS accept ends up
        // below `drop`, guest DNS would be silently denied.
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.1.1"), 8080, Some(53));
        let udp_pos = r.find("udp dport 53 accept").expect("dns rule missing");
        let log_pos = r.find("log prefix").expect("log rule missing");
        let drop_pos = r.find("counter drop").expect("drop rule missing");
        assert!(udp_pos < log_pos, "dns accept must precede log");
        assert!(log_pos < drop_pos, "log must precede drop");
    }

    #[test]
    fn ruleset_dns_rule_uses_proxy_host_address() {
        // The DNS listener is bound on the same TAP host IP as the L7 proxy
        // (both bind on net.host in run_sandbox), so the accept rule's
        // destination must match the proxy host, not some other address.
        let r = build_ruleset("crucible-tt", "tap-tt", ipv4("169.254.5.9"), 8080, Some(53));
        assert!(r.contains("ip daddr 169.254.5.9 udp dport 53"));
        // Other addresses should not appear in a UDP rule.
        assert!(!r.contains("ip daddr 127.0.0.1 udp"));
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

    // ── pump_drop_log_lines ────────────────────────────────────────────────

    use tokio::io::{AsyncWriteExt, BufReader};

    fn synthetic_line(table: &str, dst: &str, dpt: Option<u16>, proto: &str) -> String {
        let prefix = drop_log_prefix(table);
        match dpt {
            Some(p) => format!(
                "{prefix}IN=tap-x OUT= SRC=169.254.1.2 DST={dst} PROTO={proto} DPT={p}\n"
            ),
            None => format!(
                "{prefix}IN=tap-x OUT= SRC=169.254.1.2 DST={dst} PROTO={proto}\n"
            ),
        }
    }

    #[tokio::test]
    async fn pump_emits_denial_for_matching_table() {
        let table = derive_table_name("01HXY00000000000");
        let input = synthetic_line(&table, "8.8.8.8", Some(443), "TCP");
        let (tx, mut rx) = mpsc::unbounded_channel();

        pump_drop_log_lines(BufReader::new(input.as_bytes()), &table, tx)
            .await
            .expect("pump must finish cleanly on EOF");

        let ev = rx.try_recv().expect("denial event expected");
        assert_eq!(ev.destination, "8.8.8.8:443");
        assert_eq!(ev.protocol, Protocol::RawTcp);
        // Reason must follow the stable `drop_event_reason` shape so the host
        // transcript shows a consistent reason across L3 drops.
        assert!(ev.reason.contains("TCP"), "reason missing L4 proto: {:?}", ev.reason);
        assert!(ev.reason.to_lowercase().contains("l3"), "reason: {:?}", ev.reason);
        assert!(rx.try_recv().is_err(), "no extra event expected");
    }

    #[tokio::test]
    async fn pump_filters_by_table_name() {
        // Two Runs share a host. Only events whose embedded table matches
        // *our* table should be forwarded — otherwise a single tail would
        // cross-contaminate events between Runs.
        let our_table = derive_table_name("OURS-1111111111");
        let other_table = derive_table_name("OTHER-2222222222");
        let mut input = String::new();
        input.push_str(&synthetic_line(&other_table, "9.9.9.9", Some(443), "TCP"));
        input.push_str(&synthetic_line(&our_table, "1.1.1.1", Some(80), "TCP"));
        input.push_str(&synthetic_line(&other_table, "8.8.4.4", Some(53), "UDP"));

        let (tx, mut rx) = mpsc::unbounded_channel();
        pump_drop_log_lines(BufReader::new(input.as_bytes()), &our_table, tx)
            .await
            .expect("pump must finish cleanly on EOF");

        let ev = rx.try_recv().expect("our event must come through");
        assert_eq!(ev.destination, "1.1.1.1:80");
        assert!(rx.try_recv().is_err(), "other tables must be filtered out");
    }

    #[tokio::test]
    async fn pump_ignores_unrelated_lines() {
        let table = derive_table_name("01HXY00000000000");
        let mut input = String::new();
        input.push_str("May 25 12:34:56 host kernel: usb 1-1: new high-speed USB device\n");
        input.push_str("audit: type=1400 something\n");
        input.push_str("\n");
        // A line carrying the marker but missing DST= must also be skipped.
        input.push_str(&format!(
            "{}IN=tap-x OUT= PROTO=TCP DPT=443\n",
            drop_log_prefix(&table)
        ));

        let (tx, mut rx) = mpsc::unbounded_channel();
        pump_drop_log_lines(BufReader::new(input.as_bytes()), &table, tx)
            .await
            .expect("pump must finish cleanly on EOF");

        assert!(rx.try_recv().is_err(), "no events expected from unrelated lines");
    }

    #[tokio::test]
    async fn pump_returns_when_receiver_dropped() {
        // If the consumer goes away mid-tail there is nothing useful to do:
        // the pump must exit promptly rather than keep reading kernel log
        // forever and accumulating dead sends. We use a "stuck" reader (an
        // open duplex with no writer activity after the first matched line)
        // to force the loop to traverse send-failure before EOF.
        let table = derive_table_name("RUN0000000000000");
        let (mut writer, reader) = tokio::io::duplex(4096);

        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx); // close consumer before pump even reads

        // Write one matching line; pump should try to send, observe a closed
        // channel, and return. Without the early-exit the test would hang
        // here on the next read.
        let line = synthetic_line(&table, "8.8.8.8", Some(443), "TCP");
        writer.write_all(line.as_bytes()).await.unwrap();

        let pump = tokio::spawn(async move {
            pump_drop_log_lines(BufReader::new(reader), &table, tx).await
        });

        // The pump should resolve quickly. If it hangs, this test will time
        // out via the tokio test harness (and we'll know early-exit broke).
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), pump).await;
        let inner = result
            .expect("pump must not block once the receiver is gone")
            .expect("pump task must not panic");
        inner.expect("pump must return Ok on receiver-closed");

        // Drop the writer; pump is already done.
        drop(writer);
    }

    #[tokio::test]
    async fn pump_handles_multiple_matching_lines_in_order() {
        let table = derive_table_name("ORDER0000000000");
        let mut input = String::new();
        input.push_str(&synthetic_line(&table, "1.1.1.1", Some(443), "TCP"));
        input.push_str(&synthetic_line(&table, "2.2.2.2", Some(80), "TCP"));
        input.push_str(&synthetic_line(&table, "3.3.3.3", None, "ICMP"));

        let (tx, mut rx) = mpsc::unbounded_channel();
        pump_drop_log_lines(BufReader::new(input.as_bytes()), &table, tx)
            .await
            .expect("pump must finish cleanly on EOF");

        let e1 = rx.try_recv().expect("first event");
        assert_eq!(e1.destination, "1.1.1.1:443");
        let e2 = rx.try_recv().expect("second event");
        assert_eq!(e2.destination, "2.2.2.2:80");
        let e3 = rx.try_recv().expect("third event");
        assert_eq!(e3.destination, "3.3.3.3");
        assert!(e3.reason.contains("ICMP"), "reason should carry L4 proto: {:?}", e3.reason);
        assert!(rx.try_recv().is_err(), "no extra events expected");
    }

}
