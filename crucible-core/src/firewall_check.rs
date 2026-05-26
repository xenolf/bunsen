//! Pure parser for `iptables -S` output (slice 10k).
//!
//! On Ubuntu (and most distros) `ufw` / `firewalld` enable an `iptables`
//! `INPUT` chain whose default policy is `DROP`. Crucible's per-Run nftables
//! table uses `policy accept`, but iptables and our `inet` table both register
//! on the netfilter `input` hook, and a packet has to survive *every* chain.
//! A stock UFW host therefore silently drops the guest→proxy SYN before our
//! allow rule ever runs — leaving the L7+L3 enforcer unusable until the user
//! either opens the link-local range manually or asks crucible to manage the
//! host firewall for this Run.
//!
//! This module is platform-independent so the decision logic can be unit-
//! tested on macOS without `iptables` installed. The Linux-only `iptables -S`
//! shell-out, the per-TAP allow rule, and the RAII cleanup live in
//! [`crate::firewall`].
//!
//! See `.scratch/v1/issues/10-egress-enforcer.md` (slice 10k) for the design
//! rationale and the exact error message printed by the caller on
//! [`Decision::Blocked`] without an explicit opt-in.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// Whether the host's iptables INPUT chain would drop a packet arriving from
/// the per-Run /30 in `169.254.0.0/16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Either the INPUT policy is `ACCEPT`, a covering ACCEPT rule for
    /// `169.254.0.0/16` exists, or `iptables -S` produced no INPUT policy
    /// line at all (treated the same as iptables-absent: nothing to block
    /// us). Safe to proceed without touching the host firewall.
    Permissive,
    /// `iptables -P INPUT DROP` and no rule covering the link-local range
    /// was found. The guest→proxy SYN will be silently dropped at the host
    /// kernel before our nftables table sees it; the caller must either
    /// install a per-TAP allow rule (when explicitly authorized) or refuse
    /// to start the Run.
    Blocked,
}

/// Parse the stdout of `iptables -S` and decide whether the link-local
/// range can reach the host's input hook.
///
/// Rules considered "covering" are those whose `-j` target is `ACCEPT` and
/// whose `-s` (source) CIDR is a *superset of* `169.254.0.0/16`. UFW's
/// `allow from 169.254.0.0/16` lands as `-A ufw-user-input -s 169.254.0.0/16
/// -j ACCEPT` and matches exactly. A broader `0.0.0.0/0` ACCEPT also covers.
/// A narrower rule (e.g. `169.254.0.0/20`) is treated as not covering — the
/// per-Run /30 may not fall inside it, and we'd rather force the user to
/// pass `--manage-firewall` than guess.
///
/// Chain reachability is not traced. Any rule anywhere in the dump that
/// covers the range counts: in practice UFW writes its allow rules into
/// `ufw-user-input`, which is reachable from INPUT via the default UFW
/// scaffolding.
pub fn parse_iptables_save(s: &str) -> Decision {
    let mut policy: Option<&str> = None;
    let mut has_covering_accept = false;

    for raw in s.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("-P ") {
            let mut toks = rest.split_whitespace();
            if toks.next() == Some("INPUT") {
                if let Some(target) = toks.next() {
                    policy = Some(target);
                }
            }
            continue;
        }

        if !line.starts_with("-A ") {
            continue;
        }
        if extract_token_value(line, "-j") != Some("ACCEPT") {
            continue;
        }

        if let Some(src) = extract_token_value(line, "-s") {
            if subnet_covers_link_local(src) {
                has_covering_accept = true;
            }
        }
    }

    match policy {
        Some("ACCEPT") | None => Decision::Permissive,
        Some(_) if has_covering_accept => Decision::Permissive,
        Some(_) => Decision::Blocked,
    }
}

/// Find the token immediately following `key` in a whitespace-split line.
///
/// Returns `Some("ACCEPT")` for input `... -j ACCEPT ...`, `None` if `key`
/// is absent or appears at the end of the line.
fn extract_token_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut toks = line.split_whitespace();
    while let Some(tok) = toks.next() {
        if tok == key {
            return toks.next();
        }
    }
    None
}

/// True when `subnet` (CIDR) is a superset of (or equal to) `169.254.0.0/16`.
///
/// `0.0.0.0/0` is the canonical "everything" CIDR and is always covering.
/// Prefixes longer than 16 cannot cover the whole /16 and are rejected
/// even when the address matches.
fn subnet_covers_link_local(subnet: &str) -> bool {
    let (addr, prefix) = match subnet.split_once('/') {
        Some((a, p)) => match p.parse::<u8>() {
            Ok(n) => (a, n),
            Err(_) => return false,
        },
        None => (subnet, 32u8),
    };
    if prefix > 16 {
        return false;
    }

    let ip = match parse_ipv4(addr) {
        Some(ip) => ip,
        None => return false,
    };

    const LINK_LOCAL: u32 = 0xa9fe_0000;
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    (ip & mask) == (LINK_LOCAL & mask)
}

fn parse_ipv4(s: &str) -> Option<u32> {
    let mut ip: u32 = 0;
    let mut octets = 0;
    for part in s.split('.') {
        let n: u32 = part.parse().ok()?;
        if n > 255 {
            return None;
        }
        ip = (ip << 8) | n;
        octets += 1;
    }
    if octets == 4 {
        Some(ip)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU_UFW_DROP: &str = "\
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N ufw-after-input
-N ufw-after-logging-forward
-N ufw-before-input
-N ufw-user-input
-A INPUT -j ufw-before-input
-A INPUT -j ufw-after-input
-A INPUT -i lo -j ACCEPT
-A ufw-before-input -i lo -j ACCEPT
";

    #[test]
    fn policy_accept_is_permissive() {
        let s = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
        assert_eq!(parse_iptables_save(s), Decision::Permissive);
    }

    #[test]
    fn policy_drop_with_no_covering_rule_is_blocked() {
        assert_eq!(parse_iptables_save(UBUNTU_UFW_DROP), Decision::Blocked);
    }

    #[test]
    fn policy_drop_with_ufw_allow_link_local_is_permissive() {
        let s = format!(
            "{UBUNTU_UFW_DROP}-A ufw-user-input -s 169.254.0.0/16 -j ACCEPT\n"
        );
        assert_eq!(parse_iptables_save(&s), Decision::Permissive);
    }

    #[test]
    fn policy_drop_with_unrelated_allow_subnet_is_blocked() {
        // User opened a different /16 that doesn't cover 169.254/16.
        let s = format!(
            "{UBUNTU_UFW_DROP}-A ufw-user-input -s 10.0.0.0/16 -j ACCEPT\n\
             -A ufw-user-input -s 192.168.0.0/16 -j ACCEPT\n"
        );
        assert_eq!(parse_iptables_save(&s), Decision::Blocked);
    }

    #[test]
    fn docker_chains_alone_do_not_cover_link_local() {
        // Docker installs DOCKER and DOCKER-USER chains with broad rules
        // *into its own bridges*, but nothing that opens 169.254/16.
        let s = "\
-P INPUT DROP
-N DOCKER
-N DOCKER-USER
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER
-A DOCKER-USER -j RETURN
";
        assert_eq!(parse_iptables_save(s), Decision::Blocked);
    }

    #[test]
    fn missing_input_policy_line_is_permissive() {
        // Some boxes (no iptables, kernel without netfilter) produce an
        // empty dump. Treat as permissive — there's nothing to block us.
        assert_eq!(parse_iptables_save(""), Decision::Permissive);
        // Same when the dump is non-empty but the INPUT policy line is
        // missing (e.g. only custom chains shown).
        let s = "-N DOCKER\n-A DOCKER -j RETURN\n";
        assert_eq!(parse_iptables_save(s), Decision::Permissive);
    }

    #[test]
    fn zero_zero_zero_zero_slash_zero_accept_is_permissive() {
        let s = "-P INPUT DROP\n-A INPUT -s 0.0.0.0/0 -j ACCEPT\n";
        assert_eq!(parse_iptables_save(s), Decision::Permissive);
    }

    #[test]
    fn superset_of_link_local_is_permissive() {
        // 169.254.0.0/8 is a superset of 169.254.0.0/16.
        let s = "-P INPUT DROP\n-A INPUT -s 169.0.0.0/8 -j ACCEPT\n";
        assert_eq!(parse_iptables_save(s), Decision::Permissive);
    }

    #[test]
    fn subset_of_link_local_is_blocked() {
        // 169.254.0.0/20 is a strict subset — it covers only the first 16
        // /30s, but our derive_run_network picks any /30 in the /16. Do
        // not treat as covering.
        let s = "-P INPUT DROP\n-A INPUT -s 169.254.0.0/20 -j ACCEPT\n";
        assert_eq!(parse_iptables_save(s), Decision::Blocked);
    }

    #[test]
    fn accept_without_source_is_blocked() {
        // A bare `-A INPUT -j ACCEPT` (no -s) would in practice match
        // everything, but we keep the parser strict: covering requires an
        // explicit -s superset, so users who want this path use
        // --manage-firewall rather than rely on an ambiguous bare rule.
        let s = "-P INPUT DROP\n-A INPUT -j ACCEPT\n";
        assert_eq!(parse_iptables_save(s), Decision::Blocked);
    }

    #[test]
    fn trailing_whitespace_and_blank_lines_are_ignored() {
        let s = "   \n-P INPUT ACCEPT  \n   \n\n  -P FORWARD ACCEPT\n";
        assert_eq!(parse_iptables_save(s), Decision::Permissive);
    }

    #[test]
    fn policy_line_order_does_not_matter() {
        // INPUT policy after a covering rule.
        let s = "\
-A ufw-user-input -s 169.254.0.0/16 -j ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P INPUT DROP
";
        assert_eq!(parse_iptables_save(s), Decision::Permissive);
    }

    #[test]
    fn malformed_cidr_does_not_count_as_covering() {
        let s = "-P INPUT DROP\n-A INPUT -s 169.254.0.0/notanumber -j ACCEPT\n";
        assert_eq!(parse_iptables_save(s), Decision::Blocked);
    }

    #[test]
    fn rule_with_no_accept_target_does_not_cover() {
        let s = "-P INPUT DROP\n-A INPUT -s 169.254.0.0/16 -j REJECT\n";
        assert_eq!(parse_iptables_save(s), Decision::Blocked);
    }

    #[test]
    fn parse_ipv4_round_trip() {
        // 169.254.0.0 = 0xa9fe0000
        assert_eq!(parse_ipv4("169.254.0.0"), Some(0xa9fe_0000));
        assert_eq!(parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(0xffff_ffff));
        // Reject malformed inputs.
        assert_eq!(parse_ipv4("169.254"), None);
        assert_eq!(parse_ipv4("169.254.0.0.0"), None);
        assert_eq!(parse_ipv4("169.254.0.256"), None);
        assert_eq!(parse_ipv4(""), None);
    }

    #[test]
    fn subnet_covers_link_local_classification() {
        assert!(subnet_covers_link_local("169.254.0.0/16"));
        assert!(subnet_covers_link_local("169.254.0.0/8"));
        assert!(subnet_covers_link_local("169.0.0.0/8"));
        assert!(subnet_covers_link_local("0.0.0.0/0"));
        // Same /16 prefix from a different masked address — the parser
        // treats the rule's address as canonical, so 169.254.5.5/16 still
        // means "169.254.0.0/16".
        assert!(subnet_covers_link_local("169.254.5.5/16"));
        // Subnet boundary cases that must not be treated as covering.
        assert!(!subnet_covers_link_local("10.0.0.0/8"));
        assert!(!subnet_covers_link_local("169.254.0.0/17"));
        assert!(!subnet_covers_link_local("169.254.0.0/24"));
        assert!(!subnet_covers_link_local("169.254.0.0/32"));
        // Garbage in → false out.
        assert!(!subnet_covers_link_local("not-a-cidr"));
        assert!(!subnet_covers_link_local("169.254.0.0/40"));
    }
}
