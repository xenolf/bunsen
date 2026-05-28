//! Linux-only host-firewall co-existence (slice 10k).
//!
//! `enforce_host_firewall_policy` probes the host iptables INPUT chain via
//! the [`PrivilegedNetHandle`] and, together with the User Script's
//! `manage_firewall` opt-in, decides whether to proceed with a Run.
//! The decision logic lives in [`crate::firewall_check`] so it stays testable
//! on macOS.

use anyhow::Result;

use crate::firewall_check::{enforce_decision, parse_iptables_save, Decision};
use crate::privileged_net::PrivilegedNetHandle;

/// Probe iptables and turn the result, together with the User Script's
/// `manage_firewall` opt-in, into a single Yes/No-with-message answer.
///
/// - `iptables` absent → Permissive → `Ok(())`.
/// - `iptables` present, probe failed (e.g. unprivileged) → WARN on stderr,
///   treat as Permissive.
/// - INPUT policy ACCEPT, or covering rule for 169.254.0.0/16 present →
///   Permissive → `Ok(())`.
/// - INPUT policy DROP, no covering rule, `manage_firewall == false` → `Err`
///   with the byte-for-byte [`crate::firewall_check::BLOCKED_MESSAGE`].
/// - INPUT policy DROP, no covering rule, `manage_firewall == true` → `Ok(())`.
///   The per-TAP allow rule is installed later inside `sandbox_run::run`.
pub async fn enforce_host_firewall_policy(
    manage_firewall: bool,
    actor: &PrivilegedNetHandle,
) -> Result<(), String> {
    // Test-only injection point: when `BUNSEN_TEST_IPTABLES_SAVE` is set,
    // skip the real iptables shell-out and feed the synthetic dump straight
    // through the parser. Lets the Session-level test exercise the wiring
    // from `run_with_backend` → `enforce_host_firewall_policy` →
    // `SessionError::HostFirewallBlocked` without needing a Linux box with a
    // DROP policy on the INPUT chain. Compiled out of release builds.
    #[cfg(test)]
    if let Ok(s) = std::env::var(TEST_IPTABLES_SAVE_ENV) {
        return enforce_decision(parse_iptables_save(&s), manage_firewall);
    }
    #[cfg(test)]
    let _ = actor; // suppress unused warning in test builds that use the env var path

    let decision = match actor.probe_firewall().await {
        Ok(Some(stdout)) => parse_iptables_save(&stdout),
        Ok(None) => Decision::Permissive,
        Err(e) => {
            eprintln!(
                "[firewall] WARNING: failed to probe iptables: {e:#} \
                 — proceeding without firewall management"
            );
            Decision::Permissive
        }
    };
    enforce_decision(decision, manage_firewall)
}

#[cfg(test)]
pub(crate) const TEST_IPTABLES_SAVE_ENV: &str = "BUNSEN_TEST_IPTABLES_SAVE";

/// Serialise tests that mutate `TEST_IPTABLES_SAVE_ENV` — env vars are
/// process-global and `cargo test` runs tests in parallel. Any test that
/// sets the var must hold this lock for the full set/run/unset window.
#[cfg(test)]
pub(crate) static TEST_IPTABLES_SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compilation_smoke_test() {
        // Confirms the module compiles; runtime behaviour tested via Session
        // tests that set BUNSEN_TEST_IPTABLES_SAVE.
        let _ = TEST_IPTABLES_SAVE_ENV;
    }
}
