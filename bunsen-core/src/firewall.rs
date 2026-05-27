//! Linux-only iptables interaction for host firewall co-existence (slice 10k).
//!
//! Calls `iptables` to probe the host's INPUT chain and, when the User Script
//! has opted in via `--manage-firewall` / `manage_firewall=True`, installs a
//! per-TAP `ACCEPT` rule that lasts only for the lifetime of the current Run.
//! The decision logic that turns `iptables -S` stdout into a
//! [`crate::firewall_check::Decision`] lives in
//! [`crate::firewall_check::parse_iptables_save`] so it remains testable on
//! macOS.
//!
//! The shape mirrors [`crate::firecracker`]'s TAP and nftables helpers:
//! probe + add are async (they're called from the async main flow), but the
//! [`TapAllowGuard`] uses synchronous `std::process::Command` in `Drop` so
//! cleanup runs reliably on every panic/exit path, including during tokio
//! runtime shutdown when spawning a fresh async task is not safe.

use anyhow::{bail, Context, Result};
use tokio::process::Command;

/// Run `iptables -S` and capture stdout.
///
/// Returns:
/// - `Ok(Some(stdout))` — the probe succeeded; pass to
///   [`crate::firewall_check::parse_iptables_save`] for a decision.
/// - `Ok(None)` — `iptables` is not installed on the host. The caller treats
///   this as [`crate::firewall_check::Decision::Permissive`]: there is no
///   iptables chain to drop our packet (a hostile pure-nft default-drop
///   would still bite, but that's a follow-up slice).
/// - `Err(e)` — `iptables` is installed but the probe failed (most often:
///   permission denied for a non-root user). The caller logs and falls back
///   to permissive — we can't add a rule we can't read, so failing loudly
///   here would force every dev box onto `--manage-firewall` even when its
///   INPUT chain is ACCEPT-by-default.
pub async fn probe_iptables() -> Result<Option<String>> {
    let out = match Command::new("iptables").arg("-S").output().await {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("running iptables -S"),
    };
    if !out.status.success() {
        bail!(
            "iptables -S exited with {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// Install `iptables -I INPUT -i <tap> -j ACCEPT`.
///
/// `-I` inserts at the top of the INPUT chain so the rule wins even when UFW
/// or another firewall has already populated the chain with deny rules later
/// on. Scoped by `-i <tap>` so the rule never opens anything beyond traffic
/// arriving on this Run's TAP device.
pub async fn add_tap_allow(tap: &str) -> Result<()> {
    let s = Command::new("iptables")
        .args(["-I", "INPUT", "-i", tap, "-j", "ACCEPT"])
        .status()
        .await
        .context("spawn iptables -I")?;
    if !s.success() {
        bail!("iptables -I INPUT -i {tap} -j ACCEPT failed (exit {:?})", s.code());
    }
    Ok(())
}

/// Remove `iptables -D INPUT -i <tap> -j ACCEPT`.
///
/// Idempotent: a missing rule is not an error, so the same call serves both
/// the pre-Run defensive cleanup path (in case a previous Run with the same
/// id crashed before its guard ran) and explicit end-of-Run teardown.
pub async fn remove_tap_allow(tap: &str) -> Result<()> {
    let _ = Command::new("iptables")
        .args(["-D", "INPUT", "-i", tap, "-j", "ACCEPT"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    Ok(())
}

/// RAII handle that removes the per-TAP allow rule on drop.
///
/// Drop runs synchronously via `std::process::Command` rather than spawning a
/// tokio task: the guard must clean up reliably on panic and during runtime
/// shutdown, neither of which is a safe place to schedule new async work.
/// The blocking `iptables -D` typically completes in a few milliseconds —
/// well under the cost of leaving a stale ACCEPT rule on the host.
pub struct TapAllowGuard {
    tap: String,
    active: bool,
}

impl TapAllowGuard {
    /// Build a guard holding ownership of the named TAP rule. The caller is
    /// responsible for installing the rule before constructing the guard.
    pub fn new(tap: String) -> Self {
        Self { tap, active: true }
    }
}

impl Drop for TapAllowGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = std::process::Command::new("iptables")
            .args(["-D", "INPUT", "-i", &self.tap, "-j", "ACCEPT"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_records_tap_name() {
        // We can't observe Drop-side effects in a unit test without root,
        // but we can confirm the type captures the tap name passed in.
        // Set `active = false` before drop so the unit test doesn't shell
        // out to a possibly-missing iptables binary in CI.
        let mut g = TapAllowGuard::new("tap-test1234".to_string());
        assert_eq!(g.tap, "tap-test1234");
        g.active = false;
    }
}
