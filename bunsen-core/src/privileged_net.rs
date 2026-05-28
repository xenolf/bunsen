//! PrivilegedNet actor — single OS thread that owns every privileged network
//! operation.
//!
//! All child-process spawning for `ip`, `nft`, `iptables`, and `journalctl`
//! happens via `std::process::Command` on this thread, not on a tokio runtime
//! thread. That invariant is load-bearing: once Module B's capability-retaining
//! drop lands, this thread will carry `CAP_NET_ADMIN` / `CAP_NET_BIND_SERVICE`
//! / `CAP_SYSLOG` in its ambient set, and `execve` inherits from the calling
//! thread's capability state.
//!
//! Callers communicate through [`PrivilegedNetHandle`], which exposes `async fn`
//! methods so callers in a tokio context can await replies without blocking the
//! executor.

// The actor, handle, and exec implementations require Linux.
#[cfg(target_os = "linux")]
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::os::unix::io::IntoRawFd;
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::mpsc;

// Test-only: Command is used in argv-builder helpers compiled on all platforms.
#[cfg(all(test, not(target_os = "linux")))]
use std::process::Command;

#[cfg(target_os = "linux")]
use anyhow::{anyhow, bail, Context, Result};
#[cfg(target_os = "linux")]
use tokio::sync::oneshot;

// ── Command enum ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
enum Cmd {
    ProbeFirewall { reply: oneshot::Sender<Result<Option<String>>> },
    AddTapAllow { tap: String, reply: oneshot::Sender<Result<()>> },
    RemoveTapAllow { tap: String, reply: oneshot::Sender<Result<()>> },
    CreateTap {
        name: String,
        host_addr: Ipv4Addr,
        prefix_len: u8,
        owner_user: String,
        reply: oneshot::Sender<Result<()>>,
    },
    DeleteTap { name: String, reply: oneshot::Sender<Result<()>> },
    ApplyNft { ruleset: String, reply: oneshot::Sender<Result<()>> },
    DeleteNft { table: String, reply: oneshot::Sender<Result<()>> },
    BindDns { addr: SocketAddr, reply: oneshot::Sender<Result<std::os::unix::io::RawFd>> },
    SpawnJournalctl { reply: oneshot::Sender<Result<Child>> },
}

// ── Public handle ─────────────────────────────────────────────────────────────

/// Cloneable handle to the PrivilegedNet actor thread.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct PrivilegedNetHandle {
    tx: mpsc::SyncSender<Cmd>,
}

#[cfg(target_os = "linux")]
impl PrivilegedNetHandle {
    fn send(&self, cmd: Cmd) -> Result<()> {
        self.tx.try_send(cmd).map_err(|_| anyhow!("privileged-net actor: queue full or closed"))
    }

    /// Run `iptables -S` and return the output. Returns `Ok(None)` when
    /// `iptables` is not installed.
    pub async fn probe_firewall(&self) -> Result<Option<String>> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::ProbeFirewall { reply: tx })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }

    /// Install `iptables -I INPUT -i <tap> -j ACCEPT`.
    pub async fn add_tap_allow(&self, tap: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::AddTapAllow { tap: tap.to_owned(), reply: tx })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }

    /// Remove `iptables -D INPUT -i <tap> -j ACCEPT`. Idempotent.
    pub async fn remove_tap_allow(&self, tap: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::RemoveTapAllow { tap: tap.to_owned(), reply: tx })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }

    /// Create a TAP device owned by `owner_user`, bring it up, and assign the
    /// host-side /30 address.
    pub async fn create_tap(
        &self,
        name: &str,
        host_addr: Ipv4Addr,
        prefix_len: u8,
        owner_user: &str,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::CreateTap {
            name: name.to_owned(),
            host_addr,
            prefix_len,
            owner_user: owner_user.to_owned(),
            reply: tx,
        })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }

    /// Delete a TAP device. Idempotent.
    pub async fn delete_tap(&self, name: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::DeleteTap { name: name.to_owned(), reply: tx })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }

    /// Load an nftables ruleset by piping it to `nft -f -`.
    pub async fn apply_nft(&self, ruleset: String) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::ApplyNft { ruleset, reply: tx })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }

    /// Delete an nftables table. Idempotent.
    pub async fn delete_nft(&self, table: &str) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::DeleteNft { table: table.to_owned(), reply: tx })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }

    /// Bind a UDP socket on `addr` (privileged for port 53) and return the raw
    /// file descriptor. The caller adopts it via
    /// `std::net::UdpSocket::from_raw_fd` + `tokio::net::UdpSocket::from_std`.
    pub async fn bind_dns(&self, addr: SocketAddr) -> Result<std::os::unix::io::RawFd> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::BindDns { addr, reply: tx })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }

    /// Spawn `journalctl -k -f --output=cat --since=now` on the actor thread
    /// (so it inherits ambient capabilities). Returns the child process; the
    /// caller takes `child.stdout` and wires it into the drop-log line pump.
    pub async fn spawn_journalctl(&self) -> Result<Child> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::SpawnJournalctl { reply: tx })?;
        rx.await.map_err(|_| anyhow!("privileged-net actor dropped reply"))?
    }
}

// ── Actor thread ──────────────────────────────────────────────────────────────

/// Spawn the PrivilegedNet actor on a dedicated OS thread and return a handle.
#[cfg(target_os = "linux")]
pub fn start_actor() -> PrivilegedNetHandle {
    let (tx, rx) = mpsc::sync_channel::<Cmd>(64);
    std::thread::Builder::new()
        .name("privileged-net".into())
        .spawn(move || run_actor(rx))
        .expect("spawn privileged-net thread");
    PrivilegedNetHandle { tx }
}

#[cfg(target_os = "linux")]
fn run_actor(rx: mpsc::Receiver<Cmd>) {
    for cmd in rx {
        match cmd {
            Cmd::ProbeFirewall { reply } => {
                let _ = reply.send(exec_probe_firewall());
            }
            Cmd::AddTapAllow { tap, reply } => {
                let _ = reply.send(exec_add_tap_allow(&tap));
            }
            Cmd::RemoveTapAllow { tap, reply } => {
                let _ = reply.send(exec_remove_tap_allow(&tap));
            }
            Cmd::CreateTap { name, host_addr, prefix_len, owner_user, reply } => {
                let _ = reply.send(exec_create_tap(&name, host_addr, prefix_len, &owner_user));
            }
            Cmd::DeleteTap { name, reply } => {
                let _ = reply.send(exec_delete_tap(&name));
            }
            Cmd::ApplyNft { ruleset, reply } => {
                let _ = reply.send(exec_apply_nft(&ruleset));
            }
            Cmd::DeleteNft { table, reply } => {
                let _ = reply.send(exec_delete_nft(&table));
            }
            Cmd::BindDns { addr, reply } => {
                let _ = reply.send(exec_bind_dns(addr));
            }
            Cmd::SpawnJournalctl { reply } => {
                let _ = reply.send(exec_spawn_journalctl());
            }
        }
    }
}

// ── Synchronous implementations ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn exec_probe_firewall() -> Result<Option<String>> {
    let out = match Command::new("iptables").arg("-S").output() {
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

#[cfg(target_os = "linux")]
fn exec_add_tap_allow(tap: &str) -> Result<()> {
    let s = Command::new("iptables")
        .args(["-I", "INPUT", "-i", tap, "-j", "ACCEPT"])
        .status()
        .context("spawn iptables -I")?;
    if !s.success() {
        bail!("iptables -I INPUT -i {tap} -j ACCEPT failed (exit {:?})", s.code());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_remove_tap_allow(tap: &str) -> Result<()> {
    // Idempotent: ignore non-zero exit (missing rule is not an error).
    let _ = Command::new("iptables")
        .args(["-D", "INPUT", "-i", tap, "-j", "ACCEPT"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_create_tap(name: &str, host_addr: Ipv4Addr, prefix_len: u8, owner_user: &str) -> Result<()> {
    let s = Command::new("ip")
        .args(["tuntap", "add", "dev", name, "mode", "tap", "user", owner_user])
        .status()
        .context("spawn ip tuntap add")?;
    if !s.success() {
        bail!("ip tuntap add dev {name} mode tap user {owner_user} failed");
    }
    let s = Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()
        .context("spawn ip link set up")?;
    if !s.success() {
        bail!("ip link set {name} up failed");
    }
    let addr_arg = format!("{host_addr}/{prefix_len}");
    let s = Command::new("ip")
        .args(["addr", "add", &addr_arg, "dev", name])
        .status()
        .context("spawn ip addr add")?;
    if !s.success() {
        bail!("ip addr add {addr_arg} dev {name} failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_delete_tap(name: &str) -> Result<()> {
    // Idempotent: ignore exit code.
    let _ = Command::new("ip").args(["link", "del", name]).status();
    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_apply_nft(ruleset: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn nft")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(ruleset.as_bytes()).context("write nft rules")?;
    }

    let output = child.wait_with_output().context("wait nft")?;
    if !output.status.success() {
        bail!(
            "nft -f - failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_delete_nft(table: &str) -> Result<()> {
    // Idempotent: ignore non-zero exit (missing table is not an error).
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", table])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_bind_dns(addr: SocketAddr) -> Result<std::os::unix::io::RawFd> {
    let sock = UdpSocket::bind(addr).with_context(|| format!("bind UDP {addr}"))?;
    Ok(sock.into_raw_fd())
}

#[cfg(target_os = "linux")]
fn exec_spawn_journalctl() -> Result<Child> {
    Command::new("journalctl")
        .args(["-k", "-f", "--output=cat", "--since=now"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn journalctl -k -f for L3 drop-log tail")
}

// ── TapAllowGuard ─────────────────────────────────────────────────────────────

/// RAII handle that removes the per-TAP iptables allow rule on drop.
///
/// Drop runs synchronously via the `exec_remove_tap_allow` helper rather than
/// scheduling a new async task: cleanup must run reliably on panic and during
/// tokio runtime shutdown, neither of which is a safe place for new async work.
#[cfg(target_os = "linux")]
pub struct TapAllowGuard {
    tap: String,
    active: bool,
}

#[cfg(target_os = "linux")]
impl TapAllowGuard {
    pub fn new(tap: String) -> Self {
        Self { tap, active: true }
    }
}

#[cfg(target_os = "linux")]
impl Drop for TapAllowGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = exec_remove_tap_allow(&self.tap);
    }
}

// ── Argv builders exposed for testing ────────────────────────────────────────
// These functions return un-spawned Commands so tests can inspect arguments
// without root or real binaries.  They compile on all platforms so the argv
// unit tests run in CI on macOS as well as Linux.

#[cfg(test)]
fn build_create_tap_cmd(name: &str, owner_user: &str) -> Command {
    let mut cmd = Command::new("ip");
    cmd.args(["tuntap", "add", "dev", name, "mode", "tap", "user", owner_user]);
    cmd
}

#[cfg(test)]
fn build_delete_tap_cmd(name: &str) -> Command {
    let mut cmd = Command::new("ip");
    cmd.args(["link", "del", name]);
    cmd
}

#[cfg(test)]
fn build_apply_nft_cmd() -> Command {
    let mut cmd = Command::new("nft");
    cmd.args(["-f", "-"]);
    cmd
}

#[cfg(test)]
fn build_delete_nft_cmd(table: &str) -> Command {
    let mut cmd = Command::new("nft");
    cmd.args(["delete", "table", "inet", table]);
    cmd
}

#[cfg(test)]
fn build_add_tap_allow_cmd(tap: &str) -> Command {
    let mut cmd = Command::new("iptables");
    cmd.args(["-I", "INPUT", "-i", tap, "-j", "ACCEPT"]);
    cmd
}

#[cfg(test)]
fn build_remove_tap_allow_cmd(tap: &str) -> Command {
    let mut cmd = Command::new("iptables");
    cmd.args(["-D", "INPUT", "-i", tap, "-j", "ACCEPT"]);
    cmd
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn program(cmd: &Command) -> String {
        cmd.get_program().to_string_lossy().into_owned()
    }

    fn args(cmd: &Command) -> Vec<String> {
        cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn create_tap_cmd_includes_user_arg() {
        let cmd = build_create_tap_cmd("tap-abc", "alice");
        assert_eq!(program(&cmd), "ip");
        assert_eq!(
            args(&cmd),
            ["tuntap", "add", "dev", "tap-abc", "mode", "tap", "user", "alice"]
        );
    }

    #[test]
    fn delete_tap_cmd_args() {
        let cmd = build_delete_tap_cmd("tap-abc");
        assert_eq!(program(&cmd), "ip");
        assert_eq!(args(&cmd), ["link", "del", "tap-abc"]);
    }

    #[test]
    fn apply_nft_cmd_args() {
        let cmd = build_apply_nft_cmd();
        assert_eq!(program(&cmd), "nft");
        assert_eq!(args(&cmd), ["-f", "-"]);
    }

    #[test]
    fn delete_nft_cmd_args() {
        let cmd = build_delete_nft_cmd("bsn-xyz");
        assert_eq!(program(&cmd), "nft");
        assert_eq!(args(&cmd), ["delete", "table", "inet", "bsn-xyz"]);
    }

    #[test]
    fn add_tap_allow_cmd_args() {
        let cmd = build_add_tap_allow_cmd("tap-abc");
        assert_eq!(program(&cmd), "iptables");
        assert_eq!(args(&cmd), ["-I", "INPUT", "-i", "tap-abc", "-j", "ACCEPT"]);
    }

    #[test]
    fn remove_tap_allow_cmd_args() {
        let cmd = build_remove_tap_allow_cmd("tap-abc");
        assert_eq!(program(&cmd), "iptables");
        assert_eq!(args(&cmd), ["-D", "INPUT", "-i", "tap-abc", "-j", "ACCEPT"]);
    }
}
