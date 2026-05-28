//! Firecracker microVM sandbox provider (Linux only).
//!
//! Lifecycle:
//!   1. Create per-run temp directory for API socket, vsock socket, workspace.ext4
//!   2. Create TAP device
//!   3. Create empty ext4 workspace image
//!   4. Create vsock listener UDS for stdout (port 5001) and stderr (port 5002)
//!   5. Spawn `firecracker --api-sock <path>`
//!   6. Configure VM via Firecracker REST API (machine-config, boot-source, drives, net, vsock)
//!   7. POST /actions InstanceStart
//!   8. Wait for guest to connect stdout/stderr vsock sockets; accept both
//!   9. Connect host→guest control vsock (send CONNECT 5003\n)
//!
//! The handle exposes:
//!   - `stdout_socket()` / `stderr_socket()` — accepted `UnixStream` for raw bytes
//!   - `control_socket()` — `UnixStream` to write JSON control commands
//!   - `kill()` / `wait()` — VM process management

use crate::sandbox::{
    FcActionStart, FcBootSource, FcDriveConfig, FcMachineConfig, FcNetworkInterface,
    FcVsockConfig, SandboxConfig, VSOCK_CONTROL_PORT, VSOCK_STDERR_PORT, VSOCK_STDOUT_PORT,
};
use anyhow::{anyhow, bail, Context, Result};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const FIRECRACKER_READY_RETRIES: u32 = 50;
const FIRECRACKER_READY_DELAY_MS: u64 = 100;

pub struct FirecrackerHandle {
    pub stdout: UnixStream,
    pub stderr: UnixStream,
    pub control: UnixStream,
    process: Child,
    run_dir: PathBuf,
}

impl FirecrackerHandle {
    // Hard-kill fallback. Today the supervisor only does cooperative kill via
    // vsock; this is here for a follow-up slice that adds a timeout escape.
    #[allow(dead_code)]
    pub async fn kill(&mut self) -> Result<()> {
        self.process.kill().await?;
        Ok(())
    }

    pub async fn wait(&mut self) -> Result<()> {
        self.process.wait().await?;
        Ok(())
    }

    /// Host-side path to the per-Run workspace ext4 image. Lives inside the
    /// handle's temp dir, which is wiped on Drop, so callers that want to
    /// mount-extract from it must do so before the handle goes out of scope.
    /// Used by [`crate::sandbox_run`] to feed the Session's Pool extraction.
    pub fn workspace_ext4_path(&self) -> PathBuf {
        self.run_dir.join("workspace.ext4")
    }
}

impl Drop for FirecrackerHandle {
    fn drop(&mut self) {
        // TAP teardown is owned by the caller's TapGuard now; the handle only
        // removes its temp run directory. Done synchronously so it runs even
        // during tokio runtime shutdown, when spawning a fresh task is unsafe.
        let _ = std::fs::remove_dir_all(&self.run_dir);
    }
}

pub async fn start_firecracker(
    config: &SandboxConfig,
    firecracker_bin: &Path,
) -> Result<FirecrackerHandle> {
    let run_dir = std::env::temp_dir()
        .join(format!("bunsen-fc-{}", &config.run_id));

    let api_socket = run_dir.join("api.sock");
    let vsock_path = run_dir.join("vsock.sock");
    let workspace_ext4 = run_dir.join("workspace.ext4");

    let tap_name = config.tap_name.clone();

    // Clean up any leftover run-dir state from a previous crashed run. The
    // caller owns the TAP lifecycle (slice 10f) and has already created it
    // bound to the per-Run host IP, which the L7 proxy is listening on.
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).context("create firecracker run dir")?;

    // 2. Create workspace ext4 image — pre-populate from host workspace dir if present.
    eprintln!("[fc] creating workspace ext4 ({} MiB)", config.workspace_disk_mib);
    create_workspace_ext4_from_dir(&workspace_ext4, &config.workspace_host_path, config.workspace_disk_mib)
        .await
        .context("create workspace ext4")?;

    // 3. Create vsock listener UDS for stdout and stderr BEFORE starting VM,
    //    because the guest connects immediately after init runs.
    eprintln!("[fc] binding vsock listeners at {}", vsock_path.display());
    let stdout_listener = UnixListener::bind(vsock_socket_path(&vsock_path, VSOCK_STDOUT_PORT))
        .context("bind stdout vsock listener")?;
    let stderr_listener = UnixListener::bind(vsock_socket_path(&vsock_path, VSOCK_STDERR_PORT))
        .context("bind stderr vsock listener")?;

    // 4. Spawn Firecracker — redirect its stderr to our stderr so boot errors are visible.
    let fc_log = run_dir.join("firecracker.log");
    eprintln!("[fc] spawning firecracker (log: {})", fc_log.display());
    // FC stdout = guest serial console (init's stdout/stderr flow here via kernel).
    // Capture it to a separate file so init panics and boot errors are visible.
    let console_log_path = run_dir.join("console.log");
    let console_log = std::fs::File::create(&console_log_path).context("create console log")?;
    eprintln!("[fc] console log: {}", console_log_path.display());
    let process = Command::new(firecracker_bin)
        .args(["--api-sock", &api_socket.to_string_lossy()])
        .stdin(std::process::Stdio::null())
        .stdout(console_log)
        .stderr(std::fs::File::create(&fc_log).context("create fc log")?)
        .spawn()
        .context("spawn firecracker")?;

    // Wait for API socket to appear.
    eprintln!("[fc] waiting for API socket…");
    wait_for_api_socket(&api_socket).await
        .context("Firecracker API socket did not appear")?;
    eprintln!("[fc] API socket ready");

    // 5. Configure VM via REST API.
    eprintln!("[fc] configuring VM…");
    configure_vm(
        &api_socket,
        config,
        firecracker_bin,
        &workspace_ext4,
        &vsock_path,
        &tap_name,
    )
    .await
    .context("configure Firecracker VM")?;

    // 6. Start the VM.
    eprintln!("[fc] sending InstanceStart…");
    fc_put(&api_socket, "/actions", &serde_json::to_string(&FcActionStart::default()).unwrap())
        .await
        .context("Firecracker InstanceStart")?;
    eprintln!("[fc] VM started — waiting for guest to connect vsock…");

    // 7. Accept stdout and stderr connections from the guest (30 s timeout each).
    let (stdout, _) = timeout(Duration::from_secs(30), stdout_listener.accept())
        .await
        .context("timeout waiting for guest stdout vsock connection")?
        .context("accept stdout vsock")?;
    eprintln!("[fc] stdout vsock connected");

    let (stderr, _) = timeout(Duration::from_secs(10), stderr_listener.accept())
        .await
        .context("timeout waiting for guest stderr vsock connection")?
        .context("accept stderr vsock")?;
    eprintln!("[fc] stderr vsock connected");

    // 8. Connect host→guest for control (send CONNECT {port}\n).
    eprintln!("[fc] connecting control vsock…");
    let control = connect_host_to_guest(&vsock_path, VSOCK_CONTROL_PORT)
        .await
        .context("connect control vsock")?;
    eprintln!("[fc] control vsock connected");

    Ok(FirecrackerHandle {
        stdout,
        stderr,
        control,
        process,
        run_dir,
    })
}

// ─── Firecracker REST API ──────────────────────────────────────────────────

async fn configure_vm(
    api_socket: &Path,
    config: &SandboxConfig,
    _firecracker_bin: &Path,
    workspace_ext4: &Path,
    vsock_path: &Path,
    tap_name: &str,
) -> Result<()> {
    // Machine config.
    fc_put(
        api_socket,
        "/machine-config",
        &serde_json::to_string(&FcMachineConfig {
            vcpu_count: config.vcpus,
            mem_size_mib: config.mem_mib,
            smt: false,
        })
        .unwrap(),
    )
    .await?;

    // Boot source.
    let boot_args = crate::sandbox::build_boot_args(&config.spec_json);
    fc_put(
        api_socket,
        "/boot-source",
        &serde_json::to_string(&FcBootSource {
            kernel_image_path: config.kernel_path.to_string_lossy().into_owned(),
            boot_args,
        })
        .unwrap(),
    )
    .await?;

    // Root drive (read-only rootfs).
    fc_put(
        api_socket,
        "/drives/rootfs",
        &serde_json::to_string(&FcDriveConfig {
            drive_id: "rootfs".to_string(),
            path_on_host: config.rootfs_path.to_string_lossy().into_owned(),
            is_root_device: true,
            is_read_only: true,
        })
        .unwrap(),
    )
    .await?;

    // Workspace drive (read-write).
    fc_put(
        api_socket,
        "/drives/workspace",
        &serde_json::to_string(&FcDriveConfig {
            drive_id: "workspace".to_string(),
            path_on_host: workspace_ext4.to_string_lossy().into_owned(),
            is_root_device: false,
            is_read_only: false,
        })
        .unwrap(),
    )
    .await?;

    // Network interface.
    fc_put(
        api_socket,
        "/network-interfaces/eth0",
        &serde_json::to_string(&FcNetworkInterface {
            iface_id: "eth0".to_string(),
            guest_mac: "AA:FC:00:00:00:01".to_string(),
            host_dev_name: tap_name.to_string(),
        })
        .unwrap(),
    )
    .await?;

    // Vsock device.
    fc_put(
        api_socket,
        "/vsock",
        &serde_json::to_string(&FcVsockConfig {
            vsock_id: "vsock0".to_string(),
            guest_cid: 3,
            uds_path: vsock_path.to_string_lossy().into_owned(),
        })
        .unwrap(),
    )
    .await?;

    Ok(())
}

/// Minimal HTTP PUT over Firecracker's Unix API socket.
/// Reads the response by parsing headers (up to \r\n\r\n) then reading
/// exactly Content-Length bytes — works with HTTP/1.1 keep-alive.
async fn fc_put(socket: &Path, path: &str, body: &str) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect to Firecracker API socket {}", socket.display()))?;

    let request = format!(
        "PUT {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Accept: application/json\r\n\
         \r\n\
         {body}",
        len = body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let (status, content_length, header_bytes) = read_http_headers(&mut stream)
        .await
        .with_context(|| format!("read Firecracker response headers for PUT {path}"))?;

    let resp_body = if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        stream.read_exact(&mut buf).await?;
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        String::new()
    };

    if status >= 400 {
        let preview = if resp_body.is_empty() {
            String::from_utf8_lossy(&header_bytes).into_owned()
        } else {
            resp_body
        };
        bail!("Firecracker PUT {path} returned HTTP {status}: {preview}");
    }
    Ok(())
}

/// Read HTTP response headers byte-by-byte until `\r\n\r\n`.
/// Returns (status_code, content_length, raw_header_bytes).
async fn read_http_headers(stream: &mut UnixStream) -> Result<(u16, usize, Vec<u8>)> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.context("reading response byte")?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            bail!("HTTP headers exceeded 8 KiB");
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();

    let status_line = lines.next().ok_or_else(|| anyhow!("empty HTTP response"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("no status code in: {status_line}"))?
        .parse::<u16>()
        .context("parse HTTP status code")?;

    let content_length = lines
        .filter_map(|l| {
            let lower = l.to_ascii_lowercase();
            lower.starts_with("content-length:").then(|| {
                l.split_once(':').map(|x| x.1).unwrap_or("").trim().parse::<usize>().ok()
            }).flatten()
        })
        .next()
        .unwrap_or(0);

    Ok((status, content_length, buf))
}

// ─── Host→guest vsock control connection ──────────────────────────────────

/// Connect to the Firecracker vsock UDS and send `CONNECT {port}\n` to
/// establish a host→guest channel on the given vsock port.
async fn connect_host_to_guest(vsock_uds: &Path, port: u32) -> Result<UnixStream> {
    // The guest may still be calling socket()/bind()/listen() on `port` when
    // the host fires off the CONNECT — Firecracker replies with a rejection
    // line if no listener is bound yet. Retry on rejection (only) with a
    // short backoff until the total elapsed exceeds the deadline; surface
    // other errors (UDS connect, I/O) immediately. The 2 s budget is well
    // above the worst-case observed gap (~50 ms) but short enough that a
    // truly broken guest fails before the host's stdout/stderr accept
    // timeouts elapse.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let mut stream = UnixStream::connect(vsock_uds)
            .await
            .context("connect to vsock UDS")?;
        stream
            .write_all(format!("CONNECT {port}\n").as_bytes())
            .await?;
        stream.flush().await?;

        // Firecracker replies "OK <cid> <port>\n" on success, otherwise a
        // line like "Failed to accept connection: ...\n".
        let mut ack = vec![0u8; 64];
        let n = stream.read(&mut ack).await?;
        let reply = std::str::from_utf8(&ack[..n]).unwrap_or("").trim().to_string();
        if reply.starts_with("OK") {
            return Ok(stream);
        }
        if std::time::Instant::now() >= deadline {
            bail!("vsock CONNECT rejected: {reply}");
        }
        // Drop the failed UDS stream and back off briefly before retrying.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ─── TAP device management ─────────────────────────────────────────────────

pub async fn create_tap(name: &str, host_addr: Ipv4Addr, prefix_len: u8) -> Result<()> {
    let s = Command::new("ip")
        .args(["tuntap", "add", "dev", name, "mode", "tap"])
        .status()
        .await?;
    if !s.success() {
        bail!("ip tuntap add failed");
    }
    let s = Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()
        .await?;
    if !s.success() {
        bail!("ip link set up failed");
    }
    let addr_arg = format!("{host_addr}/{prefix_len}");
    let s = Command::new("ip")
        .args(["addr", "add", &addr_arg, "dev", name])
        .status()
        .await?;
    if !s.success() {
        bail!("ip addr add {addr_arg} dev {name} failed");
    }
    Ok(())
}

pub async fn delete_tap(name: &str) -> Result<()> {
    Command::new("ip")
        .args(["link", "del", name])
        .status()
        .await?;
    Ok(())
}

// ─── Workspace ext4 ────────────────────────────────────────────────────────

/// Create an ext4 workspace image, pre-populating it from `source_dir` if
/// the directory is non-empty.  Uses `mkfs.ext4 -F -d <dir>` (no root needed)
/// when content is present; falls back to dd + mkfs.ext4 for an empty image.
pub async fn create_workspace_ext4_from_dir(path: &Path, source_dir: &Path, size_mib: u32) -> Result<()> {
    let has_content = source_dir.exists() && {
        let mut rd = tokio::fs::read_dir(source_dir).await?;
        rd.next_entry().await?.is_some()
    };

    if has_content {
        // mkfs.ext4 -F -d <dir> creates an image pre-populated with the dir
        // contents, no root / loop-mount required.
        let size_bytes = format!("{}M", size_mib);
        let status = Command::new("mkfs.ext4")
            .args([
                "-F",
                "-d", &source_dir.to_string_lossy(),
                "-b", "4096",
                &path.to_string_lossy(),
                &size_bytes,
            ])
            .status()
            .await
            .context("mkfs.ext4 -d")?;
        if !status.success() {
            bail!("mkfs.ext4 -d failed");
        }
    } else {
        // Empty image: dd + mkfs.ext4.
        let status = Command::new("dd")
            .args([
                "if=/dev/zero",
                &format!("of={}", path.display()),
                "bs=1M",
                &format!("count={size_mib}"),
            ])
            .status()
            .await
            .context("dd workspace")?;
        if !status.success() {
            bail!("dd workspace failed");
        }

        let status = Command::new("mkfs.ext4")
            .args(["-q", &path.to_string_lossy()])
            .status()
            .await
            .context("mkfs.ext4")?;
        if !status.success() {
            bail!("mkfs.ext4 failed");
        }
    }
    Ok(())
}

/// Extract a Run's output from its Sandbox ext4 into the Pool.
///
/// Replaces the old `cp -a` of the whole workspace tree (see ADR-0011): the
/// ext4 is mounted read-only with `ro,nosuid,nodev,noexec`, the agent's
/// `.git/` is consumed through the hardened
/// [`crate::sandbox_fetch::fetch_pool_from_git_dir`], the narrow
/// agent-history copy preserves `.claude/` (or per-adapter equivalents)
/// onto the host, and the mount is torn down — unconditionally, even if
/// fetch or copy fails.
///
/// Both the fetch and the agent-history copy receive the mounted root, so a
/// single mount lifecycle covers both. The `agent_history_dst`, when
/// supplied, is the host-side `runs/<run-id>/agent-history/` location
/// (slice 08).
///
/// The `user_script_uid` argument flows through to
/// [`crate::sandbox_fetch::fetch_pool_from_git_dir`]; on a root bunsen the
/// `git fetch` drops to that uid, otherwise it is a no-op.
// Slice 09 rewired this function to drive the Pool fetch + narrow agent-history
// copy under a single ext4 mount lifecycle. The Firecracker dispatch through
// [`crate::session::Session::run_with_backend`] (slice 12) is its production
// caller; the CLI path also routes through it via [`crate::sandbox_run`].
#[allow(clippy::too_many_arguments)]
pub async fn extract_workspace_from_ext4(
    ext4_path: &Path,
    pool: &crate::branch_pool::BranchPool,
    run_id: &str,
    output_branch: Option<&str>,
    user_script_uid: u32,
    adapter: &str,
    agent_history_dst: Option<&Path>,
) -> Result<()> {
    use crate::sandbox_fetch::{
        build_mount_argv, copy_agent_history_narrow, fetch_pool_from_git_dir,
    };

    // losetup attach.
    let losetup = Command::new("losetup")
        .args(["-f", "--show", &ext4_path.to_string_lossy()])
        .output()
        .await
        .context("losetup -f --show")?;
    if !losetup.status.success() {
        bail!("losetup failed: {}", String::from_utf8_lossy(&losetup.stderr));
    }
    let loop_dev = String::from_utf8_lossy(&losetup.stdout).trim().to_string();

    // Mount the loop device to a temp dir with the hardening quad.
    let mnt = std::env::temp_dir().join(format!(
        "bunsen-mnt-{}-{}",
        std::process::id(),
        run_id,
    ));
    std::fs::create_dir_all(&mnt)?;

    let mount_argv = build_mount_argv(&loop_dev, &mnt);
    let argv_refs: Vec<&str> = mount_argv.iter().map(String::as_str).collect();
    let mount_status = Command::new("mount")
        .args(&argv_refs)
        .status()
        .await
        .context("mount ext4 ro,nosuid,nodev,noexec")?;
    if !mount_status.success() {
        // Clean up loop device before returning error.
        Command::new("losetup").args(["-d", &loop_dev]).status().await.ok();
        std::fs::remove_dir_all(&mnt).ok();
        bail!("mount failed for {loop_dev}");
    }

    // Try fetch + narrow copy. Both happen against the same mount, so a
    // single inner block lets us bail out cleanly while still running the
    // tear-down below.
    let inner = async {
        let source_git_dir = mnt.join(".git");
        fetch_pool_from_git_dir(pool, &source_git_dir, run_id, output_branch, user_script_uid)
            .await
            .map_err(|e| anyhow!("sandbox fetch into pool failed: {e}"))?;

        if let Some(hist_dst) = agent_history_dst {
            copy_agent_history_narrow(adapter, &mnt, hist_dst)
                .map_err(|e| anyhow!("agent-history narrow copy failed: {e}"))?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let result = inner.await;

    // Always unmount + detach, regardless of inner result.
    Command::new("umount")
        .arg(&mnt.to_string_lossy().to_string())
        .status()
        .await
        .ok();
    Command::new("losetup").args(["-d", &loop_dev]).status().await.ok();
    std::fs::remove_dir_all(&mnt).ok();

    result
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn vsock_socket_path(base: &Path, port: u32) -> PathBuf {
    crate::sandbox::vsock_socket_path(base, port)
}

async fn wait_for_api_socket(path: &Path) -> Result<()> {
    for _ in 0..FIRECRACKER_READY_RETRIES {
        if path.exists() {
            return Ok(());
        }
        sleep(Duration::from_millis(FIRECRACKER_READY_DELAY_MS)).await;
    }
    bail!("Firecracker API socket {} did not appear after {}ms",
          path.display(),
          FIRECRACKER_READY_RETRIES as u64 * FIRECRACKER_READY_DELAY_MS);
}
