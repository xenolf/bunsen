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
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::sleep;

const FIRECRACKER_READY_RETRIES: u32 = 50;
const FIRECRACKER_READY_DELAY_MS: u64 = 100;

pub struct FirecrackerHandle {
    pub stdout: UnixStream,
    pub stderr: UnixStream,
    pub control: UnixStream,
    process: Child,
    run_dir: PathBuf,
    tap_name: String,
}

impl FirecrackerHandle {
    pub async fn kill(&mut self) -> Result<()> {
        self.process.kill().await?;
        Ok(())
    }

    pub async fn wait(&mut self) -> Result<()> {
        self.process.wait().await?;
        Ok(())
    }
}

impl Drop for FirecrackerHandle {
    fn drop(&mut self) {
        let tap = self.tap_name.clone();
        let dir = self.run_dir.clone();
        tokio::spawn(async move {
            delete_tap(&tap).await.ok();
            std::fs::remove_dir_all(&dir).ok();
        });
    }
}

pub async fn start_firecracker(
    config: &SandboxConfig,
    firecracker_bin: &Path,
) -> Result<FirecrackerHandle> {
    let run_dir = std::env::temp_dir()
        .join(format!("crucible-fc-{}", &config.run_id));
    std::fs::create_dir_all(&run_dir)
        .context("create firecracker run dir")?;

    let api_socket = run_dir.join("api.sock");
    let vsock_path = run_dir.join("vsock.sock");
    let workspace_ext4 = run_dir.join("workspace.ext4");

    let tap_name = format!("tap-{}", &config.run_id[..8]);

    // 1. Create TAP device.
    create_tap(&tap_name).await.context("create TAP device")?;

    // 2. Create workspace ext4 image.
    create_workspace_ext4(&workspace_ext4, config.workspace_disk_mib)
        .await
        .context("create workspace ext4")?;

    // 3. Create vsock listener UDS for stdout and stderr BEFORE starting VM,
    //    because the guest connects immediately after init runs.
    let stdout_listener = UnixListener::bind(vsock_socket_path(&vsock_path, VSOCK_STDOUT_PORT))
        .context("bind stdout vsock listener")?;
    let stderr_listener = UnixListener::bind(vsock_socket_path(&vsock_path, VSOCK_STDERR_PORT))
        .context("bind stderr vsock listener")?;

    // 4. Spawn Firecracker.
    let process = Command::new(firecracker_bin)
        .args(["--api-sock", &api_socket.to_string_lossy()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn firecracker")?;

    // Wait for API socket to appear.
    wait_for_api_socket(&api_socket).await
        .context("Firecracker API socket did not appear")?;

    // 5. Configure VM via REST API.
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
    fc_put(&api_socket, "/actions", &serde_json::to_string(&FcActionStart::default()).unwrap())
        .await
        .context("Firecracker InstanceStart")?;

    // 7. Accept stdout and stderr connections from the guest.
    //    These arrive after crucible-init boots.
    let (stdout, _) = stdout_listener.accept().await.context("accept stdout vsock")?;
    let (stderr, _) = stderr_listener.accept().await.context("accept stderr vsock")?;

    // 8. Connect host→guest for control (send CONNECT {port}\n).
    let control = connect_host_to_guest(&vsock_path, VSOCK_CONTROL_PORT)
        .await
        .context("connect control vsock")?;

    Ok(FirecrackerHandle {
        stdout,
        stderr,
        control,
        process,
        run_dir,
        tap_name,
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
/// Sends `Connection: close` so we can use `read_to_end` after the response.
async fn fc_put(socket: &Path, path: &str, body: &str) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect to Firecracker API socket {}", socket.display()))?;

    let request = format!(
        "PUT {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let status = parse_http_status(&response)
        .with_context(|| format!("parse Firecracker response for PUT {path}"))?;

    if status >= 400 {
        let body = response_body(&response);
        bail!("Firecracker PUT {path} returned HTTP {status}: {body}");
    }
    Ok(())
}

fn parse_http_status(response: &[u8]) -> Result<u16> {
    let text = std::str::from_utf8(response).context("response is not UTF-8")?;
    let line = text.lines().next().ok_or_else(|| anyhow!("empty response"))?;
    let code = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("no status code in: {line}"))?;
    code.parse::<u16>().context("parse status code")
}

fn response_body(response: &[u8]) -> String {
    let text = String::from_utf8_lossy(response);
    if let Some(pos) = text.find("\r\n\r\n") {
        text[pos + 4..].to_string()
    } else {
        String::new()
    }
}

// ─── Host→guest vsock control connection ──────────────────────────────────

/// Connect to the Firecracker vsock UDS and send `CONNECT {port}\n` to
/// establish a host→guest channel on the given vsock port.
async fn connect_host_to_guest(vsock_uds: &Path, port: u32) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(vsock_uds)
        .await
        .context("connect to vsock UDS")?;
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await?;
    stream.flush().await?;

    // Firecracker replies "OK <cid> <port>\n" on success.
    let mut ack = vec![0u8; 32];
    let n = stream.read(&mut ack).await?;
    let reply = std::str::from_utf8(&ack[..n]).unwrap_or("").trim().to_string();
    if !reply.starts_with("OK") {
        bail!("vsock CONNECT rejected: {reply}");
    }
    Ok(stream)
}

// ─── TAP device management ─────────────────────────────────────────────────

async fn create_tap(name: &str) -> Result<()> {
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
    Ok(())
}

async fn delete_tap(name: &str) -> Result<()> {
    Command::new("ip")
        .args(["link", "del", name])
        .status()
        .await?;
    Ok(())
}

// ─── Workspace ext4 ────────────────────────────────────────────────────────

async fn create_workspace_ext4(path: &Path, size_mib: u32) -> Result<()> {
    // Create a sparse file of the desired size.
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
    Ok(())
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
