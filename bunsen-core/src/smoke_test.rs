//! `bunsen-core sandbox-smoke-test` — boots a Firecracker microVM with a
//! hello-world agent and verifies the full vsock plumbing end-to-end.
//!
//! Usage:
//!   bunsen-core sandbox-smoke-test \
//!     --kernel  /path/to/vmlinux \
//!     --rootfs  /path/to/rootfs.ext4 \
//!     [--firecracker /path/to/firecracker]
//!
//! The smoke-test spec runs:
//!   sh -c "echo hello world && sleep 1"
//! It verifies "hello world\n" appears on the stdout vsock, then sends `stop`
//! over the control vsock, then prints PASS.

use crate::firecracker::{create_tap, delete_tap, start_firecracker, FirecrackerHandle};
use crate::sandbox::SandboxConfig;
use crate::sandbox_net::{derive_run_network, derive_tap_name};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const SMOKE_SPEC_JSON: &str = r#"{
  "adapter": "black-box",
  "cmd": ["sh", "-c", "echo hello world && sleep 30"],
  "env": {}
}"#;

const HELLO_WORLD: &str = "hello world\n";
const TIMEOUT_SECS: u64 = 60;

struct Args {
    kernel: PathBuf,
    rootfs: PathBuf,
    firecracker: PathBuf,
}

pub async fn run(raw_args: &[String]) -> Result<()> {
    let args = parse_args(raw_args)?;

    println!("bunsen sandbox-smoke-test");
    println!("  kernel:      {}", args.kernel.display());
    println!("  rootfs:      {}", args.rootfs.display());
    println!("  firecracker: {}", args.firecracker.display());

    let run_id = "smoke01".to_string();
    let net = derive_run_network(&run_id);
    let tap_name = derive_tap_name(&run_id);

    // Slice 10f: the caller owns the TAP lifecycle now. Smoke test doesn't
    // exercise the L7 proxy, but it still needs to hand a live TAP to
    // start_firecracker so the VM can attach its network interface.
    let _ = delete_tap(&tap_name).await;
    create_tap(&tap_name, net.host, net.prefix_len)
        .await
        .context("create smoke TAP")?;
    // FirecrackerHandle no longer deletes the TAP on drop; own its teardown
    // here so the smoke TAP is removed on every exit path.
    let _tap_guard = crate::privileged_net::TapGuard::new(tap_name.clone());

    let config = SandboxConfig {
        kernel_path: args.kernel,
        rootfs_path: args.rootfs,
        workspace_host_path: std::env::temp_dir().join("bunsen-smoke-workspace"),
        spec_json: SMOKE_SPEC_JSON.to_string(),
        vcpus: 1,
        mem_mib: 512,
        workspace_disk_mib: 128,
        run_id,
        tap_name,
    };

    std::fs::create_dir_all(&config.workspace_host_path)
        .context("create smoke workspace dir")?;

    println!("[1/4] Starting Firecracker VM…");
    let mut handle = timeout(
        Duration::from_secs(TIMEOUT_SECS),
        start_firecracker(&config, &args.firecracker),
    )
    .await
    .context("VM start timed out")??;

    println!("[2/4] Waiting for 'hello world' on stdout vsock…");
    check_hello_world(&mut handle).await?;

    println!("[3/4] Sending 'pause' then 'resume' over control vsock…");
    send_control(&mut handle, "pause").await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    send_control(&mut handle, "resume").await?;

    println!("[4/4] Sending 'stop' over control vsock…");
    send_control(&mut handle, "stop").await?;
    timeout(Duration::from_secs(15), handle.wait())
        .await
        .context("VM did not exit after stop")??;

    println!("PASS");
    Ok(())
}

async fn check_hello_world(handle: &mut FirecrackerHandle) -> Result<()> {
    let mut buf = vec![0u8; 256];
    let mut got = String::new();

    loop {
        let n = timeout(Duration::from_secs(30), handle.stdout.as_mut().unwrap().read(&mut buf))
            .await
            .context("timeout waiting for stdout output")??;
        if n == 0 {
            bail!("stdout vsock closed before 'hello world' was received");
        }
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
        if got.contains(HELLO_WORLD) {
            return Ok(());
        }
    }
}

async fn send_control(handle: &mut FirecrackerHandle, op: &str) -> Result<()> {
    let cmd = format!("{{\"op\":\"{op}\"}}\n");
    handle
        .control
        .write_all(cmd.as_bytes())
        .await
        .context("write control command")?;
    handle.control.flush().await?;
    Ok(())
}

fn parse_args(args: &[String]) -> Result<Args> {
    let mut kernel: Option<PathBuf> = None;
    let mut rootfs: Option<PathBuf> = None;
    let mut firecracker: PathBuf = PathBuf::from("firecracker");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kernel" if i + 1 < args.len() => {
                kernel = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--rootfs" if i + 1 < args.len() => {
                rootfs = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--firecracker" if i + 1 < args.len() => {
                firecracker = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            flag => bail!("unknown flag: {flag}"),
        }
    }

    Ok(Args {
        kernel: kernel.context("--kernel is required")?,
        rootfs: rootfs.context("--rootfs is required")?,
        firecracker,
    })
}
