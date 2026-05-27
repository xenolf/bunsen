//! Sandbox-backed supervisor (Linux only).
//!
//! Reads agent output from vsock streams on a FirecrackerHandle, translates
//! bunsen-core stdin control commands into JSON messages on the control vsock,
//! and emits run_ended when both vsock streams reach EOF.

use anyhow::Result;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::adapter::BlackBoxAdapter;
use crate::egress::DenialEvent;
use crate::egress_proxy;
use crate::encoder::Encoder;
use crate::firecracker::FirecrackerHandle;
use crate::run_spec::RunSpec;

/// Pre-bound egress machinery handed to [`run`] by the caller. The L7 proxy
/// listener is bound *before* the VM starts so the bound `SocketAddr` can be
/// injected into the guest's env (`HTTP_PROXY` / `HTTPS_PROXY`); the L3
/// drop-log tail is started after nftables loads so kernel-log entries for
/// blocked guest traffic surface as `egress_denied(protocol=raw_tcp)` events
/// on the same wire as L7 denials. The supervisor owns the receive half of
/// the shared denial channel and both task handles for the duration of the
/// Run, and aborts the tasks on exit.
pub struct EgressContext {
    pub denied_rx: mpsc::UnboundedReceiver<DenialEvent>,
    pub listener: Option<tokio::task::JoinHandle<()>>,
    pub drop_log: Option<tokio::task::JoinHandle<()>>,
    /// Per-Run DNS listener (slice 10m). Bound on `net.host:53` when
    /// privileges allow; absent on dev boxes that lack `CAP_NET_BIND_SERVICE`,
    /// in which case the guest's `/etc/resolv.conf` will point at an address
    /// nothing answers on, and DNS-only egress attempts surface as L3 drops
    /// via the nftables ruleset.
    pub dns_listener: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug)]
enum ControlCmd {
    Stop,
    Kill,
    Pause,
    Resume,
    Timeout,
}

fn parse_cmd(line: &str) -> Option<ControlCmd> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    match v.get("op")?.as_str()? {
        "stop" => Some(ControlCmd::Stop),
        "kill" => Some(ControlCmd::Kill),
        "pause" => Some(ControlCmd::Pause),
        "resume" => Some(ControlCmd::Resume),
        _ => None,
    }
}

pub async fn run(
    handle: &mut FirecrackerHandle,
    spec: &RunSpec,
    encoder: &mut Encoder,
    egress: EgressContext,
) -> Result<()> {
    let mut denied_rx = egress.denied_rx;
    let proxy_handle = egress.listener;
    let drop_log_handle = egress.drop_log;
    let dns_handle = egress.dns_listener;

    // Control commands from bunsen-core's stdin.
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ControlCmd>(16);
    let stdin_cmd_tx = cmd_tx.clone();
    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(cmd) = parse_cmd(&line) {
                if stdin_cmd_tx.send(cmd).await.is_err() {
                    break;
                }
            }
        }
    });

    // Wall-clock timeout.
    let wall_clock = spec.wall_clock_seconds;
    let timeout_tx = cmd_tx.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(wall_clock)).await;
        let _ = timeout_tx.send(ControlCmd::Timeout).await;
    });

    let grace = spec.stop_grace_seconds;
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut denial_rx_open = true;
    let mut initiated_reason: Option<&'static str> = None;
    let mut stdout_buf = vec![0u8; 4096];
    let mut stderr_buf = vec![0u8; 4096];

    loop {
        if stdout_done && stderr_done {
            break;
        }

        tokio::select! {
            result = handle.stdout.read(&mut stdout_buf), if !stdout_done => {
                match result {
                    Ok(0) | Err(_) => { stdout_done = true; }
                    Ok(n) => {
                        encoder.emit("output", BlackBoxAdapter::output_event("stdout", &stdout_buf[..n]))
                            .map_err(|e| anyhow::anyhow!("encoder: {e}"))?;
                    }
                }
            }
            result = handle.stderr.read(&mut stderr_buf), if !stderr_done => {
                match result {
                    Ok(0) | Err(_) => { stderr_done = true; }
                    Ok(n) => {
                        encoder.emit("output", BlackBoxAdapter::output_event("stderr", &stderr_buf[..n]))
                            .map_err(|e| anyhow::anyhow!("encoder: {e}"))?;
                    }
                }
            }
            denial = denied_rx.recv(), if denial_rx_open => {
                match denial {
                    Some(d) => egress_proxy::emit_denial(encoder, &d)
                        .map_err(|e| anyhow::anyhow!("encoder: {e}"))?,
                    None => denial_rx_open = false,
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ControlCmd::Kill) => {
                        initiated_reason = Some("killed");
                        write_control(handle, "kill").await.ok();
                    }
                    Some(ControlCmd::Stop) => {
                        initiated_reason = Some("stopped");
                        write_control(handle, "stop").await.ok();
                        let cmd_tx2 = cmd_tx.clone();
                        tokio::spawn(async move {
                            sleep(Duration::from_secs(grace)).await;
                            let _ = cmd_tx2.send(ControlCmd::Kill).await;
                        });
                    }
                    Some(ControlCmd::Timeout) => {
                        initiated_reason = Some("timeout");
                        write_control(handle, "kill").await.ok();
                    }
                    Some(ControlCmd::Pause) => {
                        write_control(handle, "pause").await.ok();
                    }
                    Some(ControlCmd::Resume) => {
                        write_control(handle, "resume").await.ok();
                    }
                    None => {}
                }
            }
        }
    }

    // Wait for VM process to exit.
    handle.wait().await.ok();

    // Drain any denials still in the channel before emitting run_ended, then
    // tear the proxy listener down. After the VM has exited there will be no
    // new connections, but the channel may have already-queued events.
    while let Ok(d) = denied_rx.try_recv() {
        egress_proxy::emit_denial(encoder, &d)
            .map_err(|e| anyhow::anyhow!("encoder: {e}"))?;
    }
    if let Some(h) = proxy_handle {
        h.abort();
    }
    if let Some(h) = drop_log_handle {
        // Drops the task, which drops the journalctl `Child`; kill_on_drop
        // takes the kernel-log tail down for us.
        h.abort();
    }
    if let Some(h) = dns_handle {
        h.abort();
    }

    let reason = initiated_reason.unwrap_or("agent_exit");
    encoder.emit("run_ended", json!({ "reason": reason }))
        .map_err(|e| anyhow::anyhow!("encoder: {e}"))?;

    Ok(())
}

async fn write_control(handle: &mut FirecrackerHandle, op: &str) -> std::io::Result<()> {
    let msg = format!("{{\"op\":\"{op}\"}}\n");
    handle.control.write_all(msg.as_bytes()).await?;
    handle.control.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cmd_all_ops() {
        assert!(matches!(parse_cmd(r#"{"op":"stop"}"#), Some(ControlCmd::Stop)));
        assert!(matches!(parse_cmd(r#"{"op":"kill"}"#), Some(ControlCmd::Kill)));
        assert!(matches!(parse_cmd(r#"{"op":"pause"}"#), Some(ControlCmd::Pause)));
        assert!(matches!(parse_cmd(r#"{"op":"resume"}"#), Some(ControlCmd::Resume)));
    }

    #[test]
    fn parse_cmd_unknown_returns_none() {
        assert!(parse_cmd(r#"{"op":"shutdown"}"#).is_none());
        assert!(parse_cmd("not json").is_none());
        assert!(parse_cmd("").is_none());
    }

    #[test]
    fn parse_cmd_whitespace_trimmed() {
        assert!(matches!(parse_cmd(r#"  {"op":"kill"}  "#), Some(ControlCmd::Kill)));
    }
}
