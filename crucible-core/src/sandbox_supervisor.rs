//! Sandbox-backed supervisor (Linux only).
//!
//! Reads agent output from vsock streams on a FirecrackerHandle, translates
//! crucible-core stdin control commands into JSON messages on the control vsock,
//! and emits run_ended when both vsock streams reach EOF.

use anyhow::Result;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::adapter::BlackBoxAdapter;
use crate::egress_proxy::{self, DenialEvent};
use crate::encoder::Encoder;
use crate::firecracker::FirecrackerHandle;
use crate::run_spec::RunSpec;

#[derive(Debug)]
enum ControlCmd {
    Stop,
    Kill,
    Pause,
    Resume,
    Timeout,
}

pub fn parse_cmd(line: &str) -> Option<ControlCmd> {
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
) -> Result<()> {
    // ── L7 egress proxy ────────────────────────────────────────────────────
    // Spawn the per-Run forward proxy. For now we bind on 127.0.0.1:0; the
    // veth-local IP that L3 nftables will redirect guest traffic to is a
    // future slice. Denials land on `denied_rx` and are fused into the
    // event stream by the main loop below.
    let policy = spec.effective_egress_policy();
    let (denied_tx, mut denied_rx) = mpsc::unbounded_channel::<DenialEvent>();
    let proxy_handle = match egress_proxy::spawn_listener(
        "127.0.0.1:0".parse().expect("static addr"),
        policy,
        denied_tx,
    )
    .await
    {
        Ok((addr, h)) => {
            eprintln!("[egress] L7 proxy listening on {addr}");
            Some(h)
        }
        Err(e) => {
            eprintln!("[egress] failed to start proxy listener: {e}");
            None
        }
    };

    // Control commands from crucible-core's stdin.
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
