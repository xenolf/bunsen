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
