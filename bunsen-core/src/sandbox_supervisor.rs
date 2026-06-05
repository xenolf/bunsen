//! Sandbox-backed supervisor (Linux only).
//!
//! Reads agent output from vsock streams on a FirecrackerHandle, translates
//! bunsen-core stdin control commands into JSON messages on the control vsock,
//! and emits run_ended when both vsock streams reach EOF.

use anyhow::Result;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::adapter::BlackBoxAdapter;
use crate::aider_adapter::AiderParser;
use crate::claude_code_adapter::ClaudeCodeParser;
use crate::codex_adapter::CodexParser;
use crate::egress::DenialEvent;
use crate::pi_adapter::PiParser;
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

enum AdapterParser {
    ClaudeCode(ClaudeCodeParser),
    Aider(AiderParser),
    Codex(CodexParser),
    Pi(PiParser),
    BlackBox,
}

impl AdapterParser {
    fn parse_stdout(&mut self, line: &str) -> Vec<(String, serde_json::Value)> {
        match self {
            AdapterParser::ClaudeCode(p) => p.parse_line(line),
            AdapterParser::Aider(p) => p.parse_line(line),
            AdapterParser::Codex(p) => p.parse_line(line),
            AdapterParser::Pi(p) => p.parse_line(line),
            AdapterParser::BlackBox => vec![(
                "output".into(),
                BlackBoxAdapter::output_event("stdout", line.as_bytes()),
            )],
        }
    }

    fn flush(&mut self) -> Vec<(String, serde_json::Value)> {
        match self {
            AdapterParser::Aider(p) => p.flush(),
            _ => vec![],
        }
    }
}

#[derive(Debug)]
enum OutputLine {
    Line { stream: &'static str, text: String },
    Done,
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
    let mut parser = match spec.adapter.as_str() {
        "claude-code" => AdapterParser::ClaudeCode(ClaudeCodeParser::new()),
        "aider" => AdapterParser::Aider(AiderParser::new()),
        "codex" => AdapterParser::Codex(CodexParser::new()),
        "pi" => AdapterParser::Pi(PiParser::new()),
        _ => AdapterParser::BlackBox,
    };

    let stdout = handle.stdout.take().expect("stdout already consumed");
    let stderr = handle.stderr.take().expect("stderr already consumed");

    let mut denied_rx = egress.denied_rx;
    let proxy_handle = egress.listener;
    let drop_log_handle = egress.drop_log;
    let dns_handle = egress.dns_listener;

    // Channel: output lines → main task (same pattern as supervisor.rs)
    let (out_tx, mut out_rx) = mpsc::channel::<OutputLine>(256);
    let out_tx2 = out_tx.clone();

    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if out_tx.send(OutputLine::Line { stream: "stdout", text: line + "\n" }).await.is_err() {
                break;
            }
        }
        let _ = out_tx.send(OutputLine::Done).await;
    });

    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if out_tx2.send(OutputLine::Line { stream: "stderr", text: line + "\n" }).await.is_err() {
                break;
            }
        }
        let _ = out_tx2.send(OutputLine::Done).await;
    });

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
    let mut done_count = 0usize;
    let mut denial_rx_open = true;
    let mut initiated_reason: Option<&'static str> = None;

    loop {
        tokio::select! {
            msg = out_rx.recv() => {
                match msg {
                    Some(OutputLine::Line { stream, text }) => {
                        if stream == "stdout" {
                            for (event_type, payload) in parser.parse_stdout(&text) {
                                encoder.emit(&event_type, payload)
                                    .map_err(|e| anyhow::anyhow!("encoder: {e}"))?;
                            }
                        } else {
                            encoder.emit("output", BlackBoxAdapter::output_event(stream, text.as_bytes()))
                                .map_err(|e| anyhow::anyhow!("encoder: {e}"))?;
                        }
                    }
                    Some(OutputLine::Done) => {
                        done_count += 1;
                        if done_count >= 2 {
                            break;
                        }
                    }
                    None => break,
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
                        write_control(&mut handle.control, "kill").await.ok();
                    }
                    Some(ControlCmd::Stop) => {
                        initiated_reason = Some("stopped");
                        write_control(&mut handle.control, "stop").await.ok();
                        let cmd_tx2 = cmd_tx.clone();
                        tokio::spawn(async move {
                            sleep(Duration::from_secs(grace)).await;
                            let _ = cmd_tx2.send(ControlCmd::Kill).await;
                        });
                    }
                    Some(ControlCmd::Timeout) => {
                        initiated_reason = Some("timeout");
                        write_control(&mut handle.control, "kill").await.ok();
                    }
                    Some(ControlCmd::Pause) => {
                        write_control(&mut handle.control, "pause").await.ok();
                    }
                    Some(ControlCmd::Resume) => {
                        write_control(&mut handle.control, "resume").await.ok();
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
        h.abort();
    }
    if let Some(h) = dns_handle {
        h.abort();
    }

    // Flush any per-line state the adapter parser was holding (e.g. aider's
    // split Tokens:/Cost: pair) so the transcript surfaces it before run_ended.
    for (event_type, payload) in parser.flush() {
        encoder.emit(&event_type, payload)
            .map_err(|e| anyhow::anyhow!("encoder: {e}"))?;
    }

    let reason = initiated_reason.unwrap_or("agent_exit");
    encoder.emit("run_ended", json!({ "reason": reason }))
        .map_err(|e| anyhow::anyhow!("encoder: {e}"))?;

    Ok(())
}

async fn write_control(control: &mut UnixStream, op: &str) -> std::io::Result<()> {
    let msg = format!("{{\"op\":\"{op}\"}}\n");
    control.write_all(msg.as_bytes()).await?;
    control.flush().await?;
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
