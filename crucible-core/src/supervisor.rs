use std::path::Path;
use std::process::Stdio;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use crate::adapter::BlackBoxAdapter;
use crate::encoder::Encoder;
use crate::run_spec::RunSpec;

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

fn signal_pgid(pgid: Pid, sig: Signal) {
    let _ = killpg(pgid, sig);
}

pub async fn run(spec: &RunSpec, _run_id: &str, encoder: &mut Encoder, workspace_path: &Path) -> std::io::Result<()> {
    let mut cmd = Command::new(&spec.cmd[0]);
    cmd.args(&spec.cmd[1..])
        .envs(&spec.env)
        .current_dir(workspace_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Child gets its own stdin (closed/null) — crucible-core's stdin is for control commands
        .stdin(Stdio::null());

    // Place child in its own process group
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;
    let child_pid = child.id().expect("child pid") as i32;
    let pgid = Pid::from_raw(child_pid);

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Channel: output lines → main task
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

    // Read crucible-core's own stdin for control commands
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ControlCmd>(16);
    let stdin_tx = cmd_tx.clone();
    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(cmd) = parse_cmd(&line) {
                if stdin_tx.send(cmd).await.is_err() {
                    break;
                }
            }
        }
    });

    // Wall-clock timeout: SIGKILL after the limit, regardless of state
    let wall_clock = spec.wall_clock_seconds;
    let timeout_tx = cmd_tx.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(wall_clock)).await;
        let _ = timeout_tx.send(ControlCmd::Timeout).await;
    });

    let grace = spec.stop_grace_seconds;
    let mut done_count = 0usize;
    // Track whether a terminal command was issued and what reason to use
    let mut initiated_reason: Option<&'static str> = None;

    loop {
        tokio::select! {
            msg = out_rx.recv() => {
                match msg {
                    Some(OutputLine::Line { stream, text }) => {
                        encoder.emit("output", BlackBoxAdapter::output_event(stream, text.as_bytes()))?;
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
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(ControlCmd::Kill) => {
                        // Only override "stopped" with "killed" when grace-period escalates
                        if initiated_reason != Some("stopped") {
                            initiated_reason = Some("killed");
                        } else {
                            initiated_reason = Some("killed"); // grace period escalation
                        }
                        signal_pgid(pgid, Signal::SIGKILL);
                    }
                    Some(ControlCmd::Stop) => {
                        initiated_reason = Some("stopped");
                        signal_pgid(pgid, Signal::SIGTERM);
                        let cmd_tx2 = cmd_tx.clone();
                        tokio::spawn(async move {
                            sleep(Duration::from_secs(grace)).await;
                            // Grace period expired — escalate; this overrides "stopped" to "killed"
                            let _ = cmd_tx2.send(ControlCmd::Kill).await;
                        });
                    }
                    Some(ControlCmd::Timeout) => {
                        initiated_reason = Some("timeout");
                        signal_pgid(pgid, Signal::SIGKILL);
                    }
                    Some(ControlCmd::Pause) => {
                        signal_pgid(pgid, Signal::SIGSTOP);
                    }
                    Some(ControlCmd::Resume) => {
                        signal_pgid(pgid, Signal::SIGCONT);
                    }
                    None => {}
                }
            }
        }
    }

    let status = child.wait().await?;
    let exit_code = status.code();

    let reason = match initiated_reason {
        Some(r) => r,
        None => {
            if exit_code.is_some() { "agent_exit" } else { "killed" }
        }
    };

    let payload = if let Some(code) = exit_code {
        json!({ "reason": reason, "exit_code": code })
    } else {
        json!({ "reason": reason })
    };
    encoder.emit("run_ended", payload)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cmd_stop() {
        assert!(matches!(parse_cmd(r#"{"op":"stop"}"#), Some(ControlCmd::Stop)));
    }

    #[test]
    fn parse_cmd_kill() {
        assert!(matches!(parse_cmd(r#"{"op":"kill"}"#), Some(ControlCmd::Kill)));
    }

    #[test]
    fn parse_cmd_pause() {
        assert!(matches!(parse_cmd(r#"{"op":"pause"}"#), Some(ControlCmd::Pause)));
    }

    #[test]
    fn parse_cmd_resume() {
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
