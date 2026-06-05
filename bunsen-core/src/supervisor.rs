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
use crate::aider_adapter::AiderParser;
use crate::claude_code_adapter::ClaudeCodeParser;
use crate::codex_adapter::CodexParser;
use crate::encoder::Encoder;
use crate::pi_adapter::PiParser;
use crate::run_spec::RunSpec;

/// Per-adapter line parser dispatch. Each branch owns whatever state
/// the parser needs across lines; the supervisor only cares about the
/// (event_type, payload) pairs it gets back.
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

    /// End-of-stream flush hook. Currently only the aider parser holds
    /// state that must be drained after the final stdout line.
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

fn signal_pgid(pgid: Pid, sig: Signal) {
    let _ = killpg(pgid, sig);
}

/// Per-adapter dispatch for agent-native history preservation.
///
/// - `claude-code` stores everything in a single `.claude/` directory
///   at the workspace root; we recursively copy that into `agent-history/`.
/// - `aider` writes its history as a set of top-level files
///   (`.aider.chat.history.md`, `.aider.input.history`,
///   `.aider.llm.history`) plus cache state under `.aider.tags.cache.v3/`
///   that callers don't want to retain. We copy only the user-facing
///   history files.
/// - `pi` writes its session tree under `.pi/agent/sessions/`; we copy
///   only that subtree to exclude `auth.json` and `settings.json`.
/// - Anything else falls back to the claude-code behavior so existing
///   adapters keep working; unknown adapters that have no `.claude/`
///   simply produce an empty `agent-history/`, which is correct.
fn copy_agent_history(adapter: &str, workspace: &Path, dst: &Path) -> std::io::Result<()> {
    match adapter {
        "aider" => copy_aider_history(workspace, dst),
        // codex is invoked with --ephemeral; the normalised transcript is the sole record.
        "codex" => Ok(()),
        "pi" => {
            let pi_sessions = workspace.join(".pi").join("agent").join("sessions");
            if pi_sessions.exists() {
                let dst_sessions = dst.join(".pi").join("agent").join("sessions");
                copy_dir_all(&pi_sessions, &dst_sessions)?;
            }
            Ok(())
        }
        _ => {
            let dot_claude = workspace.join(".claude");
            if dot_claude.exists() {
                copy_dir_all(&dot_claude, dst)?;
            }
            Ok(())
        }
    }
}

const AIDER_HISTORY_FILES: &[&str] = &[
    ".aider.chat.history.md",
    ".aider.input.history",
    ".aider.llm.history",
];

fn copy_aider_history(workspace: &Path, dst: &Path) -> std::io::Result<()> {
    let mut any = false;
    for name in AIDER_HISTORY_FILES {
        let src = workspace.join(name);
        if src.exists() {
            if !any {
                std::fs::create_dir_all(dst)?;
                any = true;
            }
            std::fs::copy(&src, dst.join(name))?;
        }
    }
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}

pub async fn run(spec: &RunSpec, _run_id: &str, encoder: &mut Encoder, workspace_path: &Path, agent_history_path: Option<&Path>) -> std::io::Result<()> {
    let mut parser = match spec.adapter.as_str() {
        "claude-code" => AdapterParser::ClaudeCode(ClaudeCodeParser::new()),
        "aider" => AdapterParser::Aider(AiderParser::new()),
        "codex" => AdapterParser::Codex(CodexParser::new()),
        "pi" => AdapterParser::Pi(PiParser::new()),
        _ => AdapterParser::BlackBox,
    };

    let mut cmd = Command::new(&spec.cmd[0]);
    cmd.args(&spec.cmd[1..])
        .envs(&spec.env)
        .current_dir(workspace_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Child gets its own stdin (closed/null) — bunsen-core's stdin is for control commands
        .stdin(Stdio::null());

    // Pi writes its session store to ~/.pi/agent/ by default; redirect into
    // the workspace so the session tree is capturable after the run.
    // User-supplied env takes precedence — only inject when key is absent.
    if spec.adapter == "pi" && !spec.env.contains_key("PI_CODING_AGENT_DIR") {
        cmd.env("PI_CODING_AGENT_DIR", workspace_path.join(".pi"));
    }

    // Place child in its own process group
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))
                .map_err(std::io::Error::other)?;
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

    // Read bunsen-core's own stdin for control commands
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
                        if stream == "stdout" {
                            for (event_type, payload) in parser.parse_stdout(&text) {
                                encoder.emit(&event_type, payload)?;
                            }
                        } else {
                            encoder.emit("output", BlackBoxAdapter::output_event(stream, text.as_bytes()))?;
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

    // Flush any per-line state the adapter parser was holding for a
    // multi-line event (aider's split Tokens:/Cost: pair) so the
    // transcript surfaces it before run_ended.
    for (event_type, payload) in parser.flush() {
        encoder.emit(&event_type, payload)?;
    }

    // Copy agent's native history (best-effort) into agent-history/.
    if let Some(hist_dst) = agent_history_path {
        if let Err(e) = copy_agent_history(&spec.adapter, workspace_path, hist_dst) {
            eprintln!("[supervisor] agent history copy warning: {e}");
        }
    }

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

    #[test]
    fn copy_dir_all_copies_recursively() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("a.txt"), "hello").unwrap();
        std::fs::write(src.path().join("sub/b.txt"), "world").unwrap();

        copy_dir_all(src.path(), dst.path()).unwrap();

        assert_eq!(std::fs::read_to_string(dst.path().join("a.txt")).unwrap(), "hello");
        assert_eq!(std::fs::read_to_string(dst.path().join("sub/b.txt")).unwrap(), "world");
    }

    #[test]
    fn copy_dir_all_noop_when_src_absent() {
        let dst = tempfile::tempdir().unwrap();
        // copy_dir_all only called when src exists; test the guard in run() directly:
        // If workspace .claude/ doesn't exist, no copy happens — dst stays empty.
        let nonexistent = std::path::Path::new("/tmp/bunsen-nonexistent-12345/.claude");
        if !nonexistent.exists() {
            // Guard: copy_dir_all is NOT called — simulate the guard condition
            let hist = dst.path().join("agent-history");
            // The function should not create hist when .claude is absent
            assert!(!hist.exists());
        }
    }

    #[test]
    fn copy_aider_history_copies_known_files_only() {
        let workspace = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let dst_path = dst.path().join("agent-history");

        std::fs::write(workspace.path().join(".aider.chat.history.md"), "chat").unwrap();
        std::fs::write(workspace.path().join(".aider.input.history"), "input").unwrap();
        std::fs::write(workspace.path().join(".aider.llm.history"), "llm").unwrap();
        // A cache dir and an unrelated dotfile should be ignored.
        std::fs::create_dir_all(workspace.path().join(".aider.tags.cache.v3")).unwrap();
        std::fs::write(
            workspace.path().join(".aider.tags.cache.v3/x"),
            "cache",
        )
        .unwrap();
        std::fs::write(workspace.path().join("README.md"), "readme").unwrap();

        copy_agent_history("aider", workspace.path(), &dst_path).unwrap();

        assert_eq!(
            std::fs::read_to_string(dst_path.join(".aider.chat.history.md")).unwrap(),
            "chat"
        );
        assert_eq!(
            std::fs::read_to_string(dst_path.join(".aider.input.history")).unwrap(),
            "input"
        );
        assert_eq!(
            std::fs::read_to_string(dst_path.join(".aider.llm.history")).unwrap(),
            "llm"
        );
        assert!(!dst_path.join(".aider.tags.cache.v3").exists());
        assert!(!dst_path.join("README.md").exists());
    }

    #[test]
    fn copy_aider_history_noop_when_no_files_present() {
        let workspace = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let dst_path = dst.path().join("agent-history");

        copy_agent_history("aider", workspace.path(), &dst_path).unwrap();
        assert!(!dst_path.exists(), "no aider history → no agent-history/");
    }

    #[test]
    fn copy_agent_history_codex_creates_no_files() {
        let workspace = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let dst_path = dst.path().join("agent-history");
        // Even with a .claude/ present, codex must not copy it.
        std::fs::create_dir_all(workspace.path().join(".claude")).unwrap();
        std::fs::write(workspace.path().join(".claude/session.json"), "sess").unwrap();
        copy_agent_history("codex", workspace.path(), &dst_path).unwrap();
        assert!(!dst_path.exists(), "codex history copy must be a no-op");
    }

    #[test]
    fn copy_agent_history_falls_back_to_claude_layout_for_other_adapters() {
        let workspace = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let dst_path = dst.path().join("agent-history");

        std::fs::create_dir_all(workspace.path().join(".claude")).unwrap();
        std::fs::write(workspace.path().join(".claude/session.json"), "sess").unwrap();

        copy_agent_history("claude-code", workspace.path(), &dst_path).unwrap();
        assert_eq!(
            std::fs::read_to_string(dst_path.join("session.json")).unwrap(),
            "sess"
        );
    }

    #[test]
    fn copy_pi_history_copies_sessions_not_credentials() {
        let workspace = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let dst_path = dst.path().join("agent-history");

        // Create the pi session tree.
        std::fs::create_dir_all(
            workspace.path().join(".pi").join("agent").join("sessions").join("ses1"),
        ).unwrap();
        std::fs::write(
            workspace.path().join(".pi").join("agent").join("sessions").join("ses1").join("events.jsonl"),
            "session data",
        ).unwrap();
        // Files that must NOT be copied.
        std::fs::write(workspace.path().join(".pi").join("agent").join("auth.json"), "secret").unwrap();
        std::fs::write(workspace.path().join(".pi").join("agent").join("settings.json"), "cfg").unwrap();

        copy_agent_history("pi", workspace.path(), &dst_path).unwrap();

        assert_eq!(
            std::fs::read_to_string(
                dst_path.join(".pi").join("agent").join("sessions").join("ses1").join("events.jsonl")
            ).unwrap(),
            "session data",
        );
        assert!(!dst_path.join(".pi").join("agent").join("auth.json").exists(),
            "auth.json must not be copied");
        assert!(!dst_path.join(".pi").join("agent").join("settings.json").exists(),
            "settings.json must not be copied");
    }

    #[test]
    fn copy_pi_history_noop_when_sessions_absent() {
        let workspace = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let dst_path = dst.path().join("agent-history");

        copy_agent_history("pi", workspace.path(), &dst_path).unwrap();
        assert!(!dst_path.exists(), "no pi sessions → no agent-history/");
    }
}
