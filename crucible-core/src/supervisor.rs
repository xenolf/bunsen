
use std::path::Path;
use std::process::Stdio;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::adapter::BlackBoxAdapter;
use crate::encoder::Encoder;
use crate::run_spec::RunSpec;

pub async fn run(spec: &RunSpec, _run_id: &str, encoder: &mut Encoder, workspace_path: &Path) -> std::io::Result<()> {
    let mut child = Command::new(&spec.cmd[0])
        .args(&spec.cmd[1..])
        .envs(&spec.env)
        .current_dir(workspace_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Drain stdout and stderr concurrently
    let stdout_task = tokio::spawn(drain_stream(stdout, "stdout"));
    let stderr_task = tokio::spawn(drain_stream(stderr, "stderr"));

    let (stdout_chunks, stderr_chunks) = tokio::join!(stdout_task, stderr_task);

    for (stream, text) in stdout_chunks.unwrap() {
        encoder.emit("output", BlackBoxAdapter::output_event(&stream, text.as_bytes()))?;
    }
    for (stream, text) in stderr_chunks.unwrap() {
        encoder.emit("output", BlackBoxAdapter::output_event(&stream, text.as_bytes()))?;
    }

    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(-1);
    encoder.emit("run_ended", json!({
        "reason": "agent_exit",
        "exit_code": exit_code,
    }))?;

    Ok(())
}

async fn drain_stream<R>(reader: R, stream_name: &'static str) -> Vec<(String, String)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    let mut chunks = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        chunks.push((stream_name.to_string(), line + "\n"));
    }
    chunks
}
