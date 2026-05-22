mod adapter;
mod encoder;
mod events;
mod redactor;
mod run_dir;
mod run_spec;
mod sandbox;
mod supervisor;
mod ulid;
mod workspace_materializer;

#[cfg(target_os = "linux")]
mod firecracker;
#[cfg(target_os = "linux")]
mod smoke_test;

use events::{SCHEMA_VERSION, CRUCIBLE_VERSION};
use run_dir::{RunDir, MetaJson};
use serde_json::json;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Subcommand dispatch.
    if args.get(1).map(|s| s.as_str()) == Some("sandbox-smoke-test") {
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = smoke_test::run(&args[2..]).await {
                eprintln!("smoke-test failed: {e:#}");
                std::process::exit(1);
            }
            return;
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("sandbox-smoke-test: Linux + KVM required");
            std::process::exit(1);
        }
    }

    let spec_json = parse_spec_arg(&args).unwrap_or_else(|| {
        eprintln!("usage: crucible-core --spec <json>");
        std::process::exit(1);
    });

    let spec = run_spec::RunSpec::from_json(&spec_json).unwrap_or_else(|e| {
        eprintln!("invalid spec: {e}");
        std::process::exit(1);
    });

    let run_id = ulid::generate();
    eprintln!("{run_id}");

    let run_dir = RunDir::create(&run_id).unwrap_or_else(|e| {
        eprintln!("failed to create run dir: {e}");
        std::process::exit(1);
    });

    run_dir.write_spec(&spec_json).ok();

    let workspace_path = run_dir.workspace_path();
    workspace_materializer::materialize(
        spec.branching_strategy.as_deref(),
        spec.host_repo_path.as_deref(),
        &workspace_path,
        &run_id,
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("failed to materialize workspace: {e}");
        std::process::exit(1);
    });

    let started_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let meta = MetaJson {
        run_id: run_id.clone(),
        started_at: started_at.clone(),
        ended_at: None,
        exit_reason: None,
        schema_version: SCHEMA_VERSION,
        crucible_version: CRUCIBLE_VERSION.to_string(),
        parent_run_id: None,
    };
    run_dir.write_meta(&meta).ok();

    let redactor = if spec.secrets.is_empty() {
        None
    } else {
        Some(
            redactor::Redactor::new(spec.secrets.clone()).unwrap_or_else(|e| {
                eprintln!("invalid secrets: {e}");
                std::process::exit(1);
            }),
        )
    };

    let mut enc = encoder::Encoder::new(&run_id, &run_dir.transcript_path(), redactor)
        .unwrap_or_else(|e| {
            eprintln!("failed to open transcript: {e}");
            std::process::exit(1);
        });

    let workspace_path_str = workspace_path.to_string_lossy().into_owned();
    let transcript_path = run_dir.transcript_path().to_string_lossy().into_owned();

    enc.emit("run_started", json!({
        "adapter": spec.adapter,
        "workspace_path": workspace_path_str,
        "transcript_path": transcript_path,
    })).unwrap();

    let result = supervisor::run(&spec, &run_id, &mut enc, &workspace_path).await;

    let ended_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let exit_reason = if result.is_ok() { "agent_exit" } else { "supervisor_error" };

    let meta = MetaJson {
        run_id: run_id.clone(),
        started_at,
        ended_at: Some(ended_at),
        exit_reason: Some(exit_reason.to_string()),
        schema_version: SCHEMA_VERSION,
        crucible_version: CRUCIBLE_VERSION.to_string(),
        parent_run_id: None,
    };
    run_dir.write_meta(&meta).ok();

    if let Err(e) = result {
        eprintln!("supervisor error: {e}");
        std::process::exit(1);
    }
}

fn parse_spec_arg(args: &[String]) -> Option<String> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--spec" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(v) = args[i].strip_prefix("--spec=") {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
}
