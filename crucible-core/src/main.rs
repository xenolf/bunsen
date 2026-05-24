mod adapter;
mod claude_code_adapter;
mod egress;
mod egress_proxy;
mod encoder;
mod events;
mod oci_cache;
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
mod sandbox_supervisor;
#[cfg(target_os = "linux")]
mod smoke_test;

use events::{SCHEMA_VERSION, CRUCIBLE_VERSION};
use run_dir::{RunDir, MetaJson, ResourceLimits};
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

    let cli = parse_cli_args(&args);

    let spec_json = cli.spec.unwrap_or_else(|| {
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

    let resource_limits = ResourceLimits {
        memory_mb: spec.memory_mb,
        vcpus: spec.vcpus,
        workspace_disk_mb: spec.workspace_disk_mb,
        wall_clock_seconds: spec.wall_clock_seconds,
    };

    let meta = MetaJson {
        run_id: run_id.clone(),
        started_at: started_at.clone(),
        ended_at: None,
        exit_reason: None,
        schema_version: SCHEMA_VERSION,
        crucible_version: CRUCIBLE_VERSION.to_string(),
        parent_run_id: None,
        resource_limits: Some(resource_limits.clone()),
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

    // ── Dispatch: sandbox (Linux + --kernel/--rootfs) or host subprocess ───
    let agent_history_path = run_dir.agent_history_path();
    let result = run_with_backend(cli.kernel, cli.rootfs, cli.firecracker, &spec, &run_id, &mut enc, &workspace_path, Some(&agent_history_path)).await;

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
        resource_limits: Some(resource_limits),
    };
    run_dir.write_meta(&meta).ok();

    if let Err(e) = result {
        eprintln!("supervisor error: {e}");
        std::process::exit(1);
    }
}

async fn run_with_backend(
    kernel: Option<std::path::PathBuf>,
    rootfs: Option<std::path::PathBuf>,
    firecracker_bin: Option<std::path::PathBuf>,
    spec: &run_spec::RunSpec,
    run_id: &str,
    enc: &mut encoder::Encoder,
    workspace_path: &std::path::Path,
    agent_history_path: Option<&std::path::Path>,
) -> std::io::Result<()> {
    // On Linux: use Firecracker when --kernel is provided.
    // Rootfs comes from --rootfs, or is pulled from spec.oci_image on first use.
    #[cfg(target_os = "linux")]
    if let Some(kernel) = kernel {
        let rootfs = match rootfs {
            Some(p) => p,
            None => {
                let oci_ref = spec.oci_image.as_deref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "sandbox mode requires --rootfs or oci-image in spec",
                    )
                })?;
                oci_cache::resolve_rootfs(oci_ref)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:#}")))?
            }
        };
        return run_sandbox(kernel, rootfs, firecracker_bin, spec, run_id, enc, workspace_path).await;
    }
    // On Linux after the if-let: kernel was moved; suppress unused warnings.
    #[cfg(target_os = "linux")]
    let _ = (rootfs, firecracker_bin);

    // On macOS: all three were never consumed.
    #[cfg(not(target_os = "linux"))]
    let _ = (kernel, rootfs, firecracker_bin);

    supervisor::run(spec, run_id, enc, workspace_path, agent_history_path).await
}

#[cfg(target_os = "linux")]
async fn run_sandbox(
    kernel: std::path::PathBuf,
    rootfs: std::path::PathBuf,
    firecracker_bin: Option<std::path::PathBuf>,
    spec: &run_spec::RunSpec,
    run_id: &str,
    enc: &mut encoder::Encoder,
    workspace_path: &std::path::Path,
) -> std::io::Result<()> {
    use firecracker::{create_workspace_ext4_from_dir, extract_workspace_from_ext4, start_firecracker};
    use sandbox::SandboxConfig;

    let fc_bin = firecracker_bin.unwrap_or_else(|| std::path::PathBuf::from("firecracker"));
    let sandbox_spec_json = sandbox::build_sandbox_spec_json(spec);

    let config = SandboxConfig {
        kernel_path: kernel,
        rootfs_path: rootfs,
        workspace_host_path: workspace_path.to_path_buf(),
        spec_json: sandbox_spec_json,
        vcpus: spec.vcpus,
        mem_mib: spec.memory_mb,
        workspace_disk_mib: spec.workspace_disk_mb,
        run_id: run_id.to_string(),
    };

    // Populate workspace ext4 from the materialized workspace directory.
    let workspace_ext4 = std::env::temp_dir()
        .join(format!("crucible-fc-{run_id}"))
        .join("workspace.ext4");
    // The workspace ext4 is created inside start_firecracker; here we just
    // need to ensure the host dir exists so mkfs.ext4 -d can read it.
    // start_firecracker creates the run_dir, so we pass config with the
    // workspace_host_path to signal it to pre-populate.

    let mut handle = start_firecracker(&config, &fc_bin)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:#}")))?;

    let result = sandbox_supervisor::run(&mut handle, spec, enc).await;

    // After VM exits, extract workspace files back to the host path.
    if workspace_ext4.exists() {
        if let Err(e) = extract_workspace_from_ext4(&workspace_ext4, workspace_path).await {
            eprintln!("[fc] workspace extraction warning: {e:#}");
        }
    }

    result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:#}")))
}

struct CliArgs {
    spec: Option<String>,
    kernel: Option<std::path::PathBuf>,
    rootfs: Option<std::path::PathBuf>,
    firecracker: Option<std::path::PathBuf>,
}

fn parse_cli_args(args: &[String]) -> CliArgs {
    let mut spec = None;
    let mut kernel = None;
    let mut rootfs = None;
    let mut firecracker = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--spec" if i + 1 < args.len() => { spec = Some(args[i+1].clone()); i += 2; }
            "--kernel" if i + 1 < args.len() => { kernel = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            "--rootfs" if i + 1 < args.len() => { rootfs = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            "--firecracker" if i + 1 < args.len() => { firecracker = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            other => {
                if let Some(v) = other.strip_prefix("--spec=") { spec = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--kernel=") { kernel = Some(std::path::PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--rootfs=") { rootfs = Some(std::path::PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--firecracker=") { firecracker = Some(std::path::PathBuf::from(v)); }
                i += 1;
            }
        }
    }
    CliArgs { spec, kernel, rootfs, firecracker }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_cli_kernel_rootfs_spec() {
        let args = strs(&["crucible-core", "--kernel", "/vmlinux", "--rootfs", "/rootfs.ext4", "--spec", r#"{"adapter":"black-box","cmd":["echo"]}"#]);
        let cli = parse_cli_args(&args);
        assert_eq!(cli.kernel.unwrap().to_str().unwrap(), "/vmlinux");
        assert_eq!(cli.rootfs.unwrap().to_str().unwrap(), "/rootfs.ext4");
        assert!(cli.spec.is_some());
        assert!(cli.firecracker.is_none());
    }

    #[test]
    fn parse_cli_firecracker_optional() {
        let args = strs(&["crucible-core", "--kernel", "/k", "--rootfs", "/r", "--firecracker", "/fc", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert_eq!(cli.firecracker.unwrap().to_str().unwrap(), "/fc");
    }

    #[test]
    fn parse_cli_no_sandbox_flags() {
        let args = strs(&["crucible-core", "--spec", r#"{"adapter":"black-box","cmd":["echo"]}"#]);
        let cli = parse_cli_args(&args);
        assert!(cli.kernel.is_none());
        assert!(cli.rootfs.is_none());
        assert!(cli.spec.is_some());
    }
}
