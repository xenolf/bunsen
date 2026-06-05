mod adapter;
mod aider_adapter;
mod branch_pool;
mod bunsen_paths;
mod claude_code_adapter;
mod codex_adapter;
mod pi_adapter;
mod dns;
mod egress;
mod egress_proxy;
mod encoder;
mod events;
mod firewall_check;
mod kernel;
mod oci_cache;
mod redactor;
mod run_dir;
mod run_spec;
mod sandbox;
mod sandbox_fetch;
mod sandbox_net;
mod sandbox_nft;
mod session;
mod session_cli;
mod supervisor;
mod target_user;
mod ulid;
mod workspace_materializer;

#[cfg(target_os = "linux")]
mod firecracker;
#[cfg(target_os = "linux")]
mod firewall;
mod privileged_net;
#[cfg(target_os = "linux")]
mod sandbox_run;
#[cfg(target_os = "linux")]
mod sandbox_supervisor;
#[cfg(target_os = "linux")]
mod smoke_test;

use clap::{Args, Parser, Subcommand};
use events::{SCHEMA_VERSION, BUNSEN_VERSION};
use run_dir::{RunDir, MetaJson, ResourceLimits};
use serde_json::json;

#[derive(Parser)]
#[command(name = "bunsen-core")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run(RunArgs),
    Session(session_cli::SessionArgs),
    SandboxSmokeTest(SandboxSmokeTestArgs),
}

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    spec: String,
    #[arg(long)]
    kernel: Option<std::path::PathBuf>,
    #[arg(long)]
    rootfs: Option<std::path::PathBuf>,
    #[arg(long)]
    firecracker: Option<std::path::PathBuf>,
    #[arg(long)]
    session: Option<String>,
    #[arg(long)]
    manage_firewall: bool,
    /// Account to resolve data/cache paths against (and, once the privilege
    /// drop lands, to drop to). Mirrors `session --as-user`. When omitted under
    /// `sudo`, the account is taken from `SUDO_USER`/`SUDO_UID`.
    #[arg(long)]
    as_user: Option<String>,
}

#[derive(Args)]
struct SandboxSmokeTestArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::SandboxSmokeTest(args) => {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = smoke_test::run(&args.args).await {
                    eprintln!("smoke-test failed: {e:#}");
                    std::process::exit(1);
                }
                return;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                eprintln!("sandbox-smoke-test: Linux + KVM required");
                std::process::exit(1);
            }
        }

        Command::Session(args) => {
            std::process::exit(session_cli::run(args).await);
        }

        Command::Run(cli) => run_main(cli).await,
    }
}

async fn run_main(cli: RunArgs) {
    let spec_json = cli.spec.clone();

    let spec = run_spec::RunSpec::from_json(&spec_json).unwrap_or_else(|e| {
        eprintln!("invalid spec: {e}");
        std::process::exit(1);
    });

    // ── User Script user resolution (sudo / privilege model) ───────────────
    // `session open` resolves the target account from `--as-user`/`SUDO_*` and
    // rewrites HOME/XDG before writing the Session to disk (see
    // `target_user::resolve_and_drop`). The run path must perform the SAME path
    // resolution, or attaching to that Session looks under root's home and
    // fails with "session not found". We apply only the environment fix-up
    // here, NOT the uid/gid drop: the per-Run network + Firecracker setup still
    // needs root. The actual drop is the pending privilege arc (see the
    // `owner_user` note in `session.rs::dispatch`).
    match target_user::resolve(
        &target_user::inputs_from_process(cli.as_user.clone()),
        &target_user::RealSystemContext,
    ) {
        Ok(target_user::ResolutionOutcome::Drop(user)) => target_user::apply_env_fixup(&user),
        Ok(target_user::ResolutionOutcome::NoDrop) => {}
        Err(e) => {
            eprintln!("[bunsen-core] target-user resolution failed: {e}");
            std::process::exit(1);
        }
    }

    if let Some(sid) = cli.session.clone() {
        let mut sess = match session::Session::attach(&sid) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("session attach {sid:?} failed: {e}");
                std::process::exit(1);
            }
        };
        let backend = session::RunBackend {
            kernel: cli.kernel.clone(),
            rootfs: cli.rootfs.clone(),
            firecracker_bin: cli.firecracker.clone(),
            manage_firewall: cli.manage_firewall,
        };
        match sess.run_with_backend(spec, backend).await {
            Ok(res) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "run_id": res.run_id,
                        "pool_sha": res.pool_sha,
                        "output_branch_pushed": res.output_branch_pushed,
                        "uncommitted_paths": res.uncommitted_paths,
                    })
                );
                return;
            }
            Err(e) => {
                eprintln!("session run failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // ── Slice 02 (v1.1): lazy kernel resolve ──────────────────────────────
    #[cfg(target_os = "linux")]
    let resolved_kernel: Option<std::path::PathBuf> = if let Some(k) = cli.kernel.clone() {
        Some(k)
    } else if spec.oci_image.is_some() || cli.rootfs.is_some() {
        match kernel::ensure_kernel().await {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("[bunsen-core] failed to acquire guest kernel: {e:#}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let resolved_kernel: Option<std::path::PathBuf> = cli.kernel.clone();

    // ── PrivilegedNet actor ───────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    let actor = privileged_net::start_actor();

    // ── Slice 10k: host firewall probe ────────────────────────────────────
    #[cfg(target_os = "linux")]
    if resolved_kernel.is_some() {
        if let Err(msg) = firewall::enforce_host_firewall_policy(cli.manage_firewall, &actor).await {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }

    let run_id = ulid::generate();
    eprintln!("{run_id}");

    let session_path = cli_session_dir();
    if let Err(e) = std::fs::create_dir_all(&session_path) {
        eprintln!("failed to create cli session dir: {e}");
        std::process::exit(1);
    }
    let run_dir = RunDir::create(&session_path, &run_id).unwrap_or_else(|e| {
        eprintln!("failed to create run dir: {e}");
        std::process::exit(1);
    });

    run_dir.write_spec(&spec_json).ok();

    let workspace_path = run_dir.path.join("workspace");
    if let Err(e) = std::fs::create_dir_all(&workspace_path) {
        eprintln!("failed to create workspace dir: {e}");
        std::process::exit(1);
    }

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
        bunsen_version: BUNSEN_VERSION.to_string(),
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

    let agent_history_path = run_dir.agent_history_path();
    #[cfg(target_os = "linux")]
    let result = run_with_backend(resolved_kernel, cli.rootfs, cli.firecracker, cli.manage_firewall, &spec, &run_id, &mut enc, &workspace_path, Some(&agent_history_path), &actor).await;
    #[cfg(not(target_os = "linux"))]
    let result = run_with_backend(resolved_kernel, cli.rootfs, cli.firecracker, cli.manage_firewall, &spec, &run_id, &mut enc, &workspace_path, Some(&agent_history_path)).await;

    let ended_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let exit_reason = if result.is_ok() { "agent_exit" } else { "supervisor_error" };

    let meta = MetaJson {
        run_id: run_id.clone(),
        started_at,
        ended_at: Some(ended_at),
        exit_reason: Some(exit_reason.to_string()),
        schema_version: SCHEMA_VERSION,
        bunsen_version: BUNSEN_VERSION.to_string(),
        parent_run_id: None,
        resource_limits: Some(resource_limits),
    };
    run_dir.write_meta(&meta).ok();

    if let Err(e) = result {
        eprintln!("supervisor error: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn run_with_backend(
    kernel: Option<std::path::PathBuf>,
    rootfs: Option<std::path::PathBuf>,
    firecracker_bin: Option<std::path::PathBuf>,
    manage_firewall: bool,
    spec: &run_spec::RunSpec,
    run_id: &str,
    enc: &mut encoder::Encoder,
    workspace_path: &std::path::Path,
    agent_history_path: Option<&std::path::Path>,
    actor: &privileged_net::PrivilegedNetHandle,
) -> std::io::Result<()> {
    if let Some(kernel) = kernel {
        let rootfs = match rootfs {
            Some(p) => p,
            None => {
                let oci_ref = spec
                    .oci_image
                    .as_deref()
                    .unwrap_or(oci_cache::DEFAULT_ROOTFS_IMAGE);
                oci_cache::resolve_rootfs(oci_ref)
                    .await
                    .map_err(|e| std::io::Error::other(format!("{e:#}")))?
            }
        };
        let owner_user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| "root".to_string());
        return sandbox_run::run(
            kernel,
            rootfs,
            firecracker_bin,
            manage_firewall,
            spec,
            run_id,
            enc,
            workspace_path,
            None,
            actor,
            &owner_user,
        )
        .await;
    }
    let _ = (rootfs, firecracker_bin, manage_firewall);
    supervisor::run(spec, run_id, enc, workspace_path, agent_history_path).await
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
async fn run_with_backend(
    kernel: Option<std::path::PathBuf>,
    rootfs: Option<std::path::PathBuf>,
    firecracker_bin: Option<std::path::PathBuf>,
    manage_firewall: bool,
    spec: &run_spec::RunSpec,
    run_id: &str,
    enc: &mut encoder::Encoder,
    workspace_path: &std::path::Path,
    agent_history_path: Option<&std::path::Path>,
) -> std::io::Result<()> {
    let _ = (kernel, rootfs, firecracker_bin, manage_firewall);
    supervisor::run(spec, run_id, enc, workspace_path, agent_history_path).await
}

/// Transitional sessions-root subdir for CLI invocations without a Session.
/// Carries no `meta.json`, so `Session::list` ignores it.
fn cli_session_dir() -> std::path::PathBuf {
    bunsen_paths::sessions_root().join("__cli__")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_run_kernel_rootfs_spec() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "run",
            "--kernel", "/vmlinux",
            "--rootfs", "/rootfs.ext4",
            "--spec", r#"{"adapter":"black-box","cmd":["echo"]}"#,
        ]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert_eq!(args.kernel.unwrap().to_str().unwrap(), "/vmlinux");
        assert_eq!(args.rootfs.unwrap().to_str().unwrap(), "/rootfs.ext4");
        assert!(!args.spec.is_empty());
        assert!(args.firecracker.is_none());
    }

    #[test]
    fn parse_run_firecracker_optional() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "run",
            "--kernel", "/k",
            "--rootfs", "/r",
            "--firecracker", "/fc",
            "--spec", "{}",
        ]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert_eq!(args.firecracker.unwrap().to_str().unwrap(), "/fc");
    }

    #[test]
    fn parse_run_no_sandbox_flags() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "run",
            "--spec", r#"{"adapter":"black-box","cmd":["echo"]}"#,
        ]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert!(args.kernel.is_none());
        assert!(args.rootfs.is_none());
        assert!(!args.spec.is_empty());
        assert!(!args.manage_firewall);
    }

    #[test]
    fn parse_run_manage_firewall_flag() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "run",
            "--manage-firewall",
            "--spec", "{}",
        ]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert!(args.manage_firewall);
    }

    #[test]
    fn parse_run_manage_firewall_default_false() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "run",
            "--kernel", "/k",
            "--rootfs", "/r",
            "--spec", "{}",
        ]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert!(!args.manage_firewall);
    }

    #[test]
    fn parse_run_session_flag() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "run",
            "--session", "01HSESSION0000000000000000",
            "--spec", "{}",
        ]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert_eq!(args.session.as_deref(), Some("01HSESSION0000000000000000"));
    }

    #[test]
    fn parse_run_session_default_none() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "run",
            "--spec", "{}",
        ]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert!(args.session.is_none());
    }

    #[test]
    fn parse_run_session_with_kernel_and_rootfs() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "run",
            "--session", "01HSESSION0000000000000000",
            "--kernel", "/vmlinux",
            "--rootfs", "/rootfs.ext4",
            "--spec", "{}",
        ]).unwrap();
        let Command::Run(args) = cli.command else { panic!("expected Run") };
        assert_eq!(args.session.as_deref(), Some("01HSESSION0000000000000000"));
        assert_eq!(args.kernel.unwrap().to_str().unwrap(), "/vmlinux");
        assert_eq!(args.rootfs.unwrap().to_str().unwrap(), "/rootfs.ext4");
    }

    #[test]
    fn parse_session_as_user() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "session",
            "--as-user", "alice",
            "list",
        ]).unwrap();
        let Command::Session(args) = cli.command else { panic!("expected Session") };
        assert_eq!(args.as_user.as_deref(), Some("alice"));
    }

    #[test]
    fn parse_session_as_user_absent() {
        let cli = Cli::try_parse_from(&[
            "bunsen-core", "session",
            "list",
        ]).unwrap();
        let Command::Session(args) = cli.command else { panic!("expected Session") };
        assert!(args.as_user.is_none());
    }
}
