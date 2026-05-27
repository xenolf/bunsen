mod adapter;
mod aider_adapter;
mod branch_pool;
mod claude_code_adapter;
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
mod ulid;
mod workspace_materializer;

#[cfg(target_os = "linux")]
mod firecracker;
#[cfg(target_os = "linux")]
mod firewall;
#[cfg(target_os = "linux")]
mod sandbox_run;
#[cfg(target_os = "linux")]
mod sandbox_supervisor;
#[cfg(target_os = "linux")]
mod smoke_test;

use events::{SCHEMA_VERSION, BUNSEN_VERSION};
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

    // Slice 11: `session` subcommand surface — User-Script-facing verbs that
    // wrap the Rust [`Session`] API. Each subcommand prints JSON on stdout
    // for parseability from the Python wrappers.
    if args.get(1).map(|s| s.as_str()) == Some("session") {
        std::process::exit(session_cli::run(&args[2..]).await);
    }

    let cli = parse_cli_args(&args);

    let spec_json = cli.spec.unwrap_or_else(|| {
        eprintln!("usage: bunsen-core --spec <json>");
        std::process::exit(1);
    });

    let spec = run_spec::RunSpec::from_json(&spec_json).unwrap_or_else(|e| {
        eprintln!("invalid spec: {e}");
        std::process::exit(1);
    });

    // Slice 11: `bunsen-core --session <id> --spec <json>` ties a Run to an
    // existing Session and drives it through [`Session::run`]/[`Session::run_with_backend`],
    // which own workspace materialisation, supervisor dispatch, and (when a
    // kernel was supplied) Firecracker sandbox dispatch with Pool extraction.
    // Slice 12 adds the kernel/rootfs flags to the session path so the
    // sandbox can be used per-Session, not just from the pre-Session legacy
    // CLI.
    if let Some(sid) = cli.session_id.clone() {
        let mut sess = match session::Session::attach(&sid) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("session attach {sid:?} failed: {e}");
                std::process::exit(1);
            }
        };
        // Lazy kernel + OCI-rootfs resolution now lives inside
        // `Session::run_with_backend` so any Session caller (CLI or Python)
        // gets the same behaviour without duplicating the logic. The CLI
        // just forwards its flags as RunBackend overrides; an absent
        // `--kernel` + `spec.oci_image` set will lazy-fetch correctly.
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
    // On Linux, when sandbox mode is intended but the user didn't pass an
    // explicit `--kernel /path`, fetch the pinned Firecracker-CI vmlinux
    // (lazy on first call, cached afterwards). Side-effecting work — run_dir
    // creation, transcript open, run_started emission — happens *after* this
    // step so a download/SHA failure surfaces as a clean top-level error
    // rather than partway through a Run.
    //
    // The trigger for "sandbox is intended" is `--rootfs` or `spec.oci_image`.
    // Without either we have nothing to boot, so we fall through to the
    // host-subprocess path and don't waste a kernel fetch.
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

    // ── Slice 10k: host firewall probe ────────────────────────────────────
    // Probe BEFORE we touch the run_dir, transcript, or emit run_started so
    // that an aborted probe leaves zero side effects on the host. Only runs
    // on Linux when we'll enter sandbox mode (kernel resolved); macOS and
    // host-subprocess paths don't share a kernel with the L7 proxy and have
    // nothing to probe.
    #[cfg(target_os = "linux")]
    if resolved_kernel.is_some() {
        if let Err(msg) = check_host_firewall(cli.manage_firewall).await {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }

    let run_id = ulid::generate();
    eprintln!("{run_id}");

    // Slice 08: Run dirs nest under their owning Session at
    // sessions/<id>/runs/<run-id>/. The CLI doesn't yet have a Session
    // (slice 11 wires `bunsen run --session <id>`), so until then we
    // synthesize a `__cli__` session dir under the sessions root. The
    // synthetic id has no meta.json, so Session::list silently ignores
    // it — no risk of it surfacing as a real Session.
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

    // Workspace materialisation runs inside Session::run starting at slice 09.
    // The CLI path (bunsen-core --spec ...) doesn't yet have a Session, so the
    // workspace stays empty here — the adapter is responsible for whatever
    // host-side state it needs until that wiring lands. We allocate it as a
    // sibling of the Run dir (not a child) so that nothing downstream relies
    // on the removed `RunDir::workspace_path()` accessor.
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

    // ── Dispatch: sandbox (Linux + --kernel/--rootfs) or host subprocess ───
    let agent_history_path = run_dir.agent_history_path();
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
                    .map_err(|e| std::io::Error::other(format!("{e:#}")))?
            }
        };
        return run_sandbox(kernel, rootfs, firecracker_bin, manage_firewall, spec, run_id, enc, workspace_path).await;
    }
    // On Linux after the if-let: kernel was moved; suppress unused warnings.
    #[cfg(target_os = "linux")]
    let _ = (rootfs, firecracker_bin, manage_firewall);

    // On macOS: all three were never consumed.
    #[cfg(not(target_os = "linux"))]
    let _ = (kernel, rootfs, firecracker_bin, manage_firewall);

    supervisor::run(spec, run_id, enc, workspace_path, agent_history_path).await
}

/// Probe the host iptables INPUT chain and decide whether to proceed.
///
/// On Linux + sandbox mode, called BEFORE any side-effecting host work
/// (run_dir creation, workspace materialization, encoder open). The
/// acceptance criterion is "produces no run_started events on Blocked":
/// running the probe at the top of main() makes that automatic.
///
/// Returns:
/// - `Ok(())` — proceed. Either iptables is absent, the INPUT chain is
///   ACCEPT-by-default, a covering rule already exists, or the user passed
///   `--manage-firewall` and authorized us to install one ourselves later.
/// - `Err(msg)` — the caller should print `msg` to stderr and exit non-zero.
#[cfg(target_os = "linux")]
async fn check_host_firewall(manage_firewall: bool) -> Result<(), String> {
    use firewall_check::{parse_iptables_save, Decision};

    let probe = match firewall::probe_iptables().await {
        Ok(Some(stdout)) => parse_iptables_save(&stdout),
        Ok(None) => Decision::Permissive,
        Err(e) => {
            // Probe failed but iptables exists. Most likely cause is running
            // unprivileged. We can't see the rules and we couldn't add one
            // either, so warn and treat as permissive — the L3 nft path
            // is the actual security boundary, and if the host firewall is
            // dropping us the user will see the timeout symptom and re-run
            // with --manage-firewall.
            eprintln!(
                "[firewall] WARNING: failed to probe iptables: {e:#} \
                 — proceeding without firewall management"
            );
            Decision::Permissive
        }
    };

    if matches!(probe, Decision::Blocked) && !manage_firewall {
        return Err(
            "[bunsen-core] ERROR: host iptables INPUT policy is DROP and no allow rule covers \
             169.254.0.0/16, so the sandbox's L7 proxy will be unreachable from the guest. \
             Re-run with --manage-firewall (Python: manage_firewall=True) to let bunsen add \
             a per-TAP allow rule for the lifetime of this Run, or open the link-local range \
             manually: sudo ufw allow from 169.254.0.0/16".to_string()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_sandbox(
    kernel: std::path::PathBuf,
    rootfs: std::path::PathBuf,
    firecracker_bin: Option<std::path::PathBuf>,
    manage_firewall: bool,
    spec: &run_spec::RunSpec,
    run_id: &str,
    enc: &mut encoder::Encoder,
    workspace_path: &std::path::Path,
) -> std::io::Result<()> {
    // The full Firecracker lifecycle lives in `sandbox_run` so that the CLI
    // (this caller) and `Session::run_with_backend` share one implementation.
    // The CLI's legacy path does not extract into a Pool — workspace state
    // dies at VM exit, matching ADR-0010 — so `extraction` is `None`.
    sandbox_run::run(
        kernel,
        rootfs,
        firecracker_bin,
        manage_firewall,
        spec,
        run_id,
        enc,
        workspace_path,
        None,
    )
    .await
}

struct CliArgs {
    spec: Option<String>,
    kernel: Option<std::path::PathBuf>,
    rootfs: Option<std::path::PathBuf>,
    firecracker: Option<std::path::PathBuf>,
    manage_firewall: bool,
    /// Slice 11: tie the Run to a Session by ULID. When set, Session::run
    /// drives the Run end-to-end (materialise from Pool → run agent →
    /// extract back into Pool). Without it, the legacy CLI path keeps the
    /// pre-Session behaviour for backwards compatibility.
    session_id: Option<String>,
}

/// Transitional sessions-root subdir for CLI invocations. Used until
/// slice 11 wires `bunsen run --session <id>`. Carries no `meta.json`,
/// so `Session::list` ignores it.
fn cli_session_dir() -> std::path::PathBuf {
    xdg_data_home()
        .join("bunsen")
        .join("sessions")
        .join("__cli__")
}

fn xdg_data_home() -> std::path::PathBuf {
    if let Ok(v) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(v)
    } else {
        std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"))
            .join(".local")
            .join("share")
    }
}

fn parse_cli_args(args: &[String]) -> CliArgs {
    let mut spec = None;
    let mut kernel = None;
    let mut rootfs = None;
    let mut firecracker = None;
    let mut manage_firewall = false;
    let mut session_id: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--spec" if i + 1 < args.len() => { spec = Some(args[i+1].clone()); i += 2; }
            "--kernel" if i + 1 < args.len() => { kernel = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            "--rootfs" if i + 1 < args.len() => { rootfs = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            "--firecracker" if i + 1 < args.len() => { firecracker = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            "--session" if i + 1 < args.len() => { session_id = Some(args[i+1].clone()); i += 2; }
            "--manage-firewall" => { manage_firewall = true; i += 1; }
            other => {
                if let Some(v) = other.strip_prefix("--spec=") { spec = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--kernel=") { kernel = Some(std::path::PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--rootfs=") { rootfs = Some(std::path::PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--firecracker=") { firecracker = Some(std::path::PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--session=") { session_id = Some(v.to_string()); }
                i += 1;
            }
        }
    }
    CliArgs { spec, kernel, rootfs, firecracker, manage_firewall, session_id }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_cli_kernel_rootfs_spec() {
        let args = strs(&["bunsen-core", "--kernel", "/vmlinux", "--rootfs", "/rootfs.ext4", "--spec", r#"{"adapter":"black-box","cmd":["echo"]}"#]);
        let cli = parse_cli_args(&args);
        assert_eq!(cli.kernel.unwrap().to_str().unwrap(), "/vmlinux");
        assert_eq!(cli.rootfs.unwrap().to_str().unwrap(), "/rootfs.ext4");
        assert!(cli.spec.is_some());
        assert!(cli.firecracker.is_none());
    }

    #[test]
    fn parse_cli_firecracker_optional() {
        let args = strs(&["bunsen-core", "--kernel", "/k", "--rootfs", "/r", "--firecracker", "/fc", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert_eq!(cli.firecracker.unwrap().to_str().unwrap(), "/fc");
    }

    #[test]
    fn parse_cli_no_sandbox_flags() {
        let args = strs(&["bunsen-core", "--spec", r#"{"adapter":"black-box","cmd":["echo"]}"#]);
        let cli = parse_cli_args(&args);
        assert!(cli.kernel.is_none());
        assert!(cli.rootfs.is_none());
        assert!(cli.spec.is_some());
        assert!(!cli.manage_firewall);
    }

    #[test]
    fn parse_cli_manage_firewall_flag() {
        let args = strs(&["bunsen-core", "--manage-firewall", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert!(cli.manage_firewall);
        assert!(cli.spec.is_some());
    }

    #[test]
    fn parse_cli_manage_firewall_default_false() {
        let args = strs(&["bunsen-core", "--kernel", "/k", "--rootfs", "/r", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert!(!cli.manage_firewall);
    }

    #[test]
    fn parse_cli_session_flag_space_form() {
        let args = strs(&["bunsen-core", "--session", "01HSESSION0000000000000000", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert_eq!(cli.session_id.as_deref(), Some("01HSESSION0000000000000000"));
    }

    #[test]
    fn parse_cli_session_flag_equals_form() {
        let args = strs(&["bunsen-core", "--session=01HSESSION0000000000000000", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert_eq!(cli.session_id.as_deref(), Some("01HSESSION0000000000000000"));
    }

    #[test]
    fn parse_cli_session_default_none() {
        let args = strs(&["bunsen-core", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert!(cli.session_id.is_none());
    }

    /// Slice 12 (Firecracker dispatch through Session::run): the
    /// `--session <id> --kernel <p> --rootfs <p>` argument set parses as a
    /// single CLI call so the binary can route the Run through
    /// `Session::run_with_backend` with a sandbox-shaped RunBackend.
    #[test]
    fn parse_cli_session_with_kernel_and_rootfs() {
        let args = strs(&[
            "bunsen-core",
            "--session",
            "01HSESSION0000000000000000",
            "--kernel",
            "/vmlinux",
            "--rootfs",
            "/rootfs.ext4",
            "--spec",
            "{}",
        ]);
        let cli = parse_cli_args(&args);
        assert_eq!(cli.session_id.as_deref(), Some("01HSESSION0000000000000000"));
        assert_eq!(cli.kernel.unwrap().to_str().unwrap(), "/vmlinux");
        assert_eq!(cli.rootfs.unwrap().to_str().unwrap(), "/rootfs.ext4");
        assert!(cli.spec.is_some());
    }
}
