mod adapter;
mod claude_code_adapter;
mod dns;
mod egress;
mod egress_proxy;
mod encoder;
mod events;
mod firewall_check;
mod oci_cache;
mod redactor;
mod run_dir;
mod run_spec;
mod sandbox;
mod sandbox_net;
mod sandbox_nft;
mod supervisor;
mod ulid;
mod workspace_materializer;

#[cfg(target_os = "linux")]
mod firecracker;
#[cfg(target_os = "linux")]
mod firewall;
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

    // ── Slice 10k: host firewall probe ────────────────────────────────────
    // Probe BEFORE we touch the run_dir, transcript, or emit run_started so
    // that an aborted probe leaves zero side effects on the host. Only runs
    // on Linux in sandbox mode (--kernel provided); macOS and host-subprocess
    // paths don't share a kernel with the L7 proxy and have nothing to probe.
    #[cfg(target_os = "linux")]
    if cli.kernel.is_some() {
        if let Err(msg) = check_host_firewall(cli.manage_firewall).await {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }

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
    let result = run_with_backend(cli.kernel, cli.rootfs, cli.firecracker, cli.manage_firewall, &spec, &run_id, &mut enc, &workspace_path, Some(&agent_history_path)).await;

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
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:#}")))?
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
            "[crucible-core] ERROR: host iptables INPUT policy is DROP and no allow rule covers \
             169.254.0.0/16, so the sandbox's L7 proxy will be unreachable from the guest. \
             Re-run with --manage-firewall (Python: manage_firewall=True) to let crucible add \
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
    use firecracker::{
        apply_nftables_ruleset, create_tap, delete_nftables_table, delete_tap,
        extract_workspace_from_ext4, spawn_drop_log_emitter, start_firecracker,
    };
    use sandbox::SandboxConfig;
    use sandbox_net::{derive_run_network, derive_tap_name};
    use sandbox_nft::{build_ruleset, derive_table_name};
    use sandbox_supervisor::EgressContext;
    use std::net::SocketAddr;

    let fc_bin = firecracker_bin.unwrap_or_else(|| std::path::PathBuf::from("firecracker"));

    // ── Per-Run network ────────────────────────────────────────────────────
    // Derive the /30 IPv4 pair and TAP name from the run_id, then create the
    // TAP and assign its host-side address. The L7 proxy will bind on that
    // address (slice 10f) so the TAP must be up first. Any leftover TAP from
    // a previous crashed Run with the same id is removed defensively — this
    // mirrors the pre-cleanup behavior start_firecracker used to do.
    let net = derive_run_network(run_id);
    let tap_name = derive_tap_name(run_id);
    let _ = delete_tap(&tap_name).await;
    eprintln!(
        "[fc] creating TAP device {tap_name} (host {host}/{prefix}, guest {guest})",
        host = net.host,
        prefix = net.prefix_len,
        guest = net.guest,
    );
    create_tap(&tap_name, net.host, net.prefix_len)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:#}")))?;

    // ── Slice 10k: host iptables co-existence ─────────────────────────────
    // The pre-flight probe in main() already decided whether we can proceed.
    // If the caller passed --manage-firewall we install the per-TAP allow
    // rule unconditionally (idempotent pre-cleanup first, in case a previous
    // Run with the same tap_name crashed before its guard ran). The
    // TapAllowGuard removes the rule via std::process::Command on Drop —
    // synchronous so cleanup runs reliably on panic and during runtime
    // shutdown. Holding the guard in run_sandbox's local scope ties its
    // lifetime to the Run.
    let _firewall_guard = if manage_firewall {
        let _ = firewall::remove_tap_allow(&tap_name).await;
        firewall::add_tap_allow(&tap_name)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:#}")))?;
        eprintln!("[firewall] installed per-TAP allow rule for {tap_name}");
        Some(firewall::TapAllowGuard::new(tap_name.clone()))
    } else {
        None
    };

    // ── L7 egress proxy ────────────────────────────────────────────────────
    // Bind the proxy on the TAP host IP (port 0 → kernel-assigned) so the
    // address injected as HTTP_PROXY / HTTPS_PROXY is reachable from inside
    // the guest once eth0 comes up. Bind happens before build_sandbox_spec_json
    // so the bound SocketAddr flows into the env. Listener-bind failure
    // remains non-fatal here: a follow-up slice adds L3 nftables that make
    // proxy presence load-bearing.
    let policy = spec.effective_egress_policy();
    let (denied_tx, denied_rx) = tokio::sync::mpsc::unbounded_channel();
    // Keep a sender clone for the L3 drop-log task (spawned below). The proxy
    // takes its own clone; once both producers exit, the supervisor's
    // `denied_rx.recv()` returns None and the select arm flips off.
    let drop_log_tx = denied_tx.clone();
    let proxy_bind: SocketAddr = SocketAddr::from((net.host, 0));
    let (proxy_addr, proxy_handle) = match egress_proxy::spawn_listener(
        proxy_bind,
        policy,
        denied_tx,
    )
    .await
    {
        Ok((addr, h)) => {
            eprintln!("[egress] L7 proxy listening on {addr}");
            (Some(addr), Some(h))
        }
        Err(e) => {
            eprintln!("[egress] failed to start proxy listener: {e}");
            (None, None)
        }
    };

    // ── L3 egress enforcement (nftables) ───────────────────────────────────
    // Default-deny on the TAP — only TCP to the L7 proxy address is allowed.
    // Drops are logged with a per-Run prefix so a follow-up slice can emit
    // egress_denied(protocol=raw_tcp) events from the kernel log. Only loaded
    // when the proxy actually bound: without a proxy address there is no
    // safe rule to allow, so loading the table here would render the guest
    // completely offline (matches "fail-closed" intent but is too aggressive
    // until the proxy is treated as mandatory in a later slice).
    let nft_table = derive_table_name(run_id);
    // Defensive: clean up any leftover table from a previous crashed Run
    // with the same id before reloading.
    let _ = delete_nftables_table(&nft_table).await;
    let mut nft_loaded = false;
    if let Some(addr) = proxy_addr {
        let rules = build_ruleset(&nft_table, &tap_name, net.host, addr.port());
        eprintln!("[egress] loading nftables table {nft_table}");
        match apply_nftables_ruleset(&rules).await {
            Ok(()) => nft_loaded = true,
            Err(e) => {
                eprintln!("[egress] WARNING: failed to load L3 nftables rules: {e:#}");
            }
        }
    } else {
        eprintln!(
            "[egress] proxy not bound — skipping L3 nftables rules (no enforcement this Run)"
        );
    }

    // ── L3 drop-log side-channel ──────────────────────────────────────────
    // Tail `journalctl -k -f` and forward drops whose table matches this
    // Run's nft table as DenialEvents on the same channel the L7 proxy uses,
    // so the supervisor's existing select-arm emits them uniformly as
    // `egress_denied(protocol=raw_tcp)`. Only started when the ruleset
    // actually loaded — without rules, the kernel has nothing to log.
    let drop_log_handle = if nft_loaded {
        match spawn_drop_log_emitter(nft_table.clone(), drop_log_tx) {
            Ok(h) => {
                eprintln!("[egress] drop-log emitter watching table {nft_table}");
                Some(h)
            }
            Err(e) => {
                eprintln!(
                    "[egress] WARNING: failed to start drop-log emitter: {e:#} \
                     — L3 drops will not produce egress_denied events"
                );
                None
            }
        }
    } else {
        // No nft rules loaded → no kernel-log lines to tail. Drop the unused
        // sender so the supervisor's denial channel can close cleanly when
        // the proxy task exits.
        drop(drop_log_tx);
        None
    };

    let sandbox_spec_json = sandbox::build_sandbox_spec_json(spec, proxy_addr, Some(net));

    let config = SandboxConfig {
        kernel_path: kernel,
        rootfs_path: rootfs,
        workspace_host_path: workspace_path.to_path_buf(),
        spec_json: sandbox_spec_json,
        vcpus: spec.vcpus,
        mem_mib: spec.memory_mb,
        workspace_disk_mib: spec.workspace_disk_mb,
        run_id: run_id.to_string(),
        tap_name,
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

    let egress_ctx = EgressContext {
        denied_rx,
        listener: proxy_handle,
        drop_log: drop_log_handle,
    };
    let result = sandbox_supervisor::run(&mut handle, spec, enc, egress_ctx).await;

    // After VM exits, extract workspace files back to the host path.
    if workspace_ext4.exists() {
        if let Err(e) = extract_workspace_from_ext4(&workspace_ext4, workspace_path).await {
            eprintln!("[fc] workspace extraction warning: {e:#}");
        }
    }

    // Remove the per-Run nftables table. Idempotent; safe even if loading
    // earlier failed.
    let _ = delete_nftables_table(&nft_table).await;

    result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e:#}")))
}

struct CliArgs {
    spec: Option<String>,
    kernel: Option<std::path::PathBuf>,
    rootfs: Option<std::path::PathBuf>,
    firecracker: Option<std::path::PathBuf>,
    manage_firewall: bool,
}

fn parse_cli_args(args: &[String]) -> CliArgs {
    let mut spec = None;
    let mut kernel = None;
    let mut rootfs = None;
    let mut firecracker = None;
    let mut manage_firewall = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--spec" if i + 1 < args.len() => { spec = Some(args[i+1].clone()); i += 2; }
            "--kernel" if i + 1 < args.len() => { kernel = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            "--rootfs" if i + 1 < args.len() => { rootfs = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            "--firecracker" if i + 1 < args.len() => { firecracker = Some(std::path::PathBuf::from(&args[i+1])); i += 2; }
            "--manage-firewall" => { manage_firewall = true; i += 1; }
            other => {
                if let Some(v) = other.strip_prefix("--spec=") { spec = Some(v.to_string()); }
                else if let Some(v) = other.strip_prefix("--kernel=") { kernel = Some(std::path::PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--rootfs=") { rootfs = Some(std::path::PathBuf::from(v)); }
                else if let Some(v) = other.strip_prefix("--firecracker=") { firecracker = Some(std::path::PathBuf::from(v)); }
                i += 1;
            }
        }
    }
    CliArgs { spec, kernel, rootfs, firecracker, manage_firewall }
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
        assert!(!cli.manage_firewall);
    }

    #[test]
    fn parse_cli_manage_firewall_flag() {
        let args = strs(&["crucible-core", "--manage-firewall", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert!(cli.manage_firewall);
        assert!(cli.spec.is_some());
    }

    #[test]
    fn parse_cli_manage_firewall_default_false() {
        let args = strs(&["crucible-core", "--kernel", "/k", "--rootfs", "/r", "--spec", "{}"]);
        let cli = parse_cli_args(&args);
        assert!(!cli.manage_firewall);
    }
}
