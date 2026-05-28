//! Linux-only Firecracker sandbox lifecycle.
//!
//! The body here was lifted from `main.rs::run_sandbox` so both the legacy
//! CLI entry point (`bunsen-core --kernel /k --rootfs /r --spec ...`) and
//! the Session-aware entry point ([`crate::session::Session::run_with_backend`])
//! share one implementation of the sandbox lifecycle: per-Run TAP, L7 proxy,
//! DNS listener, L3 nftables ruleset, drop-log emitter, Firecracker start,
//! and the sandbox supervisor that watches the guest's vsock streams.
//!
//! The only Session-specific delta lives in [`PoolExtraction`]: when
//! supplied, after the supervisor returns, the workspace ext4 image is
//! mounted read-only and the agent's commits are fetched into the Session's
//! [`crate::branch_pool::BranchPool`] via the hardened ADR-0011 path
//! ([`crate::firecracker::extract_workspace_from_ext4`]). The CLI path
//! continues to pass `None` and accepts losing workspace state at VM exit,
//! matching ADR-0010's "Pool is the source of truth" rule.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::os::unix::io::FromRawFd as _;
use std::path::{Path, PathBuf};

use crate::branch_pool::BranchPool;
use crate::dns;
use crate::egress_proxy;
use crate::encoder::Encoder;
use crate::firecracker::{extract_workspace_from_ext4, start_firecracker};
use crate::privileged_net::PrivilegedNetHandle;
use crate::run_spec::RunSpec;
use crate::sandbox::{self, SandboxConfig};
use crate::sandbox_net::{derive_run_network, derive_tap_name};
use crate::sandbox_nft::{build_ruleset, derive_table_name, pump_drop_log_lines};
use crate::sandbox_supervisor::{self, EgressContext};

/// Per-Run request to fetch the agent's commits out of the workspace ext4
/// image and into the supplied [`BranchPool`] after the guest exits.
///
/// Without this struct, the legacy CLI flow runs the sandbox and lets
/// workspace state die with the VM. With it, the same lifecycle ends with
/// the hardened mount + fetch + narrow-history-copy + unmount cycle from
/// ADR-0011, leaving an audit ref (and optionally an output_branch ref) in
/// the Pool.
pub struct PoolExtraction<'a> {
    pub pool: &'a BranchPool,
    pub output_branch: Option<&'a str>,
    pub agent_history_dst: Option<&'a Path>,
    pub user_script_uid: u32,
}

/// Run the Firecracker sandbox lifecycle for one Run.
///
/// `workspace_path` is the host-side directory whose contents become the
/// initial state of the guest's `/workspace` ext4 image (driven by
/// [`crate::firecracker::create_workspace_ext4_from_dir`]).
///
/// When `extraction` is `Some`, the agent's commits are read out of the
/// post-Run ext4 image into the supplied Pool before the
/// [`FirecrackerHandle`] is dropped (which deletes the temp dir containing
/// `workspace.ext4`).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    kernel: PathBuf,
    rootfs: PathBuf,
    firecracker_bin: Option<PathBuf>,
    manage_firewall: bool,
    spec: &RunSpec,
    run_id: &str,
    enc: &mut Encoder,
    workspace_path: &Path,
    extraction: Option<PoolExtraction<'_>>,
    actor: &PrivilegedNetHandle,
    owner_user: &str,
) -> std::io::Result<()> {
    let fc_bin = firecracker_bin.unwrap_or_else(|| PathBuf::from("firecracker"));

    // ── Per-Run network ────────────────────────────────────────────────────
    // Derive the /30 IPv4 pair and TAP name from the run_id, then create the
    // TAP and assign its host-side address. The L7 proxy will bind on that
    // address (slice 10f) so the TAP must be up first. Any leftover TAP from
    // a previous crashed Run with the same id is removed defensively — this
    // mirrors the pre-cleanup behavior start_firecracker used to do.
    let net = derive_run_network(run_id);
    let tap_name = derive_tap_name(run_id);
    let _ = actor.delete_tap(&tap_name).await;
    eprintln!(
        "[fc] creating TAP device {tap_name} (host {host}/{prefix}, guest {guest})",
        host = net.host,
        prefix = net.prefix_len,
        guest = net.guest,
    );
    actor
        .create_tap(&tap_name, net.host, net.prefix_len, owner_user)
        .await
        .map_err(|e| std::io::Error::other(format!("{e:#}")))?;
    // Tie the TAP's lifetime to this Run: the guard deletes it on every exit
    // path (success, error, or panic). This replaces the deletion that used to
    // live in FirecrackerHandle::drop, so teardown stays centralised in the
    // privileged-net module.
    let _tap_guard = crate::privileged_net::TapGuard::new(tap_name.clone());

    // ── Slice 10k: host iptables co-existence ─────────────────────────────
    // The pre-flight probe in main() already decided whether we can proceed.
    // If the caller passed --manage-firewall we install the per-TAP allow
    // rule unconditionally (idempotent pre-cleanup first, in case a previous
    // Run with the same tap_name crashed before its guard ran). The
    // TapAllowGuard removes the rule via std::process::Command on Drop —
    // synchronous so cleanup runs reliably on panic and during runtime
    // shutdown. Holding the guard in this local scope ties its lifetime to
    // the Run.
    let _firewall_guard = if manage_firewall {
        let _ = actor.remove_tap_allow(&tap_name).await;
        actor
            .add_tap_allow(&tap_name)
            .await
            .map_err(|e| std::io::Error::other(format!("{e:#}")))?;
        eprintln!("[firewall] installed per-TAP allow rule for {tap_name}");
        Some(crate::privileged_net::TapAllowGuard::new(tap_name.clone()))
    } else {
        None
    };

    // ── L7 egress proxy ────────────────────────────────────────────────────
    // Bind the proxy on the TAP host IP (port 0 → kernel-assigned) so the
    // address injected as HTTP_PROXY / HTTPS_PROXY is reachable from inside
    // the guest once eth0 comes up. Bind happens before build_sandbox_spec_json
    // so the bound SocketAddr flows into the env.
    let policy = spec.effective_egress_policy();
    let (denied_tx, denied_rx) = tokio::sync::mpsc::unbounded_channel();
    let drop_log_tx = denied_tx.clone();
    let dns_tx = denied_tx.clone();
    let proxy_bind: SocketAddr = SocketAddr::from((net.host, 0));
    let (proxy_addr, proxy_handle) = match egress_proxy::spawn_listener(
        proxy_bind,
        policy.clone(),
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

    // ── DNS listener (slice 10m) ───────────────────────────────────────────
    // The actor binds the privileged :53 socket synchronously on its thread
    // (inheriting CAP_NET_BIND_SERVICE once Module B lands). We adopt the raw
    // fd into a tokio UdpSocket and hand it to the async listener loop.
    use std::env;
    let upstream: SocketAddr = match env::var("BUNSEN_DNS_UPSTREAM") {
        Ok(s) => s.parse().unwrap_or_else(|_| {
            let fallback = dns::default_dns_upstream();
            eprintln!(
                "[egress] WARNING: invalid BUNSEN_DNS_UPSTREAM={s:?}, \
                 falling back to {fallback}"
            );
            fallback
        }),
        Err(_) => dns::default_dns_upstream(),
    };
    let dns_bind: SocketAddr = SocketAddr::from((net.host, 53));
    let (dns_port, dns_handle) = match actor.bind_dns(dns_bind).await {
        Ok(raw_fd) => {
            // SAFETY: the actor just created this fd; we take exclusive ownership.
            let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
            match tokio::net::UdpSocket::from_std(std_sock) {
                Ok(tok_sock) => {
                    match dns::spawn_dns_listener_from_socket(
                        tok_sock,
                        policy,
                        dns::TokioUdpResolver::new(upstream),
                        dns_tx,
                    )
                    .await
                    {
                        Ok((addr, h)) => {
                            eprintln!("[egress] DNS listener bound on {addr} (upstream {upstream})");
                            (Some(addr.port()), Some(h))
                        }
                        Err(e) => {
                            eprintln!(
                                "[egress] failed to start DNS listener loop: {e} \
                                 — DNS-only egress attempts will surface as raw_tcp drops"
                            );
                            (None, None)
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[egress] failed to convert DNS fd to tokio socket: {e} \
                         — DNS-only egress attempts will surface as raw_tcp drops"
                    );
                    (None, None)
                }
            }
        }
        Err(e) => {
            eprintln!(
                "[egress] failed to bind DNS listener on {dns_bind}: {e} \
                 — DNS-only egress attempts will surface as raw_tcp drops"
            );
            (None, None)
        }
    };

    // ── L3 egress enforcement (nftables) ───────────────────────────────────
    let nft_table = derive_table_name(run_id);
    let _ = actor.delete_nft(&nft_table).await;
    let mut nft_loaded = false;
    if let Some(addr) = proxy_addr {
        let rules = build_ruleset(&nft_table, &tap_name, net.host, addr.port(), dns_port);
        eprintln!("[egress] loading nftables table {nft_table}");
        match actor.apply_nft(rules).await {
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
    // The actor spawns journalctl synchronously so it inherits CAP_SYSLOG
    // (once Module B lands). We take the child's stdout and drive the line
    // pump inside a tokio task.
    let drop_log_handle = if nft_loaded {
        match actor.spawn_journalctl().await {
            Ok(mut child) => match child.stdout.take() {
                Some(stdout) => {
                    match tokio::process::ChildStdout::from_std(stdout) {
                        Ok(async_stdout) => {
                            let table = nft_table.clone();
                            let sender = drop_log_tx;
                            // Own the child via a reaper so it is killed whether
                            // the pump exits on its own or the task is aborted on
                            // Run teardown — dropping a std::process::Child alone
                            // does not kill it.
                            let reaper = crate::privileged_net::ChildReaper(child);
                            eprintln!("[egress] drop-log emitter watching table {nft_table}");
                            Some(tokio::spawn(async move {
                                let _reaper = reaper;
                                let reader = tokio::io::BufReader::new(async_stdout);
                                if let Err(e) = pump_drop_log_lines(reader, &table, sender).await {
                                    eprintln!("[egress] drop-log pump exited with error: {e:#}");
                                }
                            }))
                        }
                        Err(e) => {
                            eprintln!(
                                "[egress] WARNING: failed to adapt journalctl stdout: {e:#} \
                                 — L3 drops will not produce egress_denied events"
                            );
                            drop(drop_log_tx);
                            None
                        }
                    }
                }
                None => {
                    eprintln!(
                        "[egress] WARNING: journalctl child has no stdout pipe \
                         — L3 drops will not produce egress_denied events"
                    );
                    drop(drop_log_tx);
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "[egress] WARNING: failed to spawn journalctl: {e:#} \
                     — L3 drops will not produce egress_denied events"
                );
                drop(drop_log_tx);
                None
            }
        }
    } else {
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

    let mut handle = start_firecracker(&config, &fc_bin)
        .await
        .map_err(|e| std::io::Error::other(format!("{e:#}")))?;

    let egress_ctx = EgressContext {
        denied_rx,
        listener: proxy_handle,
        drop_log: drop_log_handle,
        dns_listener: dns_handle,
    };
    let supervisor_result = sandbox_supervisor::run(&mut handle, spec, enc, egress_ctx).await;

    // Pool extraction happens inside this scope so the FirecrackerHandle
    // (and therefore the temp dir holding workspace.ext4) is still alive.
    // Drop occurs at function exit; cleanup of the TAP + run_dir runs after
    // extraction has read the ext4 image.
    let extraction_result: std::io::Result<()> = if let Some(ext) = extraction {
        let ext4_path = handle.workspace_ext4_path();
        extract_workspace_from_ext4(
            &ext4_path,
            ext.pool,
            run_id,
            ext.output_branch,
            ext.user_script_uid,
            &spec.adapter,
            ext.agent_history_dst,
        )
        .await
        .map_err(|e| std::io::Error::other(format!("{e:#}")))
    } else {
        Ok(())
    };

    // Remove the per-Run nftables table. Idempotent; safe even if loading
    // earlier failed.
    let _ = actor.delete_nft(&nft_table).await;

    // The supervisor's failure wins if both fail: it carries the agent-side
    // error, which is the more useful signal for the user.
    supervisor_result.map_err(|e| std::io::Error::other(format!("{e:#}")))?;
    extraction_result
}
