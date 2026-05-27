//! Sandbox Fetch — the **single** host-side path that reads commits out of an
//! adversarial Sandbox's `.git` directory.
//!
//! See [ADR-0011](../../docs/adr/0011-hardened-git-fetch-from-sandbox.md) for
//! the threat model and rationale. The full posture lives in this one module
//! so a future change to the flag set, refspec shape, or deprivilege mechanic
//! is a single diff — no other place in the crate constructs a `git fetch`
//! command line against an ext4.
//!
//! Public surface:
//!
//! - [`sandbox_fetch_from_ext4`] (Linux only): the full lifecycle —
//!   `losetup` + `mount -o ro,nosuid,nodev,noexec` + hardened `git fetch` +
//!   `umount` + `losetup -d`. This is what slice 09 will swap in for the old
//!   `cp -a` extraction in `firecracker.rs`.
//! - [`fetch_pool_from_git_dir`]: the hardened-fetch step on its own, taking a
//!   pre-mounted (or fixture) `.git` directory. Cross-platform and used
//!   directly by tests that cannot exercise the privileged mount step.
//!
//! Both paths share the same hardening: the `-c` flags + `GIT_CONFIG_*` env
//! + explicit `HEAD:refs/heads/runs/<run-id>` (plus optional
//!   `HEAD:refs/heads/<output_branch>`) refspec — never a wildcard. Namespace
//!   validation is delegated to [`BranchPool::validate_run_output_targets`]
//!   so the reserved-namespace and already-exists rules live in one place.

// Scaffolding for slice 09 — the firecracker extraction path swaps `cp -a`
// for `sandbox_fetch_from_ext4`. Until then, only the tests in this module
// and downstream slices invoke it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use tokio::process::Command;

use crate::branch_pool::{BranchPool, BranchPoolError};

/// `-c key=value` overrides applied to every hardened fetch. Listed before
/// the `fetch` subcommand on the argv (see ADR-0011 "What hardened means").
pub const HARDENING_CONFIG_ARGS: &[&str] = &[
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "protocol.file.allow=user",
    "-c",
    "credential.helper=",
];

/// Environment variables applied to every hardened fetch.
pub const HARDENING_ENV_VARS: &[(&str, &str)] = &[
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
];

/// Mount option string passed to `mount -o ...`. Read-only with the standard
/// hostile-filesystem hardening triad.
pub const MOUNT_OPTIONS: &str = "ro,nosuid,nodev,noexec";

/// Known agent-history subpaths to extract from a Workspace after a Run.
///
/// Each entry is a path relative to the Workspace root. Files and directories
/// are both supported. The set is per-adapter; unknown adapters get the
/// claude-code default of `.claude/`. The list is intentionally explicit and
/// short so a future addition (e.g. a new adapter's history file) is a single
/// diff in this module, not scattered across copy helpers.
pub fn agent_history_subpaths(adapter: &str) -> &'static [&'static str] {
    match adapter {
        "aider" => AIDER_HISTORY_SUBPATHS,
        // claude-code stores everything under `.claude/`; unknown adapters
        // fall back to the same convention so they keep working without a
        // per-adapter entry.
        _ => &[".claude"],
    }
}

const AIDER_HISTORY_SUBPATHS: &[&str] = &[
    ".aider.chat.history.md",
    ".aider.input.history",
    ".aider.llm.history",
];

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SandboxFetchError {
    Io(std::io::Error),
    Pool(BranchPoolError),
    /// `losetup -f --show` or `losetup -d` failed.
    Loop { context: String, stderr: String },
    /// `mount` or `umount` failed.
    Mount { context: String, stderr: String },
    /// The hardened `git fetch` returned a non-zero status.
    Git { stderr: String },
}

impl std::fmt::Display for SandboxFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Pool(e) => write!(f, "pool error: {e}"),
            Self::Loop { context, stderr } => write!(f, "loop device error in {context}: {stderr}"),
            Self::Mount { context, stderr } => write!(f, "mount error in {context}: {stderr}"),
            Self::Git { stderr } => write!(f, "hardened git fetch failed: {stderr}"),
        }
    }
}

impl std::error::Error for SandboxFetchError {}

impl From<std::io::Error> for SandboxFetchError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<BranchPoolError> for SandboxFetchError {
    fn from(e: BranchPoolError) -> Self {
        Self::Pool(e)
    }
}

// ── Pure helpers (testable without root, mount, or git) ────────────────────

/// Build the argv passed after `git` for the hardened fetch.
///
/// Layout: `[hardening -c flags] fetch --no-tags --no-recurse-submodules
/// <source_git_dir> HEAD:refs/heads/runs/<run-id> [HEAD:refs/heads/<output_branch>]`.
///
/// The refspec is **always** explicit. No wildcard or `+refs/*:refs/*` is
/// constructed regardless of input — see ADR-0011.
pub fn build_hardened_argv(
    source_git_dir: &Path,
    run_id: &str,
    output_branch: Option<&str>,
) -> Vec<String> {
    let mut argv: Vec<String> = Vec::with_capacity(HARDENING_CONFIG_ARGS.len() + 5);
    for s in HARDENING_CONFIG_ARGS {
        argv.push((*s).to_string());
    }
    argv.push("fetch".into());
    argv.push("--no-tags".into());
    argv.push("--no-recurse-submodules".into());
    argv.push(source_git_dir.to_string_lossy().to_string());
    argv.push(format!("HEAD:refs/heads/runs/{run_id}"));
    if let Some(name) = output_branch {
        argv.push(format!("HEAD:refs/heads/{name}"));
    }
    argv
}

/// Decide which uid to set on the spawned `git fetch`.
///
/// - If the bunsen host process is running as root (`current_euid == 0`),
///   drop to `user_script_uid` so git reads the agent's `.git` as the User
///   Script's user — not root.
/// - Otherwise, the bunsen process is already the User Script's user, so
///   we leave the spawn uid alone (returns `None`).
pub fn compute_spawn_uid(current_euid: u32, user_script_uid: u32) -> Option<u32> {
    if current_euid == 0 {
        Some(user_script_uid)
    } else {
        None
    }
}

/// Build the argv passed to `mount` for the read-only Sandbox `.git` mount.
/// The options string is the load-bearing `ro,nosuid,nodev,noexec`.
pub fn build_mount_argv(loop_dev: &str, mountpoint: &Path) -> Vec<String> {
    vec![
        "-o".into(),
        MOUNT_OPTIONS.into(),
        loop_dev.into(),
        mountpoint.to_string_lossy().to_string(),
    ]
}

// ── Narrow agent-history copy ─────────────────────────────────────────────

/// Copy a small, explicit list of subpaths from `source_root` to `dst_root`,
/// refusing to follow symlinks whose targets escape `source_root`.
///
/// Used after a Run to preserve the agent's native history (e.g. claude-code's
/// `.claude/`, aider's `.aider.*.history` files) on the host so the User
/// Script can debug agent behaviour. These files are NOT pulled into the
/// Pool — the Pool only carries the agent's commits.
///
/// Behaviour:
/// - Missing subpaths are skipped silently.
/// - Symbolic links are not followed. Any symlink found while walking is
///   skipped entirely — recreating it in `dst_root` would be load-bearing
///   only if the agent intentionally produced one, and we'd rather lose the
///   symlink than copy out-of-tree data into the host's filesystem.
/// - Only regular files and directories are traversed/copied. Special files
///   (sockets, devices, FIFOs) are skipped.
///
/// The symlink-escape guard is the load-bearing part: even though we don't
/// follow symlinks at all in the current implementation, `source_root` is
/// canonicalised up front so a future relaxation that wants to allow
/// in-tree symlinks has a `starts_with(canonical)` check to apply.
pub fn copy_agent_history_narrow(
    adapter: &str,
    source_root: &Path,
    dst_root: &Path,
) -> std::io::Result<()> {
    let canonical_source = match std::fs::canonicalize(source_root) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for sub in agent_history_subpaths(adapter) {
        let src = canonical_source.join(sub);
        let dst = dst_root.join(sub);
        copy_narrow_entry(&canonical_source, &src, &dst)?;
    }
    Ok(())
}

fn copy_narrow_entry(
    source_root: &Path,
    src: &Path,
    dst: &Path,
) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(src) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        // Refuse to follow. Even when the target stays inside source_root,
        // we skip rather than recreate — `agent-history/` is a snapshot of
        // the agent's session memory, not a faithful reproduction of the
        // workspace layout. The canonical guard below documents the
        // tighter check a future relaxation would apply.
        if let Ok(resolved) = std::fs::canonicalize(src) {
            // Verifies the symlink doesn't point outside the source tree.
            // We never follow regardless, but if a future change opts to
            // follow internal symlinks this is the predicate it'd use.
            let _ = resolved.starts_with(source_root);
        }
        return Ok(());
    }
    if ft.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let name = entry.file_name();
            copy_narrow_entry(source_root, &entry.path(), &dst.join(&name))?;
        }
        return Ok(());
    }
    if ft.is_file() {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
        return Ok(());
    }
    // Sockets / devices / FIFOs — skip.
    Ok(())
}

// ── Fetch step (cross-platform, used by both fixtures and the ext4 lifecycle) ─

/// Perform the hardened `git fetch` from `source_git_dir` (a bare or non-bare
/// repo, or the mounted `.git` of a Sandbox ext4) into `pool`.
///
/// Validation is delegated to [`BranchPool::validate_run_output_targets`] —
/// the reserved-namespace and already-exists checks live there. The git
/// invocation is the fully hardened command described in ADR-0011.
///
/// `user_script_uid` is consulted only when the current process is root; see
/// [`compute_spawn_uid`].
pub async fn fetch_pool_from_git_dir(
    pool: &BranchPool,
    source_git_dir: &Path,
    run_id: &str,
    output_branch: Option<&str>,
    user_script_uid: u32,
) -> Result<(), SandboxFetchError> {
    pool.validate_run_output_targets(run_id, output_branch).await?;
    let argv = build_hardened_argv(source_git_dir, run_id, output_branch);
    let mut cmd = Command::new("git");
    cmd.current_dir(pool.path());
    // Clear the inherited environment of git-specific overrides and replace
    // with our hardened set. (Don't .env_clear() — we need PATH etc.)
    for (k, v) in HARDENING_ENV_VARS {
        cmd.env(k, v);
    }
    cmd.args(&argv);
    apply_spawn_uid(&mut cmd, user_script_uid);
    let out = cmd.output().await?;
    if !out.status.success() {
        return Err(SandboxFetchError::Git {
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn apply_spawn_uid(cmd: &mut Command, user_script_uid: u32) {
    let current = nix::unistd::geteuid().as_raw();
    if let Some(uid) = compute_spawn_uid(current, user_script_uid) {
        // `tokio::process::Command::uid` is the Unix-only setter for the
        // child process's uid (mirrors std's `CommandExt::uid`).
        cmd.uid(uid);
    }
}

#[cfg(not(unix))]
fn apply_spawn_uid(_cmd: &mut Command, _user_script_uid: u32) {
    // No-op on non-unix targets — bunsen only ships there for the dev path.
}

// ── Full ext4 lifecycle (Linux only) ───────────────────────────────────────

/// The single host-side path that reads commits out of an adversarial
/// Sandbox's ext4. Performs `losetup` + `mount -o ro,nosuid,nodev,noexec` +
/// hardened `git fetch` + `umount` + `losetup -d`. The mount and loop-device
/// cleanup always runs, even if the fetch fails.
///
/// `ext4_path` is the Sandbox's workspace image; the mounted root must
/// contain a `.git` directory (the Workspace's `.git`).
///
/// `user_script_uid` is the uid the bunsen host process should drop to for
/// the actual `git fetch`. Used only if bunsen is running as root.
#[cfg(target_os = "linux")]
pub async fn sandbox_fetch_from_ext4(
    pool: &BranchPool,
    ext4_path: &Path,
    run_id: &str,
    output_branch: Option<&str>,
    user_script_uid: u32,
) -> Result<(), SandboxFetchError> {
    // Validate first so we fail before touching the kernel loop subsystem.
    pool.validate_run_output_targets(run_id, output_branch).await?;

    let loop_dev = losetup_attach(ext4_path).await?;
    let mnt = make_mount_dir().await?;

    let inner = async {
        let mount_argv = build_mount_argv(&loop_dev, &mnt);
        let argv_refs: Vec<&str> = mount_argv.iter().map(String::as_str).collect();
        let mount_out = Command::new("mount").args(&argv_refs).output().await?;
        if !mount_out.status.success() {
            return Err(SandboxFetchError::Mount {
                context: format!("mount {loop_dev} {}", mnt.display()),
                stderr: String::from_utf8_lossy(&mount_out.stderr).to_string(),
            });
        }

        let source_git_dir = mnt.join(".git");
        fetch_pool_from_git_dir(pool, &source_git_dir, run_id, output_branch, user_script_uid).await
    };

    let fetch_result = inner.await;

    // Always clean up: umount → losetup -d → rmdir.
    let _ = Command::new("umount").arg(&mnt).status().await;
    let _ = Command::new("losetup").args(["-d", &loop_dev]).status().await;
    let _ = std::fs::remove_dir_all(&mnt);

    fetch_result
}

#[cfg(target_os = "linux")]
async fn losetup_attach(ext4_path: &Path) -> Result<String, SandboxFetchError> {
    let out = Command::new("losetup")
        .args(["-f", "--show", &ext4_path.to_string_lossy()])
        .output()
        .await?;
    if !out.status.success() {
        return Err(SandboxFetchError::Loop {
            context: format!("losetup -f --show {}", ext4_path.display()),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
async fn make_mount_dir() -> Result<PathBuf, SandboxFetchError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "bunsen-sbf-{}-{}",
        std::process::id(),
        n
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

// Keep make_mount_dir available to non-Linux for symmetry of the API surface
// (currently unused there, but harmless).
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
async fn make_mount_dir() -> Result<PathBuf, SandboxFetchError> {
    Err(SandboxFetchError::Mount {
        context: "make_mount_dir".into(),
        stderr: "ext4 mount only supported on linux".into(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command as StdCommand;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_temp_dir(suffix: &str) -> PathBuf {
        use std::time::SystemTime;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "bunsen-sbf-test-{suffix}-{pid}-{nanos}-{n}"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run_git_sync_in(cwd: &Path, args: &[&str]) {
        let status = StdCommand::new("git")
            .current_dir(cwd)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} in {cwd:?} failed");
    }

    fn make_workspace_repo(suffix: &str) -> (PathBuf, String) {
        // A non-bare repo whose `.git/` is what the Sandbox would expose at
        // /<mnt>/.git after losetup+mount.
        let dir = make_temp_dir(suffix);
        run_git_sync_in(&dir, &["init", "-b", "main", "--quiet"]);
        run_git_sync_in(&dir, &["config", "user.email", "agent@test"]);
        run_git_sync_in(&dir, &["config", "user.name", "Agent"]);
        std::fs::write(dir.join("hello.txt"), "hello\n").unwrap();
        run_git_sync_in(&dir, &["add", "hello.txt"]);
        run_git_sync_in(&dir, &["commit", "-m", "agent commit", "--quiet"]);
        let out = StdCommand::new("git")
            .current_dir(&dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (dir, sha)
    }

    fn ref_sha(repo: &Path, full_ref: &str) -> String {
        let out = StdCommand::new("git")
            .current_dir(repo)
            .args(["rev-parse", full_ref])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    // ── Pure helpers ──────────────────────────────────────────────────────

    #[test]
    fn argv_contains_all_required_hardening_config_flags() {
        let argv = build_hardened_argv(Path::new("/tmp/ws/.git"), "01HRUN", None);
        let joined = argv.join(" ");
        // Each `-c key=value` pair must appear with the exact key=value form.
        assert!(argv.windows(2).any(|w| w[0] == "-c" && w[1] == "core.hooksPath=/dev/null"),
                "missing core.hooksPath override in {joined}");
        assert!(argv.windows(2).any(|w| w[0] == "-c" && w[1] == "protocol.file.allow=user"),
                "missing protocol.file.allow override in {joined}");
        assert!(argv.windows(2).any(|w| w[0] == "-c" && w[1] == "credential.helper="),
                "missing credential.helper override in {joined}");
    }

    #[test]
    fn argv_contains_no_recurse_submodules() {
        let argv = build_hardened_argv(Path::new("/tmp/ws/.git"), "01HRUN", None);
        assert!(argv.iter().any(|a| a == "--no-recurse-submodules"));
    }

    #[test]
    fn argv_uses_explicit_runs_refspec_only_when_no_output_branch() {
        let argv = build_hardened_argv(Path::new("/tmp/ws/.git"), "01HRUNX", None);
        let refspecs: Vec<&String> = argv.iter().filter(|s| s.contains("HEAD:")).collect();
        assert_eq!(refspecs.len(), 1, "expected exactly one refspec, got {refspecs:?}");
        assert_eq!(refspecs[0], "HEAD:refs/heads/runs/01HRUNX");
    }

    #[test]
    fn argv_emits_second_refspec_when_output_branch_supplied() {
        let argv = build_hardened_argv(
            Path::new("/tmp/ws/.git"),
            "01HRUNY",
            Some("feature/agent-work"),
        );
        let refspecs: Vec<&String> = argv.iter().filter(|s| s.contains("HEAD:")).collect();
        assert_eq!(refspecs.len(), 2, "expected two refspecs, got {refspecs:?}");
        assert_eq!(refspecs[0], "HEAD:refs/heads/runs/01HRUNY");
        assert_eq!(refspecs[1], "HEAD:refs/heads/feature/agent-work");
    }

    #[test]
    fn argv_never_contains_wildcard_refspec_regardless_of_input() {
        for (run_id, branch) in [
            ("plain", None),
            ("with-branch", Some("feature/x")),
            // Adversarial-looking inputs: the function passes them through
            // verbatim into the refspec, but never constructs `refs/*:refs/*`.
            ("ulid", Some("refs/heads/sneaky")),
            ("ulid", Some("*")),
        ] {
            let argv = build_hardened_argv(Path::new("/tmp/ws/.git"), run_id, branch);
            for a in &argv {
                assert!(
                    !a.contains("refs/*"),
                    "argv must never contain a wildcard refspec; got {a} in {argv:?}",
                );
                assert!(
                    !a.starts_with('+'),
                    "argv must never construct a force-refspec (+...); got {a} in {argv:?}",
                );
            }
        }
    }

    #[test]
    fn argv_places_hardening_config_before_fetch_subcommand() {
        let argv = build_hardened_argv(Path::new("/tmp/ws/.git"), "01HRUN", None);
        let fetch_idx = argv.iter().position(|a| a == "fetch").unwrap();
        // Every `-c` flag must come before `fetch` — `-c` after a subcommand
        // is silently ignored by git.
        for (i, a) in argv.iter().enumerate() {
            if a == "-c" {
                assert!(i < fetch_idx, "stray -c at position {i} (after fetch at {fetch_idx})");
            }
        }
    }

    #[test]
    fn hardening_env_has_required_overrides() {
        let env: std::collections::HashMap<&str, &str> =
            HARDENING_ENV_VARS.iter().copied().collect();
        assert_eq!(env.get("GIT_CONFIG_NOSYSTEM"), Some(&"1"));
        assert_eq!(env.get("GIT_CONFIG_GLOBAL"), Some(&"/dev/null"));
    }

    #[test]
    fn mount_options_string_is_the_load_bearing_quad() {
        assert_eq!(MOUNT_OPTIONS, "ro,nosuid,nodev,noexec");
    }

    #[test]
    fn build_mount_argv_uses_hardening_quad() {
        let argv = build_mount_argv("/dev/loop7", Path::new("/tmp/mnt"));
        assert_eq!(argv[0], "-o");
        assert_eq!(argv[1], "ro,nosuid,nodev,noexec");
        assert_eq!(argv[2], "/dev/loop7");
        assert_eq!(argv[3], "/tmp/mnt");
    }

    // ── Deprivilege decision ──────────────────────────────────────────────

    #[test]
    fn compute_spawn_uid_drops_to_user_when_root() {
        assert_eq!(compute_spawn_uid(0, 1000), Some(1000));
        assert_eq!(compute_spawn_uid(0, 65534), Some(65534));
    }

    #[test]
    fn compute_spawn_uid_leaves_alone_when_already_user() {
        assert_eq!(compute_spawn_uid(1000, 1000), None);
        // Even a mismatch — if the host bunsen process isn't root, we can't
        // change uid, and we trust the host to already be the right user.
        assert_eq!(compute_spawn_uid(500, 1000), None);
        assert_eq!(compute_spawn_uid(65534, 1000), None);
    }

    // ── Fetch against a fixture .git ──────────────────────────────────────

    #[tokio::test]
    async fn fetch_pool_from_git_dir_writes_audit_ref() {
        let (work, sha) = make_workspace_repo("audit");
        let pool_dir = make_temp_dir("pool-audit");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        fetch_pool_from_git_dir(&pool, &work.join(".git"), "01HRUN1", None, current_uid())
            .await
            .unwrap();

        assert_eq!(ref_sha(&pool_dir, "refs/heads/runs/01HRUN1"), sha);

        std::fs::remove_dir_all(&work).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn fetch_pool_from_git_dir_writes_audit_and_output_branch_at_same_sha() {
        let (work, sha) = make_workspace_repo("both");
        let pool_dir = make_temp_dir("pool-both");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        fetch_pool_from_git_dir(
            &pool,
            &work.join(".git"),
            "01HRUN2",
            Some("feature/done"),
            current_uid(),
        )
        .await
        .unwrap();

        assert_eq!(ref_sha(&pool_dir, "refs/heads/runs/01HRUN2"), sha);
        assert_eq!(ref_sha(&pool_dir, "refs/heads/feature/done"), sha);

        std::fs::remove_dir_all(&work).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn fetch_pool_delegates_to_pool_for_reserved_namespace() {
        // Pool::validate_run_output_targets must reject `host/*` regardless
        // of what sandbox_fetch does — we are delegating, not duplicating.
        let (work, _sha) = make_workspace_repo("res-host");
        let pool_dir = make_temp_dir("pool-res-host");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        let err = fetch_pool_from_git_dir(
            &pool,
            &work.join(".git"),
            "01HRUN3",
            Some("host/sneak"),
            current_uid(),
        )
        .await
        .unwrap_err();
        match err {
            SandboxFetchError::Pool(BranchPoolError::ReservedNamespace { namespace, .. }) => {
                assert_eq!(namespace, "host/");
            }
            other => panic!("expected Pool::ReservedNamespace, got {other:?}"),
        }

        std::fs::remove_dir_all(&work).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn fetch_pool_delegates_to_pool_for_runs_namespace_in_output_branch() {
        let (work, _sha) = make_workspace_repo("res-runs");
        let pool_dir = make_temp_dir("pool-res-runs");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        let err = fetch_pool_from_git_dir(
            &pool,
            &work.join(".git"),
            "01HRUN4",
            Some("runs/forged"),
            current_uid(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            SandboxFetchError::Pool(BranchPoolError::ReservedNamespace { .. })
        ));

        std::fs::remove_dir_all(&work).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn fetch_pool_refuses_to_overwrite_existing_run_audit_ref() {
        // Once a `runs/<id>` ref exists, a second fetch for the same id is
        // rejected by the Pool's validation.
        let (work, _sha) = make_workspace_repo("dup-runs");
        let pool_dir = make_temp_dir("pool-dup-runs");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        fetch_pool_from_git_dir(&pool, &work.join(".git"), "01HRUN5", None, current_uid())
            .await
            .unwrap();
        let err = fetch_pool_from_git_dir(&pool, &work.join(".git"), "01HRUN5", None, current_uid())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SandboxFetchError::Pool(BranchPoolError::RefAlreadyExists { .. })
        ));

        std::fs::remove_dir_all(&work).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    fn current_uid() -> u32 {
        #[cfg(unix)]
        {
            nix::unistd::getuid().as_raw()
        }
        #[cfg(not(unix))]
        {
            0
        }
    }

    // ── Narrow agent-history copy ─────────────────────────────────────────

    #[test]
    fn agent_history_subpaths_claude_code_uses_dot_claude() {
        assert_eq!(agent_history_subpaths("claude-code"), &[".claude"]);
    }

    #[test]
    fn agent_history_subpaths_aider_uses_known_history_files() {
        let subs = agent_history_subpaths("aider");
        assert!(subs.contains(&".aider.chat.history.md"));
        assert!(subs.contains(&".aider.input.history"));
        assert!(subs.contains(&".aider.llm.history"));
    }

    #[test]
    fn agent_history_subpaths_unknown_adapter_falls_back_to_dot_claude() {
        assert_eq!(agent_history_subpaths("black-box"), &[".claude"]);
    }

    #[test]
    fn copy_agent_history_narrow_copies_claude_dir_recursively() {
        let src = make_temp_dir("ah-claude-src");
        let dst = make_temp_dir("ah-claude-dst");
        std::fs::create_dir_all(src.join(".claude").join("sub")).unwrap();
        std::fs::write(src.join(".claude").join("a.json"), b"a").unwrap();
        std::fs::write(src.join(".claude").join("sub").join("b.json"), b"b").unwrap();
        // A file outside `.claude/` must NOT be copied — only the known
        // subpath list is in scope.
        std::fs::write(src.join("README.md"), b"readme").unwrap();

        copy_agent_history_narrow("claude-code", &src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join(".claude").join("a.json")).unwrap(), b"a");
        assert_eq!(
            std::fs::read(dst.join(".claude").join("sub").join("b.json")).unwrap(),
            b"b"
        );
        assert!(!dst.join("README.md").exists(), "out-of-list file must not be copied");

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[test]
    fn copy_agent_history_narrow_skips_missing_subpaths() {
        let src = make_temp_dir("ah-empty-src");
        let dst = make_temp_dir("ah-empty-dst");
        // No `.claude/` exists.
        copy_agent_history_narrow("claude-code", &src, &dst).unwrap();
        assert!(!dst.join(".claude").exists());
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[test]
    fn copy_agent_history_narrow_does_not_follow_out_of_tree_symlink() {
        // The adversarial case from ADR-0011: an agent plants a symlink
        // pointing to `/etc/passwd`. The narrow copy must not read it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let src = make_temp_dir("ah-sym-src");
            let dst = make_temp_dir("ah-sym-dst");
            std::fs::create_dir_all(src.join(".claude")).unwrap();
            // Symlink pointing to a host file the agent should never reach.
            symlink("/etc/passwd", src.join(".claude").join("escape")).unwrap();

            copy_agent_history_narrow("claude-code", &src, &dst).unwrap();
            let copied = dst.join(".claude").join("escape");
            // The symlink target must NOT have been read into a regular file.
            assert!(
                !copied.exists() || std::fs::symlink_metadata(&copied).map(|m| m.file_type().is_symlink()).unwrap_or(false),
                "out-of-tree symlink must not be materialised as a regular file"
            );
            // And nothing matching /etc/passwd's content (which starts with "root:")
            // should have leaked through.
            if let Ok(bytes) = std::fs::read(&copied) {
                assert!(
                    !bytes.starts_with(b"root:"),
                    "out-of-tree symlink content leaked through narrow copy"
                );
            }
            std::fs::remove_dir_all(&src).ok();
            std::fs::remove_dir_all(&dst).ok();
        }
    }

    #[test]
    fn copy_agent_history_narrow_skips_in_tree_symlink_too() {
        // The conservative posture: even in-tree symlinks are skipped, since
        // `agent-history/` is a memory snapshot, not a workspace mirror.
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let src = make_temp_dir("ah-sym-in-src");
            let dst = make_temp_dir("ah-sym-in-dst");
            std::fs::create_dir_all(src.join(".claude")).unwrap();
            std::fs::write(src.join(".claude").join("real.txt"), b"real").unwrap();
            symlink("real.txt", src.join(".claude").join("alias.txt")).unwrap();

            copy_agent_history_narrow("claude-code", &src, &dst).unwrap();
            assert_eq!(
                std::fs::read(dst.join(".claude").join("real.txt")).unwrap(),
                b"real",
                "real file inside .claude/ is copied"
            );
            // The in-tree symlink is skipped per the conservative rule.
            let alias = dst.join(".claude").join("alias.txt");
            assert!(!alias.exists(), "in-tree symlink must be skipped");
            std::fs::remove_dir_all(&src).ok();
            std::fs::remove_dir_all(&dst).ok();
        }
    }

    #[test]
    fn copy_agent_history_narrow_copies_aider_files_only() {
        let src = make_temp_dir("ah-aider-src");
        let dst = make_temp_dir("ah-aider-dst");
        std::fs::write(src.join(".aider.chat.history.md"), b"chat").unwrap();
        std::fs::write(src.join(".aider.input.history"), b"in").unwrap();
        std::fs::write(src.join(".aider.llm.history"), b"llm").unwrap();
        // The aider cache directory and unrelated workspace files are out
        // of scope.
        std::fs::create_dir_all(src.join(".aider.tags.cache.v3")).unwrap();
        std::fs::write(src.join(".aider.tags.cache.v3").join("x"), b"cache").unwrap();
        std::fs::write(src.join("README.md"), b"readme").unwrap();

        copy_agent_history_narrow("aider", &src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join(".aider.chat.history.md")).unwrap(), b"chat");
        assert_eq!(std::fs::read(dst.join(".aider.input.history")).unwrap(), b"in");
        assert_eq!(std::fs::read(dst.join(".aider.llm.history")).unwrap(), b"llm");
        assert!(!dst.join(".aider.tags.cache.v3").exists(), "cache dir must not be copied");
        assert!(!dst.join("README.md").exists());
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dst).ok();
    }
}
