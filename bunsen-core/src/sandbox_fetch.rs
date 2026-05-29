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
//!   `debugfs rdump` (no `losetup`/`mount`/`CAP_SYS_ADMIN`) + symlink scrub
//!   + hardened `git fetch`. Replaces the old mount-based extraction.
//! - [`fetch_pool_from_git_dir`]: the hardened-fetch step on its own, taking a
//!   pre-extracted (or fixture) `.git` directory. Cross-platform and used
//!   directly by tests that cannot exercise the ext4 path.
//! - [`debugfs_rdump`] (Linux only): extract a single path from an ext4 image
//!   into a host directory using `debugfs`, without mounting.
//! - [`scrub_symlinks`]: remove all symlinks from an extracted tree before
//!   passing it to `git fetch` or the narrow agent-history copy.
//!
//! All paths share the same hardening: the `-c` flags + `GIT_CONFIG_*` env
//! + explicit `HEAD:refs/heads/runs/<run-id>` (plus optional
//!   `HEAD:refs/heads/<output_branch>`) refspec — never a wildcard. Namespace
//!   validation is delegated to [`BranchPool::validate_run_output_targets`]
//!   so the reserved-namespace and already-exists rules live in one place.

use std::path::Path;

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
    /// The hardened `git fetch` returned a non-zero status.
    Git { stderr: String },
    /// `debugfs rdump` returned a non-zero status or an unexpected error.
    #[cfg(target_os = "linux")]
    Debugfs { context: String, stderr: String },
}

impl std::fmt::Display for SandboxFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Pool(e) => write!(f, "pool error: {e}"),
            Self::Git { stderr } => write!(f, "hardened git fetch failed: {stderr}"),
            #[cfg(target_os = "linux")]
            Self::Debugfs { context, stderr } => {
                write!(f, "debugfs error in {context}: {stderr}")
            }
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

#[cfg(target_os = "linux")]
/// Remove every symlink found recursively under `dir`.
///
/// Called after `debugfs rdump` to ensure no adversarial symlinks planted by
/// the agent inside the Workspace ext4 survive into the host-side extraction
/// directory. Regular files and directories are left intact.
pub fn scrub_symlinks(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // DirEntry::metadata uses lstat — does not follow symlinks.
        let meta = entry.metadata()?;
        if meta.file_type().is_symlink() {
            std::fs::remove_file(entry.path())?;
        } else if meta.file_type().is_dir() {
            scrub_symlinks(&entry.path())?;
        }
    }
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

/// Extract `src_path` (a path inside `ext4_path`) into `dst_dir` using
/// `debugfs rdump`, without mounting the filesystem.
///
/// `dst_dir` must already exist. A directory source is extracted as a
/// subdirectory of `dst_dir` with the same base name; a file source is
/// placed directly in `dst_dir`. No `CAP_SYS_ADMIN` is required.
///
/// Returns `Ok(true)` if the path was extracted, `Ok(false)` if the path
/// does not exist inside the image (debugfs exits 0 but creates no output).
#[cfg(target_os = "linux")]
pub async fn debugfs_rdump(
    ext4_path: &Path,
    src_path: &str,
    dst_dir: &Path,
) -> Result<bool, SandboxFetchError> {
    let base = Path::new(src_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| SandboxFetchError::Debugfs {
            context: format!("rdump: invalid src_path {src_path}"),
            stderr: String::new(),
        })?;

    let cmd_str = format!("rdump {} {}", src_path, dst_dir.display());
    let out = Command::new("debugfs")
        .args(["-R", &cmd_str, &ext4_path.to_string_lossy()])
        .output()
        .await?;

    if !out.status.success() {
        return Err(SandboxFetchError::Debugfs {
            context: format!("rdump {src_path} from {}", ext4_path.display()),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }

    // If debugfs silently skipped a missing path, the expected output won't exist.
    Ok(dst_dir.join(base).exists())
}

/// Read commits out of a Workspace ext4 into `pool` using `debugfs rdump`
/// (no `losetup`/`mount`/`CAP_SYS_ADMIN`). Any symlinks present in the
/// extracted `.git` are scrubbed before the hardened `git fetch` runs.
///
/// `ext4_path` must contain a `.git` directory at the root of the Workspace.
/// `user_script_uid` is consulted only when the current process is root.
#[cfg(target_os = "linux")]
pub async fn sandbox_fetch_from_ext4(
    pool: &BranchPool,
    ext4_path: &Path,
    run_id: &str,
    output_branch: Option<&str>,
    user_script_uid: u32,
) -> Result<(), SandboxFetchError> {
    pool.validate_run_output_targets(run_id, output_branch).await?;

    let tmp = tempfile::TempDir::new()?;
    let tmp_path = tmp.path();

    let found = debugfs_rdump(ext4_path, "/.git", tmp_path).await?;
    if !found {
        return Err(SandboxFetchError::Debugfs {
            context: format!("rdump /.git from {}", ext4_path.display()),
            stderr: ".git not found in workspace ext4".into(),
        });
    }
    scrub_symlinks(&tmp_path.join(".git"))?;

    fetch_pool_from_git_dir(
        pool,
        &tmp_path.join(".git"),
        run_id,
        output_branch,
        user_script_uid,
    )
    .await
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

    // ── scrub_symlinks ────────────────────────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn scrub_symlinks_removes_symlinks_and_leaves_regular_files() {
        use std::os::unix::fs::symlink;
        let dir = make_temp_dir("scrub-sym");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("regular.txt"), b"keep").unwrap();
        std::fs::write(dir.join("sub").join("nested.txt"), b"keep").unwrap();
        // Absolute out-of-tree symlink — the adversarial case.
        symlink("/etc/passwd", dir.join("bad_link")).unwrap();
        // Relative in-tree symlink — also scrubbed.
        symlink("../regular.txt", dir.join("sub").join("relative_link")).unwrap();

        scrub_symlinks(&dir).unwrap();

        assert!(dir.join("regular.txt").exists(), "regular file must survive");
        assert!(dir.join("sub").join("nested.txt").exists(), "nested file must survive");
        assert!(!dir.join("bad_link").exists(), "absolute symlink must be removed");
        assert!(
            !dir.join("sub").join("relative_link").exists(),
            "relative symlink must be removed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── debugfs_rdump + sandbox_fetch_from_ext4 (Linux only, requires mkfs.ext4 + debugfs) ──

    #[cfg(target_os = "linux")]
    fn make_workspace_ext4(src: &Path, size: &str) -> PathBuf {
        let ext4 = src.with_extension("ext4");
        let status = StdCommand::new("mkfs.ext4")
            .args([
                "-F",
                "-q",
                "-d",
                &src.to_string_lossy(),
                &ext4.to_string_lossy(),
                size,
            ])
            .status()
            .expect("mkfs.ext4 must be available for ext4 fixture tests");
        assert!(status.success(), "mkfs.ext4 failed for {src:?}");
        ext4
    }

    #[cfg(target_os = "linux")]
    fn has_debugfs() -> bool {
        StdCommand::new("debugfs").arg("-V").output().is_ok()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn debugfs_rdump_extracts_directory_from_ext4() {
        if !has_debugfs() {
            return;
        }
        let src = make_temp_dir("dbgfs-src");
        std::fs::create_dir_all(src.join("mydir")).unwrap();
        std::fs::write(src.join("mydir").join("hello.txt"), b"hello\n").unwrap();
        let ext4 = make_workspace_ext4(&src, "10M");

        let dst = make_temp_dir("dbgfs-dst");
        let found = debugfs_rdump(&ext4, "/mydir", &dst).await.unwrap();

        assert!(found, "/mydir must be found in ext4");
        assert_eq!(
            std::fs::read(dst.join("mydir").join("hello.txt")).unwrap(),
            b"hello\n"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_file(&ext4).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn debugfs_rdump_returns_false_for_missing_path() {
        if !has_debugfs() {
            return;
        }
        let src = make_temp_dir("dbgfs-miss-src");
        let ext4 = make_workspace_ext4(&src, "10M");

        let dst = make_temp_dir("dbgfs-miss-dst");
        let found = debugfs_rdump(&ext4, "/nonexistent", &dst).await.unwrap();

        assert!(!found, "nonexistent path must return Ok(false)");

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_file(&ext4).ok();
        std::fs::remove_dir_all(&dst).ok();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sandbox_fetch_from_ext4_writes_pool_ref_via_debugfs() {
        if !has_debugfs() {
            return;
        }
        let (work, sha) = make_workspace_repo("ext4-pool");
        let ext4 = make_workspace_ext4(&work, "16M");

        let pool_dir = make_temp_dir("pool-ext4");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        sandbox_fetch_from_ext4(&pool, &ext4, "01HEXT1", None, current_uid())
            .await
            .unwrap();

        assert_eq!(ref_sha(&pool_dir, "refs/heads/runs/01HEXT1"), sha);

        std::fs::remove_dir_all(&work).ok();
        std::fs::remove_file(&ext4).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sandbox_fetch_from_ext4_also_writes_output_branch() {
        if !has_debugfs() {
            return;
        }
        let (work, sha) = make_workspace_repo("ext4-out");
        let ext4 = make_workspace_ext4(&work, "16M");

        let pool_dir = make_temp_dir("pool-ext4-out");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        sandbox_fetch_from_ext4(&pool, &ext4, "01HEXT2", Some("feature/done"), current_uid())
            .await
            .unwrap();

        assert_eq!(ref_sha(&pool_dir, "refs/heads/runs/01HEXT2"), sha);
        assert_eq!(ref_sha(&pool_dir, "refs/heads/feature/done"), sha);

        std::fs::remove_dir_all(&work).ok();
        std::fs::remove_file(&ext4).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[cfg(all(target_os = "linux", unix))]
    #[tokio::test]
    async fn sandbox_fetch_from_ext4_symlink_in_git_is_scrubbed() {
        // A symlink planted inside .git/ by an adversarial agent must not
        // survive into the host extraction dir (it is scrubbed before git fetch).
        if !has_debugfs() {
            return;
        }
        use std::os::unix::fs::symlink;
        let (work, sha) = make_workspace_repo("ext4-sym");
        // Plant an adversarial symlink inside .git/hooks/
        std::fs::create_dir_all(work.join(".git").join("hooks")).unwrap();
        symlink("/etc/passwd", work.join(".git").join("hooks").join("escape")).unwrap();

        let ext4 = make_workspace_ext4(&work, "16M");

        let pool_dir = make_temp_dir("pool-ext4-sym");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        // Extraction must succeed (symlink scrubbed, not followed).
        sandbox_fetch_from_ext4(&pool, &ext4, "01HEXT3", None, current_uid())
            .await
            .unwrap();

        assert_eq!(ref_sha(&pool_dir, "refs/heads/runs/01HEXT3"), sha);

        std::fs::remove_dir_all(&work).ok();
        std::fs::remove_file(&ext4).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }
}
