//! Branch Pool — the crucible-managed git store owned by a Session.
//!
//! All git invocations crucible makes against the Pool funnel through this
//! module's public verbs so the future hardening surface (ADR-0011 et al.)
//! is single-sited. See ADR-0010 for the surrounding Session model.

// Scaffolding for slices 05+ (Session lifecycle, run-end-to-end, close).
// Tests exercise the full public surface; main.rs is wired in by slice 05.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Output;
use tokio::process::Command;

pub const RESERVED_HOST: &str = "host/";
pub const RESERVED_RUNS: &str = "runs/";

#[derive(Debug)]
pub enum BranchPoolError {
    Io(std::io::Error),
    Git { context: String, stderr: String },
    ReservedNamespace { name: String, namespace: &'static str },
    RefAlreadyExists { name: String },
    NotFastForward { pool_ref: String, host_ref: String },
}

impl std::fmt::Display for BranchPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Git { context, stderr } => write!(f, "git error in {context}: {stderr}"),
            Self::ReservedNamespace { name, namespace } => write!(
                f,
                "ref name {name:?} falls in reserved namespace {namespace:?}"
            ),
            Self::RefAlreadyExists { name } => {
                write!(f, "ref {name:?} already exists in pool; refusing to overwrite")
            }
            Self::NotFastForward { pool_ref, host_ref } => write!(
                f,
                "non-fast-forward push {pool_ref} -> {host_ref} requires force: true"
            ),
        }
    }
}

impl std::error::Error for BranchPoolError {}

impl From<std::io::Error> for BranchPoolError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Filter for [`BranchPool::list_refs`].
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum NamespaceFilter {
    #[default]
    All,
    Host,
    Runs,
    UserNamed,
}

/// A single line of a close-time manifest.
///
/// `pool_ref` and `host_ref` are short branch names (no `refs/heads/` prefix).
/// `force: true` opts this one pair into a non-FF push.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub pool_ref: String,
    pub host_ref: String,
    pub force: bool,
}

#[derive(Debug)]
pub struct BranchPool {
    path: PathBuf,
}

impl BranchPool {
    /// Initialise a fresh bare git repo at `path`. Creates intermediate
    /// directories. Errors if the path already contains a non-empty repo.
    pub async fn init(path: PathBuf) -> Result<Self, BranchPoolError> {
        std::fs::create_dir_all(&path)?;
        run_git(&["init", "--bare", "--quiet"], Some(&path)).await?;
        Ok(Self { path })
    }

    /// Re-attach to an existing Pool on disk.
    pub fn open(path: PathBuf) -> Result<Self, BranchPoolError> {
        if !path.join("HEAD").exists() {
            return Err(BranchPoolError::Git {
                context: "open".into(),
                stderr: format!("{} does not look like a bare git repo", path.display()),
            });
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Copy the declared `refs` from `host_repo` into the Pool under
    /// `host/<ref>` names. Only the declared refs are pulled — anything
    /// else in the host's namespace is ignored.
    pub async fn mirror_from_host(
        &self,
        host_repo: &Path,
        refs: &[String],
    ) -> Result<(), BranchPoolError> {
        if refs.is_empty() {
            return Ok(());
        }
        let mut args: Vec<String> = vec!["fetch".into(), "--no-tags".into(), path_to_str(host_repo)];
        for r in refs {
            // `+` lets a later mirror overwrite the previous host/<r> tip
            args.push(format!("+refs/heads/{r}:refs/heads/host/{r}"));
        }
        run_git(&str_args(&args), Some(&self.path)).await?;
        Ok(())
    }

    /// Write `runs/<run_id>` (always) and `<output_branch>` (if supplied)
    /// into the Pool, both pointing at `source_repo`'s HEAD. Refuses to
    /// overwrite an existing ref. Rejects `output_branch` in reserved
    /// `host/*` or `runs/*` namespaces.
    pub async fn accept_run_output(
        &self,
        run_id: &str,
        output_branch: Option<&str>,
        source_repo: &Path,
    ) -> Result<(), BranchPoolError> {
        if let Some(name) = output_branch {
            validate_user_ref_name(name)?;
            if branch_exists(&self.path, name).await? {
                return Err(BranchPoolError::RefAlreadyExists { name: name.into() });
            }
        }
        let audit = format!("runs/{run_id}");
        if branch_exists(&self.path, &audit).await? {
            return Err(BranchPoolError::RefAlreadyExists { name: audit });
        }
        let mut args: Vec<String> = vec![
            "fetch".into(),
            "--no-tags".into(),
            path_to_str(source_repo),
            format!("HEAD:refs/heads/{audit}"),
        ];
        if let Some(name) = output_branch {
            args.push(format!("HEAD:refs/heads/{name}"));
        }
        run_git(&str_args(&args), Some(&self.path)).await?;
        Ok(())
    }

    /// List branch refs in the Pool, optionally filtered to a namespace.
    pub async fn list_refs(
        &self,
        filter: NamespaceFilter,
    ) -> Result<Vec<String>, BranchPoolError> {
        let out = run_git(
            &["for-each-ref", "--format=%(refname:short)", "refs/heads/"],
            Some(&self.path),
        )
        .await?;
        let mut names: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect();
        names.retain(|n| match filter {
            NamespaceFilter::All => true,
            NamespaceFilter::Host => n.starts_with(RESERVED_HOST),
            NamespaceFilter::Runs => n.starts_with(RESERVED_RUNS),
            NamespaceFilter::UserNamed => {
                !n.starts_with(RESERVED_HOST) && !n.starts_with(RESERVED_RUNS)
            }
        });
        names.sort();
        Ok(names)
    }

    /// Push a manifest of `(pool_ref, host_ref, force)` tuples to `host_repo`.
    ///
    /// FF-only by default; per-pair `force: true` opts that one pair into
    /// non-FF. The entire manifest is validated against the host repo before
    /// any push is attempted — any non-FF pair without `force: true` aborts
    /// the whole call.
    ///
    /// Audit refs (`runs/*`) are silently skipped — they are never pushed.
    pub async fn push_manifest(
        &self,
        host_repo: &Path,
        manifest: &[ManifestEntry],
    ) -> Result<(), BranchPoolError> {
        let kept: Vec<&ManifestEntry> = manifest
            .iter()
            .filter(|e| !e.pool_ref.starts_with(RESERVED_RUNS))
            .collect();

        // Validation pass. For each pair, if the host already has the ref,
        // fetch its tip into a temp namespace and check is-ancestor.
        // Clean up temp refs even on failure so the Pool isn't littered.
        let mut temp_refs: Vec<String> = Vec::new();
        let validation = self
            .validate_manifest(host_repo, &kept, &mut temp_refs)
            .await;
        for t in &temp_refs {
            let _ = run_git(&["update-ref", "-d", t], Some(&self.path)).await;
        }
        validation?;

        if kept.is_empty() {
            return Ok(());
        }

        let mut args: Vec<String> = vec![
            "push".into(),
            "--atomic".into(),
            path_to_str(host_repo),
        ];
        for e in &kept {
            let prefix = if e.force { "+" } else { "" };
            args.push(format!(
                "{prefix}refs/heads/{}:refs/heads/{}",
                e.pool_ref, e.host_ref
            ));
        }
        run_git(&str_args(&args), Some(&self.path)).await?;
        Ok(())
    }

    async fn validate_manifest(
        &self,
        host_repo: &Path,
        kept: &[&ManifestEntry],
        temp_refs: &mut Vec<String>,
    ) -> Result<(), BranchPoolError> {
        for (i, e) in kept.iter().enumerate() {
            // pool_ref must resolve in the Pool
            let pool_sha = rev_parse(&self.path, &format!("refs/heads/{}", e.pool_ref)).await?;
            // host_ref's current tip (None ⇒ new branch on host, trivially FF)
            let host_sha = ls_remote(host_repo, &format!("refs/heads/{}", e.host_ref)).await?;
            let Some(host_sha) = host_sha else { continue };
            if e.force {
                continue;
            }
            // Pull host_sha into a unique temp ref so the ancestor check is local
            let temp = format!("refs/crucible-validate/{i}");
            run_git(
                &[
                    "fetch",
                    "--no-tags",
                    &path_to_str(host_repo),
                    &format!("refs/heads/{}:{}", e.host_ref, temp),
                ],
                Some(&self.path),
            )
            .await?;
            temp_refs.push(temp);
            if !is_ancestor(&self.path, &host_sha, &pool_sha).await? {
                return Err(BranchPoolError::NotFastForward {
                    pool_ref: e.pool_ref.clone(),
                    host_ref: e.host_ref.clone(),
                });
            }
        }
        Ok(())
    }

    /// Remove the Pool's on-disk storage. After this returns, `self` is no
    /// longer backed by a directory and any further verb will fail.
    pub fn wipe(&self) -> Result<(), BranchPoolError> {
        if self.path.exists() {
            std::fs::remove_dir_all(&self.path)?;
        }
        Ok(())
    }
}

fn validate_user_ref_name(name: &str) -> Result<(), BranchPoolError> {
    if name.starts_with(RESERVED_HOST) {
        return Err(BranchPoolError::ReservedNamespace {
            name: name.into(),
            namespace: RESERVED_HOST,
        });
    }
    if name.starts_with(RESERVED_RUNS) {
        return Err(BranchPoolError::ReservedNamespace {
            name: name.into(),
            namespace: RESERVED_RUNS,
        });
    }
    Ok(())
}

fn path_to_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

fn str_args(args: &[String]) -> Vec<&str> {
    args.iter().map(|s| s.as_str()).collect()
}

async fn run_git(args: &[&str], cwd: Option<&Path>) -> Result<Output, BranchPoolError> {
    let mut cmd = Command::new("git");
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    let out = cmd.args(args).output().await?;
    if !out.status.success() {
        return Err(BranchPoolError::Git {
            context: format!("git {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(out)
}

async fn branch_exists(repo: &Path, short_name: &str) -> Result<bool, BranchPoolError> {
    let full = format!("refs/heads/{short_name}");
    let out = Command::new("git")
        .current_dir(repo)
        .args(["show-ref", "--verify", "--quiet", &full])
        .output()
        .await?;
    Ok(out.status.success())
}

async fn rev_parse(repo: &Path, name: &str) -> Result<String, BranchPoolError> {
    let out = run_git(&["rev-parse", "--verify", name], Some(repo)).await?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn ls_remote(repo: &Path, name: &str) -> Result<Option<String>, BranchPoolError> {
    let url = path_to_str(repo);
    let out = run_git(&["ls-remote", &url, name], None).await?;
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.lines()
        .next()
        .and_then(|l| l.split_whitespace().next().map(|x| x.to_string()))
        .filter(|s| !s.is_empty()))
}

async fn is_ancestor(repo: &Path, ancestor: &str, descendant: &str) -> Result<bool, BranchPoolError> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .output()
        .await?;
    Ok(out.status.success())
}

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
            "crucible-bp-{suffix}-{pid}-{nanos}-{n}"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run_git_sync(args: &[&str]) {
        let status = StdCommand::new("git").args(args).status().unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn run_git_sync_in(cwd: &Path, args: &[&str]) {
        let status = StdCommand::new("git")
            .current_dir(cwd)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} in {cwd:?} failed");
    }

    fn make_host_repo(suffix: &str) -> PathBuf {
        let dir = make_temp_dir(suffix);
        run_git_sync(&["-C", dir.to_str().unwrap(), "init", "-b", "main", "--quiet"]);
        run_git_sync_in(&dir, &["config", "user.email", "host@test"]);
        run_git_sync_in(&dir, &["config", "user.name", "Host"]);
        std::fs::write(dir.join("README.md"), "host\n").unwrap();
        run_git_sync_in(&dir, &["add", "README.md"]);
        run_git_sync_in(&dir, &["commit", "-m", "host init", "--quiet"]);
        dir
    }

    fn make_bare_host_repo(suffix: &str) -> PathBuf {
        // A bare repo we can push to without git's "refusing to update the
        // currently checked out branch" guard.
        let dir = make_temp_dir(suffix);
        run_git_sync(&["init", "--bare", "-b", "main", "--quiet", dir.to_str().unwrap()]);
        dir
    }

    fn seed_bare_with_commit(bare: &Path) -> String {
        let work = make_temp_dir("seed-work");
        run_git_sync_in(&work, &["init", "-b", "main", "--quiet"]);
        run_git_sync_in(&work, &["config", "user.email", "seed@test"]);
        run_git_sync_in(&work, &["config", "user.name", "Seed"]);
        std::fs::write(work.join("seed.txt"), "seed\n").unwrap();
        run_git_sync_in(&work, &["add", "seed.txt"]);
        run_git_sync_in(&work, &["commit", "-m", "seed", "--quiet"]);
        let sha = head_sha(&work);
        run_git_sync_in(&work, &["push", bare.to_str().unwrap(), "main:main"]);
        std::fs::remove_dir_all(&work).ok();
        sha
    }

    fn head_sha(repo: &Path) -> String {
        let out = StdCommand::new("git")
            .current_dir(repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn ref_sha(repo: &Path, full_ref: &str) -> String {
        let out = StdCommand::new("git")
            .current_dir(repo)
            .args(["rev-parse", full_ref])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn add_extra_commit(repo: &Path, file: &str, msg: &str) -> String {
        std::fs::write(repo.join(file), format!("{msg}\n")).unwrap();
        run_git_sync_in(repo, &["add", file]);
        run_git_sync_in(repo, &["commit", "-m", msg, "--quiet"]);
        head_sha(repo)
    }

    fn host_branches(repo: &Path) -> Vec<String> {
        let out = StdCommand::new("git")
            .current_dir(repo)
            .args(["for-each-ref", "--format=%(refname:short)", "refs/heads/"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect()
    }

    // --- init / wipe ---

    #[tokio::test]
    async fn init_creates_bare_repo() {
        let pool_dir = make_temp_dir("init");
        let _pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        assert!(pool_dir.join("HEAD").exists());
        assert!(pool_dir.join("objects").exists());
        assert!(pool_dir.join("refs").exists());
        // Bare repos have no working tree.
        assert!(!pool_dir.join(".git").exists());
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn wipe_removes_storage() {
        let pool_dir = make_temp_dir("wipe");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        assert!(pool_dir.exists());
        pool.wipe().unwrap();
        assert!(!pool_dir.exists());
    }

    #[tokio::test]
    async fn open_rejects_non_repo_path() {
        let dir = make_temp_dir("open-bad");
        let err = BranchPool::open(dir.clone()).unwrap_err();
        assert!(matches!(err, BranchPoolError::Git { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- mirror_from_host ---

    #[tokio::test]
    async fn mirror_copies_only_declared_refs() {
        let host = make_host_repo("mir-host");
        // Seed host with two extra refs, only one of which we'll mirror.
        run_git_sync_in(&host, &["branch", "feature"]);
        run_git_sync_in(&host, &["branch", "do-not-mirror"]);

        let pool_dir = make_temp_dir("mir-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.mirror_from_host(&host, &["main".into(), "feature".into()])
            .await
            .unwrap();

        let mut refs = pool.list_refs(NamespaceFilter::All).await.unwrap();
        refs.sort();
        assert_eq!(refs, vec!["host/feature".to_string(), "host/main".to_string()]);
        assert!(!refs.iter().any(|r| r.contains("do-not-mirror")));

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn mirror_points_at_same_sha_as_host() {
        let host = make_host_repo("mir-sha-host");
        let host_main_sha = head_sha(&host);

        let pool_dir = make_temp_dir("mir-sha-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.mirror_from_host(&host, &["main".into()]).await.unwrap();

        let pool_host_main = ref_sha(&pool_dir, "refs/heads/host/main");
        assert_eq!(host_main_sha, pool_host_main);

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn mirror_empty_refs_is_noop() {
        let host = make_host_repo("mir-empty-host");
        let pool_dir = make_temp_dir("mir-empty-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.mirror_from_host(&host, &[]).await.unwrap();
        assert!(pool.list_refs(NamespaceFilter::All).await.unwrap().is_empty());
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    // --- accept_run_output ---

    #[tokio::test]
    async fn accept_run_output_writes_audit_ref_always() {
        let source = make_host_repo("ar-src");
        let source_head = head_sha(&source);
        let pool_dir = make_temp_dir("ar-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        pool.accept_run_output("01HRUNA", None, &source).await.unwrap();

        assert_eq!(
            ref_sha(&pool_dir, "refs/heads/runs/01HRUNA"),
            source_head
        );
        std::fs::remove_dir_all(&source).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn accept_run_output_writes_both_refs_at_same_sha() {
        let source = make_host_repo("ar-both-src");
        let source_head = head_sha(&source);
        let pool_dir = make_temp_dir("ar-both-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        pool.accept_run_output("01HRUNB", Some("feature/x"), &source)
            .await
            .unwrap();

        let audit = ref_sha(&pool_dir, "refs/heads/runs/01HRUNB");
        let user = ref_sha(&pool_dir, "refs/heads/feature/x");
        assert_eq!(audit, source_head);
        assert_eq!(user, source_head);

        std::fs::remove_dir_all(&source).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn accept_run_output_rejects_overwrite_of_user_named_ref() {
        let source = make_host_repo("ar-over-src");
        let pool_dir = make_temp_dir("ar-over-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.accept_run_output("01HRUNC1", Some("feature/y"), &source)
            .await
            .unwrap();

        let err = pool
            .accept_run_output("01HRUNC2", Some("feature/y"), &source)
            .await
            .unwrap_err();
        match err {
            BranchPoolError::RefAlreadyExists { name } => assert_eq!(name, "feature/y"),
            other => panic!("expected RefAlreadyExists, got {other:?}"),
        }

        std::fs::remove_dir_all(&source).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn accept_run_output_rejects_reserved_host_namespace() {
        let source = make_host_repo("ar-res-host-src");
        let pool_dir = make_temp_dir("ar-res-host-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        let err = pool
            .accept_run_output("01HRUND", Some("host/sneaky"), &source)
            .await
            .unwrap_err();
        match err {
            BranchPoolError::ReservedNamespace { name, namespace } => {
                assert_eq!(name, "host/sneaky");
                assert_eq!(namespace, "host/");
            }
            other => panic!("expected ReservedNamespace, got {other:?}"),
        }
        std::fs::remove_dir_all(&source).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn accept_run_output_rejects_reserved_runs_namespace() {
        let source = make_host_repo("ar-res-runs-src");
        let pool_dir = make_temp_dir("ar-res-runs-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        let err = pool
            .accept_run_output("01HRUNE", Some("runs/forged"), &source)
            .await
            .unwrap_err();
        match err {
            BranchPoolError::ReservedNamespace { name, namespace } => {
                assert_eq!(name, "runs/forged");
                assert_eq!(namespace, "runs/");
            }
            other => panic!("expected ReservedNamespace, got {other:?}"),
        }
        std::fs::remove_dir_all(&source).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    // --- list_refs ---

    #[tokio::test]
    async fn list_refs_filters_by_namespace() {
        let source = make_host_repo("lr-src");
        let pool_dir = make_temp_dir("lr-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();

        pool.mirror_from_host(&source, &["main".into()]).await.unwrap();
        pool.accept_run_output("01HRUNL", Some("feature/done"), &source)
            .await
            .unwrap();

        let all = pool.list_refs(NamespaceFilter::All).await.unwrap();
        assert!(all.contains(&"host/main".into()));
        assert!(all.contains(&"runs/01HRUNL".into()));
        assert!(all.contains(&"feature/done".into()));

        let host = pool.list_refs(NamespaceFilter::Host).await.unwrap();
        assert_eq!(host, vec!["host/main".to_string()]);

        let runs = pool.list_refs(NamespaceFilter::Runs).await.unwrap();
        assert_eq!(runs, vec!["runs/01HRUNL".to_string()]);

        let user = pool.list_refs(NamespaceFilter::UserNamed).await.unwrap();
        assert_eq!(user, vec!["feature/done".to_string()]);

        std::fs::remove_dir_all(&source).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    // --- push_manifest ---

    #[tokio::test]
    async fn push_manifest_ff_pushes_all_pairs_in_one_call() {
        // Host (bare): currently empty.
        let host = make_bare_host_repo("pm-ff-host");
        // Pool gets a base from a separate seed repo, then advances on two branches.
        let pool_dir = make_temp_dir("pm-ff-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        let seed = make_host_repo("pm-ff-seed");
        // Mirror seed/main as `host/main` (no role; just gets commits into pool)
        pool.mirror_from_host(&seed, &["main".into()]).await.unwrap();

        // Create two work branches in the pool descending from host/main.
        run_git_sync_in(&pool_dir, &["branch", "feature/a", "host/main"]);
        run_git_sync_in(&pool_dir, &["branch", "feature/b", "host/main"]);

        let manifest = vec![
            ManifestEntry { pool_ref: "feature/a".into(), host_ref: "release/a".into(), force: false },
            ManifestEntry { pool_ref: "feature/b".into(), host_ref: "release/b".into(), force: false },
        ];
        pool.push_manifest(&host, &manifest).await.unwrap();

        let hb = host_branches(&host);
        assert!(hb.contains(&"release/a".into()));
        assert!(hb.contains(&"release/b".into()));

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&seed).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn push_manifest_aborts_when_any_pair_is_non_ff_without_force() {
        // Host has a `protected` branch at SHA_X (one commit ahead of seed).
        // Pool tries to push a branch at SHA_seed (older) → not FF.
        // A second pair would be a clean new-branch push if it ran.
        let host = make_bare_host_repo("pm-abort-host");
        let _seed_sha = seed_bare_with_commit(&host);
        // Advance host's `protected` ref so pool's "older" tip is non-FF.
        // We do this by cloning bare → working → adding commit → pushing.
        let work = make_temp_dir("pm-abort-work");
        run_git_sync(&["clone", "--quiet", host.to_str().unwrap(), work.to_str().unwrap()]);
        run_git_sync_in(&work, &["config", "user.email", "w@test"]);
        run_git_sync_in(&work, &["config", "user.name", "W"]);
        run_git_sync_in(&work, &["checkout", "-b", "protected"]);
        std::fs::write(work.join("p.txt"), "p\n").unwrap();
        run_git_sync_in(&work, &["add", "p.txt"]);
        run_git_sync_in(&work, &["commit", "-m", "advance protected", "--quiet"]);
        run_git_sync_in(&work, &["push", "origin", "protected:protected"]);
        let host_protected_sha = ref_sha(&work, "HEAD");
        std::fs::remove_dir_all(&work).ok();

        // Set up pool with the older main commit only.
        let pool_dir = make_temp_dir("pm-abort-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.mirror_from_host(&host, &["main".into()]).await.unwrap();
        // Older tip — non-FF over host_protected_sha.
        run_git_sync_in(&pool_dir, &["branch", "stale", "host/main"]);
        // A perfectly valid new-branch push.
        run_git_sync_in(&pool_dir, &["branch", "newbie", "host/main"]);
        let host_branches_before = host_branches(&host);

        let manifest = vec![
            ManifestEntry { pool_ref: "newbie".into(), host_ref: "newbie".into(), force: false },
            ManifestEntry { pool_ref: "stale".into(),  host_ref: "protected".into(), force: false },
        ];
        let err = pool.push_manifest(&host, &manifest).await.unwrap_err();
        assert!(matches!(err, BranchPoolError::NotFastForward { .. }), "got {err:?}");

        // Host unchanged: protected still at the advanced SHA, no new `newbie`.
        let after = host_branches(&host);
        assert_eq!(after, host_branches_before, "host refs must be untouched");
        assert_eq!(ref_sha(&host, "refs/heads/protected"), host_protected_sha);

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn push_manifest_force_allows_non_ff_pair() {
        let host = make_bare_host_repo("pm-force-host");
        let _ = seed_bare_with_commit(&host);
        // Advance host's `protected` past where the pool will be.
        let work = make_temp_dir("pm-force-work");
        run_git_sync(&["clone", "--quiet", host.to_str().unwrap(), work.to_str().unwrap()]);
        run_git_sync_in(&work, &["config", "user.email", "w@test"]);
        run_git_sync_in(&work, &["config", "user.name", "W"]);
        run_git_sync_in(&work, &["checkout", "-b", "protected"]);
        let _ = add_extra_commit(&work, "p.txt", "advance");
        run_git_sync_in(&work, &["push", "origin", "protected:protected"]);
        std::fs::remove_dir_all(&work).ok();

        // Pool at older tip; force push.
        let pool_dir = make_temp_dir("pm-force-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.mirror_from_host(&host, &["main".into()]).await.unwrap();
        run_git_sync_in(&pool_dir, &["branch", "rewrite", "host/main"]);
        let pool_rewrite_sha = ref_sha(&pool_dir, "refs/heads/rewrite");

        let manifest = vec![ManifestEntry {
            pool_ref: "rewrite".into(),
            host_ref: "protected".into(),
            force: true,
        }];
        pool.push_manifest(&host, &manifest).await.unwrap();
        assert_eq!(ref_sha(&host, "refs/heads/protected"), pool_rewrite_sha);

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn push_manifest_never_pushes_runs_namespace() {
        let host = make_bare_host_repo("pm-runs-host");
        let pool_dir = make_temp_dir("pm-runs-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        let seed = make_host_repo("pm-runs-seed");
        pool.accept_run_output("01HRUNS", None, &seed).await.unwrap();
        pool.mirror_from_host(&seed, &["main".into()]).await.unwrap();
        run_git_sync_in(&pool_dir, &["branch", "shippable", "host/main"]);

        let manifest = vec![
            ManifestEntry { pool_ref: "runs/01HRUNS".into(), host_ref: "runs/01HRUNS".into(), force: false },
            ManifestEntry { pool_ref: "shippable".into(),    host_ref: "release/x".into(),    force: false },
        ];
        pool.push_manifest(&host, &manifest).await.unwrap();

        let hb = host_branches(&host);
        assert!(hb.contains(&"release/x".into()));
        assert!(!hb.iter().any(|n| n.starts_with("runs/")));

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&seed).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn push_manifest_with_only_runs_entries_is_clean_noop() {
        let host = make_bare_host_repo("pm-only-runs-host");
        let host_before = host_branches(&host);
        let pool_dir = make_temp_dir("pm-only-runs-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        let seed = make_host_repo("pm-only-runs-seed");
        pool.accept_run_output("01HRUNZ", None, &seed).await.unwrap();
        let manifest = vec![ManifestEntry {
            pool_ref: "runs/01HRUNZ".into(),
            host_ref: "runs/01HRUNZ".into(),
            force: false,
        }];
        pool.push_manifest(&host, &manifest).await.unwrap();
        assert_eq!(host_branches(&host), host_before);
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&seed).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    #[tokio::test]
    async fn push_manifest_validation_leaves_no_temp_refs() {
        // Validation fetches host refs into refs/crucible-validate/<i>;
        // assert these are cleaned up regardless of validation outcome.
        let host = make_bare_host_repo("pm-clean-host");
        let _ = seed_bare_with_commit(&host);
        let work = make_temp_dir("pm-clean-work");
        run_git_sync(&["clone", "--quiet", host.to_str().unwrap(), work.to_str().unwrap()]);
        run_git_sync_in(&work, &["config", "user.email", "w@test"]);
        run_git_sync_in(&work, &["config", "user.name", "W"]);
        run_git_sync_in(&work, &["checkout", "-b", "protected"]);
        let _ = add_extra_commit(&work, "p.txt", "advance");
        run_git_sync_in(&work, &["push", "origin", "protected:protected"]);
        std::fs::remove_dir_all(&work).ok();

        let pool_dir = make_temp_dir("pm-clean-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.mirror_from_host(&host, &["main".into()]).await.unwrap();
        run_git_sync_in(&pool_dir, &["branch", "stale", "host/main"]);

        let manifest = vec![ManifestEntry {
            pool_ref: "stale".into(),
            host_ref: "protected".into(),
            force: false,
        }];
        let _ = pool.push_manifest(&host, &manifest).await; // expected NotFastForward

        // No refs/crucible-validate/* should remain.
        let listing = StdCommand::new("git")
            .current_dir(&pool_dir)
            .args(["for-each-ref", "--format=%(refname)", "refs/crucible-validate/"])
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&listing.stdout);
        assert!(out.trim().is_empty(), "leftover temp refs:\n{out}");

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }
}
