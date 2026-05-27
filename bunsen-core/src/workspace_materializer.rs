//! Workspace materialiser — sources Run Workspaces from a Session's
//! [`crate::branch_pool::BranchPool`] only.
//!
//! Per ADR-0010, the host repo is never read at materialise time. A
//! [`BranchingStrategy::PoolClone`] that names a ref the Session did not
//! mirror at open fails loudly — there is no lazy fetch fallback.

// Scaffolding for slice 09 (Session::run wires this in). Tests exercise
// the full public surface today.
#![allow(dead_code)]

use std::path::Path;

use crate::run_spec::BranchingStrategy;

#[derive(Debug)]
pub enum WorkspaceMaterializerError {
    Io(std::io::Error),
    Git { context: String, stderr: String },
    PoolRefMissing { name: String },
}

impl std::fmt::Display for WorkspaceMaterializerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Git { context, stderr } => write!(f, "git error in {context}: {stderr}"),
            Self::PoolRefMissing { name } => write!(
                f,
                "pool ref {name:?} not found in pool; was it mirrored at session open?"
            ),
        }
    }
}

impl std::error::Error for WorkspaceMaterializerError {}

impl From<std::io::Error> for WorkspaceMaterializerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Materialise `workspace_path` from `pool_path` according to `strategy`.
///
/// `output_branch`, when supplied, is the name of the working branch HEAD
/// will point at after materialisation. When `None`, the working branch is
/// `runs/<run_id>` — the agent's commits land on top of this branch and are
/// fetched back into the Pool at Run end.
pub async fn materialize(
    pool_path: &Path,
    strategy: &BranchingStrategy,
    workspace_path: &Path,
    run_id: &str,
    output_branch: Option<&str>,
) -> Result<(), WorkspaceMaterializerError> {
    match strategy {
        BranchingStrategy::None => Ok(()),
        BranchingStrategy::PoolClone { base, import } => {
            pool_clone(pool_path, workspace_path, base, import, run_id, output_branch).await
        }
    }
}

async fn pool_clone(
    pool_path: &Path,
    workspace_path: &Path,
    base: &str,
    import: &[String],
    run_id: &str,
    output_branch: Option<&str>,
) -> Result<(), WorkspaceMaterializerError> {
    // Verify every requested ref exists in the Pool before we touch the
    // filesystem. A missing ref is the load-bearing failure mode for
    // "Session forgot to mirror this" — see ADR-0010.
    verify_pool_ref(pool_path, base).await?;
    for r in import {
        verify_pool_ref(pool_path, r).await?;
    }

    // `git clone` requires the target not to exist (or to be empty).
    if workspace_path.exists() {
        std::fs::remove_dir_all(workspace_path)?;
    }

    let pool_str = pool_path.to_string_lossy().into_owned();
    let ws_str = workspace_path.to_string_lossy().into_owned();

    // `--no-local` forces real fetch transport (no object hardlinks), so the
    // Workspace's `.git` is fully independent of the Pool's on-disk store —
    // important because the Workspace ends up as the body of an ext4 sent
    // into a Sandbox.
    run_git(&[
        "clone",
        "--single-branch",
        "--branch",
        base,
        "--no-local",
        &pool_str,
        &ws_str,
    ])
    .await?;

    for r in import {
        run_git(&[
            "-C",
            &ws_str,
            "fetch",
            "--no-tags",
            &pool_str,
            &format!("refs/heads/{r}:refs/heads/{r}"),
        ])
        .await?;
    }

    let working = match output_branch {
        Some(name) => name.to_string(),
        None => format!("runs/{run_id}"),
    };
    run_git(&["-C", &ws_str, "checkout", "-b", &working]).await?;

    Ok(())
}

async fn verify_pool_ref(
    pool_path: &Path,
    ref_name: &str,
) -> Result<(), WorkspaceMaterializerError> {
    let full = format!("refs/heads/{ref_name}");
    let out = tokio::process::Command::new("git")
        .current_dir(pool_path)
        .args(["show-ref", "--verify", "--quiet", &full])
        .output()
        .await?;
    if !out.status.success() {
        return Err(WorkspaceMaterializerError::PoolRefMissing {
            name: ref_name.into(),
        });
    }
    Ok(())
}

async fn run_git(args: &[&str]) -> Result<(), WorkspaceMaterializerError> {
    let out = tokio::process::Command::new("git").args(args).output().await?;
    if !out.status.success() {
        return Err(WorkspaceMaterializerError::Git {
            context: format!("git {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branch_pool::BranchPool;
    use std::path::PathBuf;
    use std::process::Command;
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
        let dir = std::env::temp_dir()
            .join(format!("bunsen-mat-{suffix}-{pid}-{nanos}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run_git_sync(args: &[&str]) {
        let status = Command::new("git").args(args).status().unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn run_git_sync_in(cwd: &Path, args: &[&str]) {
        let status = Command::new("git").current_dir(cwd).args(args).status().unwrap();
        assert!(status.success(), "git {args:?} in {cwd:?} failed");
    }

    fn make_host_repo(suffix: &str) -> PathBuf {
        let dir = make_temp_dir(suffix);
        run_git_sync(&["-C", dir.to_str().unwrap(), "init", "-b", "main", "--quiet"]);
        run_git_sync_in(&dir, &["config", "user.email", "host@test"]);
        run_git_sync_in(&dir, &["config", "user.name", "Host"]);
        std::fs::write(dir.join("README.md"), "host\n").unwrap();
        run_git_sync_in(&dir, &["add", "README.md"]);
        run_git_sync_in(&dir, &["commit", "-m", "init", "--quiet"]);
        dir
    }

    fn rev_parse(repo: &Path, name: &str) -> String {
        let out = Command::new("git")
            .current_dir(repo)
            .args(["rev-parse", name])
            .output()
            .unwrap();
        assert!(out.status.success(), "git rev-parse {name} failed");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn head_branch(repo: &Path) -> String {
        let out = Command::new("git")
            .current_dir(repo)
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn local_branches(repo: &Path) -> Vec<String> {
        let out = Command::new("git")
            .current_dir(repo)
            .args(["for-each-ref", "--format=%(refname:short)", "refs/heads/"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).lines().map(|s| s.to_string()).collect()
    }

    async fn make_pool_with_host_main(suffix: &str) -> (PathBuf, PathBuf, BranchPool) {
        let host = make_host_repo(suffix);
        let pool_dir = make_temp_dir(&format!("{suffix}-pool"));
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.mirror_from_host(&host, &["main".into()]).await.unwrap();
        (host, pool_dir, pool)
    }

    // ── BranchingStrategy::None ────────────────────────────────────────────

    #[tokio::test]
    async fn none_strategy_produces_empty_workspace_no_git() {
        let ws = make_temp_dir("none-ws");
        let pool_dir = make_temp_dir("none-pool");
        BranchPool::init(pool_dir.clone()).await.unwrap();

        materialize(&pool_dir, &BranchingStrategy::None, &ws, "01HNONE", None)
            .await
            .unwrap();

        let entries: Vec<_> = std::fs::read_dir(&ws).unwrap().collect();
        assert!(entries.is_empty(), "workspace must remain empty");
        assert!(!ws.join(".git").exists(), "no .git for BranchingStrategy::None");
        std::fs::remove_dir_all(&ws).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
    }

    // ── BranchingStrategy::PoolClone — base only ───────────────────────────

    #[tokio::test]
    async fn pool_clone_no_import_head_at_base_sha() {
        let (host, pool_dir, _pool) = make_pool_with_host_main("pc-base").await;
        let base_sha = rev_parse(&pool_dir, "refs/heads/host/main");
        let ws = make_temp_dir("pc-base-ws");
        std::fs::remove_dir_all(&ws).ok();

        materialize(
            &pool_dir,
            &BranchingStrategy::PoolClone {
                base: "host/main".into(),
                import: vec![],
            },
            &ws,
            "01HRUN1",
            None,
        )
        .await
        .unwrap();

        // HEAD's commit matches the base's commit.
        assert_eq!(rev_parse(&ws, "HEAD"), base_sha);
        // Working branch is named after run_id.
        assert_eq!(head_branch(&ws), "runs/01HRUN1");
        // The base ref is present as a local branch.
        let branches = local_branches(&ws);
        assert!(
            branches.contains(&"host/main".to_string()),
            "host/main missing from local branches: {branches:?}",
        );
        assert!(
            branches.contains(&"runs/01HRUN1".to_string()),
            "runs/01HRUN1 missing from local branches: {branches:?}",
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
        std::fs::remove_dir_all(&ws).ok();
    }

    #[tokio::test]
    async fn pool_clone_uses_output_branch_name_when_supplied() {
        let (host, pool_dir, _pool) = make_pool_with_host_main("pc-out").await;
        let ws = make_temp_dir("pc-out-ws");
        std::fs::remove_dir_all(&ws).ok();

        materialize(
            &pool_dir,
            &BranchingStrategy::PoolClone {
                base: "host/main".into(),
                import: vec![],
            },
            &ws,
            "01HRUNX",
            Some("feature/agent-output"),
        )
        .await
        .unwrap();

        assert_eq!(head_branch(&ws), "feature/agent-output");

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
        std::fs::remove_dir_all(&ws).ok();
    }

    // ── BranchingStrategy::PoolClone — with imports ───────────────────────

    #[tokio::test]
    async fn pool_clone_with_imports_creates_local_refs_and_merges() {
        // Seed two divergent branches in a host repo, mirror all three into a
        // pool, then materialise with base=host/main and import=[host/a,host/b].
        // The resulting workspace must be able to octopus-merge a and b.
        let host = make_host_repo("pc-imp-host");
        // base commit already exists on `main`. Create two non-conflicting
        // branches that each touch a different file.
        run_git_sync_in(&host, &["checkout", "-b", "feature-a"]);
        std::fs::write(host.join("a.txt"), "a\n").unwrap();
        run_git_sync_in(&host, &["add", "a.txt"]);
        run_git_sync_in(&host, &["commit", "-m", "add a", "--quiet"]);

        run_git_sync_in(&host, &["checkout", "main"]);
        run_git_sync_in(&host, &["checkout", "-b", "feature-b"]);
        std::fs::write(host.join("b.txt"), "b\n").unwrap();
        run_git_sync_in(&host, &["add", "b.txt"]);
        run_git_sync_in(&host, &["commit", "-m", "add b", "--quiet"]);
        run_git_sync_in(&host, &["checkout", "main"]);

        let pool_dir = make_temp_dir("pc-imp-pool");
        let pool = BranchPool::init(pool_dir.clone()).await.unwrap();
        pool.mirror_from_host(
            &host,
            &["main".into(), "feature-a".into(), "feature-b".into()],
        )
        .await
        .unwrap();

        let ws = make_temp_dir("pc-imp-ws");
        std::fs::remove_dir_all(&ws).ok();

        materialize(
            &pool_dir,
            &BranchingStrategy::PoolClone {
                base: "host/main".into(),
                import: vec!["host/feature-a".into(), "host/feature-b".into()],
            },
            &ws,
            "01HMERGE",
            None,
        )
        .await
        .unwrap();

        let branches = local_branches(&ws);
        assert!(
            branches.contains(&"host/feature-a".to_string()),
            "import ref a missing: {branches:?}",
        );
        assert!(
            branches.contains(&"host/feature-b".to_string()),
            "import ref b missing: {branches:?}",
        );

        // Octopus merge — succeeds when both branches are present and there
        // are no conflicts with HEAD.
        run_git_sync_in(&ws, &["config", "user.email", "ws@test"]);
        run_git_sync_in(&ws, &["config", "user.name", "WS"]);
        run_git_sync_in(
            &ws,
            &["merge", "--no-edit", "host/feature-a", "host/feature-b"],
        );
        assert!(ws.join("a.txt").exists(), "a.txt missing after merge");
        assert!(ws.join("b.txt").exists(), "b.txt missing after merge");

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
        std::fs::remove_dir_all(&ws).ok();
    }

    // ── BranchingStrategy::PoolClone — failure modes ──────────────────────

    #[tokio::test]
    async fn pool_clone_missing_base_ref_fails_loudly() {
        let (host, pool_dir, _pool) = make_pool_with_host_main("pc-miss").await;
        let ws = make_temp_dir("pc-miss-ws");
        std::fs::remove_dir_all(&ws).ok();

        let err = materialize(
            &pool_dir,
            &BranchingStrategy::PoolClone {
                base: "host/never-mirrored".into(),
                import: vec![],
            },
            &ws,
            "01HMISS",
            None,
        )
        .await
        .unwrap_err();

        match err {
            WorkspaceMaterializerError::PoolRefMissing { name } => {
                assert_eq!(name, "host/never-mirrored");
            }
            other => panic!("expected PoolRefMissing, got {other:?}"),
        }
        // No host fallback: workspace must remain empty / absent.
        assert!(
            !ws.exists() || std::fs::read_dir(&ws).unwrap().next().is_none(),
            "workspace must not be populated on missing-ref failure"
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
        std::fs::remove_dir_all(&ws).ok();
    }

    #[tokio::test]
    async fn pool_clone_missing_import_ref_fails_loudly() {
        let (host, pool_dir, _pool) = make_pool_with_host_main("pc-miss-imp").await;
        let ws = make_temp_dir("pc-miss-imp-ws");
        std::fs::remove_dir_all(&ws).ok();

        let err = materialize(
            &pool_dir,
            &BranchingStrategy::PoolClone {
                base: "host/main".into(),
                import: vec!["host/never-mirrored".into()],
            },
            &ws,
            "01HMISSIMP",
            None,
        )
        .await
        .unwrap_err();

        match err {
            WorkspaceMaterializerError::PoolRefMissing { name } => {
                assert_eq!(name, "host/never-mirrored");
            }
            other => panic!("expected PoolRefMissing, got {other:?}"),
        }

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&pool_dir).ok();
        std::fs::remove_dir_all(&ws).ok();
    }
}
