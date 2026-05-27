use std::path::Path;

#[derive(Debug)]
pub enum WorkspaceMaterializerError {
    MissingHostRepoPath,
    InvalidStrategy(String),
    GitError(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for WorkspaceMaterializerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHostRepoPath => write!(f, "branching_strategy requires host_repo_path"),
            Self::InvalidStrategy(s) => write!(f, "invalid branching strategy: {s}"),
            Self::GitError(msg) => write!(f, "git error: {msg}"),
            Self::IoError(e) => write!(f, "io error: {e}"),
        }
    }
}

pub async fn materialize(
    branching_strategy: Option<&str>,
    host_repo_path: Option<&str>,
    workspace_path: &Path,
    run_id: &str,
) -> Result<(), WorkspaceMaterializerError> {
    let strategy = match branching_strategy {
        None => return Ok(()),
        Some(s) => s,
    };

    let host_repo = host_repo_path.ok_or(WorkspaceMaterializerError::MissingHostRepoPath)?;

    if let Some(git_ref) = strategy.strip_prefix("fresh-clone:") {
        fresh_clone(host_repo, workspace_path, git_ref).await
    } else if strategy == "copy-worktree" {
        copy_worktree(host_repo, workspace_path).await
    } else if let Some(git_ref) = strategy.strip_prefix("worktree:") {
        worktree_add(host_repo, workspace_path, git_ref, run_id).await
    } else {
        Err(WorkspaceMaterializerError::InvalidStrategy(strategy.to_string()))
    }
}

async fn fresh_clone(
    host_repo: &str,
    workspace_path: &Path,
    git_ref: &str,
) -> Result<(), WorkspaceMaterializerError> {
    let output = tokio::process::Command::new("git")
        .args(["clone", "--branch", git_ref, "--no-local", host_repo,
               workspace_path.to_str().unwrap()])
        .output()
        .await
        .map_err(WorkspaceMaterializerError::IoError)?;

    if !output.status.success() {
        return Err(WorkspaceMaterializerError::GitError(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    Ok(())
}

async fn copy_worktree(
    host_repo: &str,
    workspace_path: &Path,
) -> Result<(), WorkspaceMaterializerError> {
    // "cp -a <src>/. <dst>" copies everything including hidden files
    let src = format!("{}/.", host_repo);
    let output = tokio::process::Command::new("cp")
        .args(["-a", &src, workspace_path.to_str().unwrap()])
        .output()
        .await
        .map_err(WorkspaceMaterializerError::IoError)?;

    if !output.status.success() {
        return Err(WorkspaceMaterializerError::GitError(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    Ok(())
}

async fn worktree_add(
    host_repo: &str,
    workspace_path: &Path,
    git_ref: &str,
    run_id: &str,
) -> Result<(), WorkspaceMaterializerError> {
    let branch = format!("bunsen/run-{run_id}");

    // git worktree add requires the target directory to not exist
    if workspace_path.exists() {
        std::fs::remove_dir_all(workspace_path)
            .map_err(WorkspaceMaterializerError::IoError)?;
    }

    let output = tokio::process::Command::new("git")
        .args([
            "-C", host_repo,
            "worktree", "add",
            "-b", &branch,
            workspace_path.to_str().unwrap(),
            git_ref,
        ])
        .output()
        .await
        .map_err(WorkspaceMaterializerError::IoError)?;

    if !output.status.success() {
        return Err(WorkspaceMaterializerError::GitError(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    fn make_temp_dir(suffix: &str) -> PathBuf {
        use std::time::SystemTime;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let pid = std::process::id();
        let dir = std::env::temp_dir()
            .join(format!("bunsen-test-{suffix}-{pid}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_test_git_repo(suffix: &str) -> PathBuf {
        let dir = make_temp_dir(suffix);
        let d = dir.to_str().unwrap();

        run_git(&["-C", d, "init", "-b", "main"]);
        run_git(&["-C", d, "config", "user.email", "test@example.com"]);
        run_git(&["-C", d, "config", "user.name", "Test"]);
        std::fs::write(dir.join("README.md"), "hello").unwrap();
        run_git(&["-C", d, "add", "."]);
        run_git(&["-C", d, "commit", "-m", "init"]);
        dir
    }

    fn run_git(args: &[&str]) {
        let status = Command::new("git").args(args).status().unwrap();
        assert!(status.success(), "git {:?} failed", args);
    }

    fn git_head(repo: &Path) -> String {
        let out = Command::new("git")
            .args(["-C", repo.to_str().unwrap(), "rev-parse", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    // --- tests ---

    #[tokio::test]
    async fn no_strategy_is_noop() {
        let workspace = make_temp_dir("noop");
        let result = materialize(None, None, &workspace, "run-noop").await;
        assert!(result.is_ok());
        let entries: Vec<_> = std::fs::read_dir(&workspace).unwrap().collect();
        assert!(entries.is_empty(), "workspace should remain empty");
        std::fs::remove_dir_all(&workspace).ok();
    }

    #[tokio::test]
    async fn fresh_clone_head_matches_host() {
        let host = make_test_git_repo("fc-host");
        let workspace = make_temp_dir("fc-ws");

        materialize(
            Some("fresh-clone:main"),
            Some(host.to_str().unwrap()),
            &workspace,
            "run-fc",
        )
        .await
        .unwrap();

        assert_eq!(git_head(&host), git_head(&workspace));
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&workspace).ok();
    }

    #[tokio::test]
    async fn fresh_clone_is_independent_of_host() {
        let host = make_test_git_repo("fc-ind-host");
        let workspace = make_temp_dir("fc-ind-ws");

        materialize(
            Some("fresh-clone:main"),
            Some(host.to_str().unwrap()),
            &workspace,
            "run-fc-ind",
        )
        .await
        .unwrap();

        // Commit in workspace should not appear in host
        let ws = workspace.to_str().unwrap();
        run_git(&["-C", ws, "config", "user.email", "ws@example.com"]);
        run_git(&["-C", ws, "config", "user.name", "WS"]);
        std::fs::write(workspace.join("ws.txt"), "ws change").unwrap();
        run_git(&["-C", ws, "add", "."]);
        run_git(&["-C", ws, "commit", "-m", "ws commit"]);

        assert_ne!(git_head(&host), git_head(&workspace));
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&workspace).ok();
    }

    #[tokio::test]
    async fn copy_worktree_includes_untracked_files() {
        let host = make_test_git_repo("cp-host");
        std::fs::write(host.join("untracked.txt"), "untracked content").unwrap();

        let workspace = make_temp_dir("cp-ws");

        materialize(
            Some("copy-worktree"),
            Some(host.to_str().unwrap()),
            &workspace,
            "run-cp",
        )
        .await
        .unwrap();

        assert!(workspace.join("untracked.txt").exists(), "untracked file must be copied");
        assert!(workspace.join("README.md").exists(), "committed file must be copied");
        assert!(workspace.join(".git").exists(), ".git must be copied");
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&workspace).ok();
    }

    #[tokio::test]
    async fn worktree_strategy_registers_in_host_and_uses_correct_branch() {
        let host = make_test_git_repo("wt-host");
        let workspace = make_temp_dir("wt-ws");

        // worktree add requires workspace dir to not exist
        std::fs::remove_dir_all(&workspace).ok();

        materialize(
            Some("worktree:main"),
            Some(host.to_str().unwrap()),
            &workspace,
            "test-run-01",
        )
        .await
        .unwrap();

        // workspace appears in host's worktree list
        let list_out = Command::new("git")
            .args(["-C", host.to_str().unwrap(), "worktree", "list"])
            .output()
            .unwrap();
        let list = String::from_utf8_lossy(&list_out.stdout);
        assert!(
            list.contains(workspace.to_str().unwrap()),
            "workspace not in worktree list:\n{list}"
        );

        // branch name is correct
        let branch_out = Command::new("git")
            .args(["-C", workspace.to_str().unwrap(), "rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .unwrap();
        let branch = String::from_utf8_lossy(&branch_out.stdout).trim().to_string();
        assert_eq!(branch, "bunsen/run-test-run-01");

        // cleanup: remove worktree before deleting dirs
        Command::new("git")
            .args([
                "-C", host.to_str().unwrap(),
                "worktree", "remove", "--force",
                workspace.to_str().unwrap(),
            ])
            .output()
            .ok();
        std::fs::remove_dir_all(&host).ok();
    }
}
