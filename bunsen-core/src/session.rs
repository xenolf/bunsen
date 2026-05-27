//! Session — the bounded orchestration context defined in ADR-0010.
//!
//! A Session owns a [`BranchPool`] inside its on-disk directory at
//! `~/.local/share/bunsen/sessions/<ulid>/` and defines when host-repo
//! writes are permitted (only at `close`, which lands in slice 10).
//!
//! Close is **never implicit** — there is no `Drop` impl that calls close,
//! and the Python context manager (slice 11) inherits the same rule.

// Scaffolding for slices 09/10/11. main.rs wires Session in via slice 11.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::branch_pool::{BranchPool, BranchPoolError, ManifestEntry};
use crate::ulid;

// ── State machine ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Open,
    Closing,
    Closed,
    FailedToClose,
    Discarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionError {
    pub from: SessionState,
    pub to: &'static str,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid session transition {:?} → {}", self.from, self.to)
    }
}

impl std::error::Error for TransitionError {}

impl SessionState {
    /// `open | failed_to_close → closing`.
    pub fn close_start(self) -> Result<Self, TransitionError> {
        match self {
            Self::Open | Self::FailedToClose => Ok(Self::Closing),
            _ => Err(TransitionError { from: self, to: "closing" }),
        }
    }

    /// `closing → closed`.
    pub fn close_complete(self) -> Result<Self, TransitionError> {
        match self {
            Self::Closing => Ok(Self::Closed),
            _ => Err(TransitionError { from: self, to: "closed" }),
        }
    }

    /// `closing → failed_to_close`.
    pub fn close_failed(self) -> Result<Self, TransitionError> {
        match self {
            Self::Closing => Ok(Self::FailedToClose),
            _ => Err(TransitionError { from: self, to: "failed_to_close" }),
        }
    }

    /// `open | failed_to_close → discarded`. Terminal.
    pub fn discard(self) -> Result<Self, TransitionError> {
        match self {
            Self::Open | Self::FailedToClose => Ok(Self::Discarded),
            _ => Err(TransitionError { from: self, to: "discarded" }),
        }
    }

    /// A new Run is permitted from `open` or `failed_to_close`; both stay
    /// in `open`-equivalent state for run-acceptance purposes.
    pub fn accept_new_run(self) -> Result<Self, TransitionError> {
        match self {
            Self::Open | Self::FailedToClose => Ok(self),
            _ => Err(TransitionError { from: self, to: "accept-new-run" }),
        }
    }
}

// ── Persistent metadata ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: String,
    pub state: SessionState,
    pub host_repo: PathBuf,
    pub mirror_refs: Vec<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discarded_at: Option<String>,
    /// Populated by slice 10's `Session::close` when a close attempt fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_close_failure: Option<String>,
}

// ── Errors ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SessionError {
    Io(std::io::Error),
    Pool(BranchPoolError),
    Git { context: String, stderr: String },
    Transition(TransitionError),
    NotFound { id: String },
    PurgeRequiresClosedState { id: String, state: SessionState },
    Serde(serde_json::Error),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Pool(e) => write!(f, "pool error: {e}"),
            Self::Git { context, stderr } => write!(f, "git error in {context}: {stderr}"),
            Self::Transition(e) => write!(f, "{e}"),
            Self::NotFound { id } => write!(f, "session {id:?} not found"),
            Self::PurgeRequiresClosedState { id, state } => write!(
                f,
                "purge of session {id:?} not permitted from state {state:?} (closed required)"
            ),
            Self::Serde(e) => write!(f, "metadata parse error: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<BranchPoolError> for SessionError {
    fn from(e: BranchPoolError) -> Self {
        Self::Pool(e)
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}

impl From<TransitionError> for SessionError {
    fn from(e: TransitionError) -> Self {
        Self::Transition(e)
    }
}

// ── List filter ────────────────────────────────────────────────────────────

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct ListFilter {
    /// `--all`: include `closed` Sessions in addition to the live ones.
    pub include_closed: bool,
    /// `--with-tombstones`: include `discarded` Sessions.
    pub include_tombstones: bool,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: String,
    pub state: SessionState,
    pub host_repo: PathBuf,
    pub labels: Vec<String>,
    pub created_at: String,
}

// ── Session handle ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Session {
    path: PathBuf,
    meta: SessionMeta,
    pool: BranchPool,
}

impl Session {
    /// Open a new Session under `~/.local/share/bunsen/sessions/<ulid>/`.
    ///
    /// Empty `mirror_refs` defaults to the host repo's default branch
    /// (looked up via `git symbolic-ref --short HEAD`).
    pub async fn open(
        host_repo: &Path,
        mirror_refs: Vec<String>,
        label: Option<String>,
    ) -> Result<Self, SessionError> {
        Self::open_in(&sessions_root(), host_repo, mirror_refs, label).await
    }

    /// Same as [`Session::open`], but rooted at an explicit sessions
    /// directory. Tests use this to avoid colliding with the real XDG dir.
    pub async fn open_in(
        sessions_root: &Path,
        host_repo: &Path,
        mirror_refs: Vec<String>,
        label: Option<String>,
    ) -> Result<Self, SessionError> {
        let id = ulid::generate();
        let path = sessions_root.join(&id);
        std::fs::create_dir_all(&path)?;

        let refs = if mirror_refs.is_empty() {
            vec![default_branch(host_repo).await?]
        } else {
            mirror_refs
        };

        let pool = BranchPool::init(path.join("pool")).await?;
        pool.mirror_from_host(host_repo, &refs).await?;

        let labels = label.into_iter().collect();
        let meta = SessionMeta {
            id: id.clone(),
            state: SessionState::Open,
            host_repo: host_repo.to_path_buf(),
            mirror_refs: refs,
            labels,
            created_at: now_iso8601(),
            discarded_at: None,
            last_close_failure: None,
        };
        write_meta_atomic(&path, &meta)?;

        Ok(Self { path, meta, pool })
    }

    /// Attach by ID to a Session that lives in the default XDG location.
    pub fn attach(id: &str) -> Result<Self, SessionError> {
        Self::attach_in(&sessions_root(), id)
    }

    /// Attach by ID under an explicit sessions root. Used by tests.
    pub fn attach_in(sessions_root: &Path, id: &str) -> Result<Self, SessionError> {
        let path = sessions_root.join(id);
        let meta = read_meta(&path).map_err(|e| match e {
            SessionError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                SessionError::NotFound { id: id.into() }
            }
            other => other,
        })?;
        if meta.state == SessionState::Discarded {
            // Tombstones have no Pool; the directory exists but pool/ is
            // gone. Attach is for live (or audit-readable) Sessions only.
            return Err(SessionError::NotFound { id: id.into() });
        }
        let pool = BranchPool::open(path.join("pool"))?;
        Ok(Self { path, meta, pool })
    }

    /// List Sessions under the default XDG location.
    pub fn list(filter: ListFilter) -> Result<Vec<SessionSummary>, SessionError> {
        Self::list_in(&sessions_root(), filter)
    }

    /// List under an explicit sessions root. Used by tests.
    pub fn list_in(
        sessions_root: &Path,
        filter: ListFilter,
    ) -> Result<Vec<SessionSummary>, SessionError> {
        let mut out: Vec<SessionSummary> = Vec::new();
        if !sessions_root.exists() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(sessions_root)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let meta_path = path.join("meta.json");
            if !meta_path.exists() {
                continue;
            }
            let s = match std::fs::read_to_string(&meta_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let meta: SessionMeta = match serde_json::from_str(&s) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let include = match meta.state {
                SessionState::Open
                | SessionState::FailedToClose
                | SessionState::Closing => true,
                SessionState::Closed => filter.include_closed,
                SessionState::Discarded => filter.include_tombstones,
            };
            if include {
                out.push(SessionSummary {
                    id: meta.id,
                    state: meta.state,
                    host_repo: meta.host_repo,
                    labels: meta.labels,
                    created_at: meta.created_at,
                });
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub fn id(&self) -> &str {
        &self.meta.id
    }

    pub fn state(&self) -> SessionState {
        self.meta.state
    }

    pub fn labels(&self) -> &[String] {
        &self.meta.labels
    }

    pub fn host_repo(&self) -> &Path {
        &self.meta.host_repo
    }

    pub fn mirror_refs(&self) -> &[String] {
        &self.meta.mirror_refs
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn pool(&self) -> &BranchPool {
        &self.pool
    }

    /// Append a free-form label and persist. Labels are mutable, non-unique,
    /// and a Session may carry many.
    pub fn label(&mut self, label: String) -> Result<(), SessionError> {
        self.meta.labels.push(label);
        write_meta_atomic(&self.path, &self.meta)?;
        Ok(())
    }

    /// Push the supplied manifest from the Pool to the Session's host repo.
    ///
    /// This is the **only** path by which Pool refs reach the host repo.
    /// The manifest is validated as a whole before any push is attempted:
    /// any non-FF pair without `force: true` aborts the whole close.
    ///
    /// Audit refs (`runs/*`) in the manifest are silently skipped — they
    /// are never pushed to the host. See [`BranchPool::push_manifest`].
    ///
    /// Transitions: `open | failed_to_close → closing → closed` on success,
    /// or `closing → failed_to_close` on push/validation failure. On
    /// failure, the failure reason is persisted in `meta.json` so
    /// [`Session::list`] can surface "this Session's last close failed
    /// because X."
    ///
    /// `close()` is **never** implicit — there is no `Drop` impl that
    /// invokes this, and the Python context manager (slice 11) inherits
    /// the same rule. A User Script that exits without calling `close()`
    /// leaves the Session open and detached.
    pub async fn close(&mut self, manifest: &[ManifestEntry]) -> Result<(), SessionError> {
        // open | failed_to_close → closing, persisted before any push.
        let closing = self.meta.state.close_start()?;
        self.meta.state = closing;
        // Clear any stale failure annotation from a prior failed close
        // attempt; if this close fails it'll be repopulated below.
        self.meta.last_close_failure = None;
        write_meta_atomic(&self.path, &self.meta)?;

        match self.pool.push_manifest(self.meta.host_repo.as_path(), manifest).await {
            Ok(()) => {
                let closed = self.meta.state.close_complete()?;
                self.meta.state = closed;
                write_meta_atomic(&self.path, &self.meta)?;
                Ok(())
            }
            Err(e) => {
                let failed = self.meta.state.close_failed()?;
                self.meta.state = failed;
                self.meta.last_close_failure = Some(e.to_string());
                write_meta_atomic(&self.path, &self.meta)?;
                Err(SessionError::Pool(e))
            }
        }
    }

    /// The last close-attempt failure message, if the Session is currently
    /// in `failed_to_close`. `None` otherwise.
    pub fn last_close_failure(&self) -> Option<&str> {
        self.meta.last_close_failure.as_deref()
    }

    /// Wipe the Pool immediately and replace the Session's metadata with a
    /// tombstone. Permitted from `open` and `failed_to_close`.
    pub fn discard(mut self) -> Result<(), SessionError> {
        let new_state = self.meta.state.discard()?;
        self.pool.wipe()?;
        let runs = self.path.join("runs");
        if runs.exists() {
            std::fs::remove_dir_all(&runs)?;
        }
        self.meta.state = new_state;
        self.meta.discarded_at = Some(now_iso8601());
        write_meta_atomic(&self.path, &self.meta)?;
        Ok(())
    }

    /// Permanently remove a `closed` Session. The only state from which this
    /// is allowed at the lib layer.
    pub fn purge(self) -> Result<(), SessionError> {
        if self.meta.state != SessionState::Closed {
            return Err(SessionError::PurgeRequiresClosedState {
                id: self.meta.id,
                state: self.meta.state,
            });
        }
        std::fs::remove_dir_all(&self.path)?;
        Ok(())
    }
}

// NOTE: deliberately no `Drop` impl. Close is never implicit at scope exit;
// the Python context manager (slice 11) inherits this same invariant.

// ── Helpers ────────────────────────────────────────────────────────────────

pub(crate) fn sessions_root() -> PathBuf {
    xdg_data_home().join("bunsen").join("sessions")
}

fn xdg_data_home() -> PathBuf {
    if let Ok(v) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(v)
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
            .join(".local")
            .join("share")
    }
}

fn now_iso8601() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Write `meta.json` via `meta.json.tmp` + rename. Within the same
/// filesystem, `rename(2)` is atomic, so a crash between the two steps
/// leaves no half-written `meta.json` for a later attach to observe.
fn write_meta_atomic(session_path: &Path, meta: &SessionMeta) -> Result<(), SessionError> {
    let final_path = session_path.join("meta.json");
    let tmp = session_path.join("meta.json.tmp");
    let s = serde_json::to_string_pretty(meta)?;
    std::fs::write(&tmp, s)?;
    std::fs::rename(&tmp, &final_path)?;
    Ok(())
}

fn read_meta(session_path: &Path) -> Result<SessionMeta, SessionError> {
    let p = session_path.join("meta.json");
    let s = std::fs::read_to_string(&p)?;
    let meta: SessionMeta = serde_json::from_str(&s)?;
    Ok(meta)
}

async fn default_branch(host_repo: &Path) -> Result<String, SessionError> {
    let out = tokio::process::Command::new("git")
        .current_dir(host_repo)
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .await?;
    if !out.status.success() {
        return Err(SessionError::Git {
            context: "git symbolic-ref --short HEAD".into(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if name.is_empty() {
        return Err(SessionError::Git {
            context: "git symbolic-ref --short HEAD".into(),
            stderr: "empty output".into(),
        });
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_temp_dir(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "bunsen-session-{suffix}-{pid}-{nanos}-{n}"
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

    fn make_host_repo_with_branch(suffix: &str, default_branch: &str) -> PathBuf {
        let dir = make_temp_dir(suffix);
        let status = StdCommand::new("git")
            .args(["init", "-b", default_branch, "--quiet", dir.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(status.success());
        run_git_sync_in(&dir, &["config", "user.email", "host@test"]);
        run_git_sync_in(&dir, &["config", "user.name", "Host"]);
        std::fs::write(dir.join("README.md"), "host\n").unwrap();
        run_git_sync_in(&dir, &["add", "README.md"]);
        run_git_sync_in(&dir, &["commit", "-m", "init", "--quiet"]);
        dir
    }

    fn make_host_repo(suffix: &str) -> PathBuf {
        make_host_repo_with_branch(suffix, "main")
    }

    fn fake_meta() -> SessionMeta {
        SessionMeta {
            id: "01HFAKE0000000000000000000".into(),
            state: SessionState::Open,
            host_repo: PathBuf::from("/tmp/host"),
            mirror_refs: vec!["main".into()],
            labels: vec![],
            created_at: "2026-01-01T00:00:00.000Z".into(),
            discarded_at: None,
            last_close_failure: None,
        }
    }

    // ── Pure state-machine tests (no disk I/O) ─────────────────────────────

    #[test]
    fn state_open_then_close_start_yields_closing() {
        assert_eq!(SessionState::Open.close_start().unwrap(), SessionState::Closing);
    }

    #[test]
    fn state_failed_to_close_can_close_start_again() {
        assert_eq!(
            SessionState::FailedToClose.close_start().unwrap(),
            SessionState::Closing
        );
    }

    #[test]
    fn state_closing_then_complete_yields_closed() {
        assert_eq!(
            SessionState::Closing.close_complete().unwrap(),
            SessionState::Closed
        );
    }

    #[test]
    fn state_closing_then_failed_yields_failed_to_close() {
        assert_eq!(
            SessionState::Closing.close_failed().unwrap(),
            SessionState::FailedToClose
        );
    }

    #[test]
    fn state_failed_to_close_accepts_new_run() {
        assert_eq!(
            SessionState::FailedToClose.accept_new_run().unwrap(),
            SessionState::FailedToClose
        );
    }

    #[test]
    fn state_open_accepts_new_run() {
        assert_eq!(SessionState::Open.accept_new_run().unwrap(), SessionState::Open);
    }

    #[test]
    fn state_discard_from_open_or_failed_to_close() {
        assert_eq!(SessionState::Open.discard().unwrap(), SessionState::Discarded);
        assert_eq!(
            SessionState::FailedToClose.discard().unwrap(),
            SessionState::Discarded
        );
    }

    #[test]
    fn state_terminal_states_reject_transitions() {
        assert!(SessionState::Closed.close_start().is_err());
        assert!(SessionState::Closed.discard().is_err());
        assert!(SessionState::Closed.accept_new_run().is_err());
        assert!(SessionState::Discarded.close_start().is_err());
        assert!(SessionState::Discarded.discard().is_err());
        assert!(SessionState::Discarded.accept_new_run().is_err());
    }

    #[test]
    fn state_close_complete_only_from_closing() {
        assert!(SessionState::Open.close_complete().is_err());
        assert!(SessionState::FailedToClose.close_complete().is_err());
    }

    #[test]
    fn state_close_failed_only_from_closing() {
        assert!(SessionState::Open.close_failed().is_err());
        assert!(SessionState::FailedToClose.close_failed().is_err());
    }

    // ── No Drop impl exists ────────────────────────────────────────────────

    /// Pins the close-is-never-implicit invariant from the slice 05 issue:
    /// any future addition of a custom destructor on the Session struct
    /// breaks this test.
    #[test]
    fn session_has_no_custom_destructor_impl() {
        let src = include_str!("session.rs");
        // Build the needle at runtime so this source file does not itself
        // contain the literal substring we're searching for.
        let needle = format!("{}l {} {}r {}", "imp", "Drop", "fo", "Session {");
        assert!(
            !src.contains(&needle),
            "Session must not carry a custom destructor"
        );
    }

    // ── Atomic persistence ─────────────────────────────────────────────────

    #[test]
    fn write_meta_atomic_uses_temp_then_rename() {
        let dir = make_temp_dir("atomic-ok");
        let meta = fake_meta();
        write_meta_atomic(&dir, &meta).unwrap();
        let mut entries: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(entries, vec!["meta.json"]);
        let read_back = read_meta(&dir).unwrap();
        assert_eq!(read_back.id, meta.id);
        assert_eq!(read_back.state, meta.state);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn crash_between_write_temp_and_rename_leaves_no_partial_meta() {
        // Simulate the post-write_temp / pre-rename state: a .tmp exists
        // with arbitrary content, and the canonical meta.json was never
        // produced. A subsequent attach/read sees no meta.json — exactly
        // what the atomicity contract promises.
        let dir = make_temp_dir("atomic-crash");
        std::fs::write(dir.join("meta.json.tmp"), "{ partial").unwrap();
        let final_path = dir.join("meta.json");
        assert!(
            !final_path.exists(),
            "no half-written meta.json may exist after a crash"
        );
        let err = read_meta(&dir).unwrap_err();
        // read_meta surfaces the underlying io::NotFound; that's fine.
        assert!(
            matches!(err, SessionError::Io(_)),
            "expected Io(NotFound), got {err:?}"
        );
        // A subsequent successful write replaces (and discards) the tmp.
        write_meta_atomic(&dir, &fake_meta()).unwrap();
        assert!(final_path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── open() ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn open_creates_directory_named_by_ulid_and_writes_meta() {
        let host = make_host_repo("open-meta");
        let root = make_temp_dir("open-meta-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let id = s.id().to_string();
        assert_eq!(id.len(), 26, "ULID must be 26 chars");
        let dir = root.join(&id);
        assert!(dir.exists(), "session dir must exist at sessions/<ulid>/");
        assert!(dir.join("meta.json").exists());
        assert!(dir.join("pool").join("HEAD").exists(), "pool must be initialised");
        assert_eq!(s.state(), SessionState::Open);
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn open_with_explicit_refs_mirrors_into_pool() {
        let host = make_host_repo("open-refs");
        run_git_sync_in(&host, &["branch", "feature"]);
        let root = make_temp_dir("open-refs-root");
        let s = Session::open_in(
            &root,
            &host,
            vec!["main".into(), "feature".into()],
            None,
        )
        .await
        .unwrap();
        let pool_refs = s
            .pool()
            .list_refs(crate::branch_pool::NamespaceFilter::Host)
            .await
            .unwrap();
        assert!(pool_refs.contains(&"host/main".to_string()));
        assert!(pool_refs.contains(&"host/feature".to_string()));
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn open_empty_refs_defaults_to_host_default_branch_non_main() {
        // Host's default branch is `trunk`, not `main`. The Session must
        // pick that up and mirror `host/trunk` into the Pool.
        let host = make_host_repo_with_branch("open-default", "trunk");
        let root = make_temp_dir("open-default-root");
        let s = Session::open_in(&root, &host, vec![], None).await.unwrap();
        assert_eq!(s.mirror_refs(), &["trunk".to_string()]);
        let pool_refs = s
            .pool()
            .list_refs(crate::branch_pool::NamespaceFilter::Host)
            .await
            .unwrap();
        assert_eq!(pool_refs, vec!["host/trunk".to_string()]);
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    // ── attach() ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn attach_reads_meta_back() {
        let host = make_host_repo("attach");
        let root = make_temp_dir("attach-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], Some("hello".into()))
            .await
            .unwrap();
        let id = s.id().to_string();
        drop(s); // simulate a fresh process
        let attached = Session::attach_in(&root, &id).unwrap();
        assert_eq!(attached.id(), id);
        assert_eq!(attached.state(), SessionState::Open);
        assert_eq!(attached.labels(), &["hello".to_string()]);
        assert_eq!(attached.host_repo(), host.as_path());
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn attach_missing_id_is_not_found() {
        let root = make_temp_dir("attach-miss");
        let err = Session::attach_in(&root, "01HNOPE0000000000000000000").unwrap_err();
        assert!(matches!(err, SessionError::NotFound { .. }), "got {err:?}");
        std::fs::remove_dir_all(&root).ok();
    }

    // ── labels ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn multiple_labels_coexist_on_one_session() {
        let host = make_host_repo("labels");
        let root = make_temp_dir("labels-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], Some("first".into()))
            .await
            .unwrap();
        s.label("second".into()).unwrap();
        s.label("third".into()).unwrap();
        assert_eq!(
            s.labels(),
            &["first".to_string(), "second".to_string(), "third".to_string()]
        );
        // And labels are persisted across an attach.
        let id = s.id().to_string();
        drop(s);
        let re = Session::attach_in(&root, &id).unwrap();
        assert_eq!(re.labels().len(), 3);
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    // ── list() with filters ────────────────────────────────────────────────

    fn seed_session_dir(root: &Path, id: &str, state: SessionState) {
        let dir = root.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let meta = SessionMeta {
            id: id.into(),
            state,
            host_repo: PathBuf::from("/tmp/fake-host"),
            mirror_refs: vec!["main".into()],
            labels: vec![],
            created_at: "2026-01-01T00:00:00.000Z".into(),
            discarded_at: if state == SessionState::Discarded {
                Some("2026-01-02T00:00:00.000Z".into())
            } else {
                None
            },
            last_close_failure: None,
        };
        write_meta_atomic(&dir, &meta).unwrap();
    }

    #[test]
    fn list_default_returns_only_live_sessions() {
        let root = make_temp_dir("list-default");
        seed_session_dir(&root, "01OPEN00000000000000000000", SessionState::Open);
        seed_session_dir(&root, "01FAIL00000000000000000000", SessionState::FailedToClose);
        seed_session_dir(&root, "01CLOS00000000000000000000", SessionState::Closed);
        seed_session_dir(&root, "01DISC00000000000000000000", SessionState::Discarded);

        let live = Session::list_in(&root, ListFilter::default()).unwrap();
        let ids: Vec<String> = live.iter().map(|s| s.id.clone()).collect();
        assert!(ids.contains(&"01OPEN00000000000000000000".into()));
        assert!(ids.contains(&"01FAIL00000000000000000000".into()));
        assert!(!ids.contains(&"01CLOS00000000000000000000".into()));
        assert!(!ids.contains(&"01DISC00000000000000000000".into()));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn list_all_flag_includes_closed_but_not_tombstones() {
        let root = make_temp_dir("list-all");
        seed_session_dir(&root, "01OPEN00000000000000000000", SessionState::Open);
        seed_session_dir(&root, "01CLOS00000000000000000000", SessionState::Closed);
        seed_session_dir(&root, "01DISC00000000000000000000", SessionState::Discarded);

        let filter = ListFilter { include_closed: true, include_tombstones: false };
        let res = Session::list_in(&root, filter).unwrap();
        let ids: Vec<String> = res.iter().map(|s| s.id.clone()).collect();
        assert!(ids.contains(&"01OPEN00000000000000000000".into()));
        assert!(ids.contains(&"01CLOS00000000000000000000".into()));
        assert!(!ids.contains(&"01DISC00000000000000000000".into()));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn list_with_tombstones_includes_discarded() {
        let root = make_temp_dir("list-tombs");
        seed_session_dir(&root, "01OPEN00000000000000000000", SessionState::Open);
        seed_session_dir(&root, "01CLOS00000000000000000000", SessionState::Closed);
        seed_session_dir(&root, "01DISC00000000000000000000", SessionState::Discarded);

        let filter = ListFilter { include_closed: true, include_tombstones: true };
        let res = Session::list_in(&root, filter).unwrap();
        let ids: Vec<String> = res.iter().map(|s| s.id.clone()).collect();
        assert!(ids.contains(&"01OPEN00000000000000000000".into()));
        assert!(ids.contains(&"01CLOS00000000000000000000".into()));
        assert!(ids.contains(&"01DISC00000000000000000000".into()));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn list_on_empty_root_returns_empty() {
        let root = make_temp_dir("list-empty");
        let res = Session::list_in(&root, ListFilter::default()).unwrap();
        assert!(res.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    // ── discard() ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn discard_wipes_pool_and_leaves_tombstone() {
        let host = make_host_repo("disc");
        let root = make_temp_dir("disc-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], Some("L".into()))
            .await
            .unwrap();
        let id = s.id().to_string();
        let dir = s.path().to_path_buf();
        let pool_dir = dir.join("pool");
        assert!(pool_dir.exists());
        s.discard().unwrap();

        assert!(dir.exists(), "session dir survives as tombstone");
        assert!(!pool_dir.exists(), "pool must be wiped");
        let meta = read_meta(&dir).unwrap();
        assert_eq!(meta.state, SessionState::Discarded);
        assert_eq!(meta.id, id);
        assert_eq!(meta.labels, vec!["L".to_string()]);
        assert_eq!(meta.host_repo, host);
        assert!(meta.discarded_at.is_some());
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn discard_tombstone_appears_only_with_tombstones_flag() {
        let host = make_host_repo("disc-list");
        let root = make_temp_dir("disc-list-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let id = s.id().to_string();
        s.discard().unwrap();

        // Default: not visible.
        let live = Session::list_in(&root, ListFilter::default()).unwrap();
        assert!(!live.iter().any(|x| x.id == id));

        // --all alone: still not visible.
        let all = Session::list_in(
            &root,
            ListFilter { include_closed: true, include_tombstones: false },
        )
        .unwrap();
        assert!(!all.iter().any(|x| x.id == id));

        // --with-tombstones: visible.
        let with = Session::list_in(
            &root,
            ListFilter { include_closed: false, include_tombstones: true },
        )
        .unwrap();
        assert!(with.iter().any(|x| x.id == id));
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    // ── purge() ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn purge_rejects_open_session() {
        let host = make_host_repo("purge-open");
        let root = make_temp_dir("purge-open-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let dir = s.path().to_path_buf();
        let err = s.purge().unwrap_err();
        assert!(
            matches!(err, SessionError::PurgeRequiresClosedState { .. }),
            "got {err:?}"
        );
        assert!(dir.exists(), "purge must not remove an open Session");
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn purge_removes_a_closed_session() {
        let host = make_host_repo("purge-closed");
        let root = make_temp_dir("purge-closed-root");
        // Hand-build a closed Session on disk so we don't need slice-10's
        // Session::close to test purge in isolation.
        let id = "01CLOSED000000000000000000".to_string();
        let dir = root.join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        // Stub a Pool so attach succeeds.
        let pool = BranchPool::init(dir.join("pool")).await.unwrap();
        drop(pool);
        let meta = SessionMeta {
            id: id.clone(),
            state: SessionState::Closed,
            host_repo: host.clone(),
            mirror_refs: vec!["main".into()],
            labels: vec![],
            created_at: "2026-01-01T00:00:00.000Z".into(),
            discarded_at: None,
            last_close_failure: None,
        };
        write_meta_atomic(&dir, &meta).unwrap();

        let s = Session::attach_in(&root, &id).unwrap();
        s.purge().unwrap();
        assert!(!dir.exists(), "purge must remove the session dir");
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    // ── RunDir relocation (slice 08) ───────────────────────────────────────

    #[tokio::test]
    async fn freshly_opened_session_has_no_runs_subdir() {
        // Run dirs are created lazily on first Run. A Session that's
        // never run anything must have no `runs/` directory.
        let host = make_host_repo("no-runs-subdir");
        let root = make_temp_dir("no-runs-subdir-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let dir = s.path().to_path_buf();
        assert!(dir.exists(), "session dir exists");
        assert!(!dir.join("runs").exists(), "runs/ must not be created at open()");
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn run_dir_create_nests_under_session_dir() {
        // End-to-end ADR-0010 layout: open a Session, create a Run dir
        // against its path, and assert it lands at
        // sessions/<id>/runs/<run-id>/.
        use crate::run_dir::RunDir;
        let host = make_host_repo("rd-nest");
        let root = make_temp_dir("rd-nest-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let sid = s.id().to_string();
        let session_dir = s.path().to_path_buf();
        let rd = RunDir::create(&session_dir, "01HRUNFIXTURE0000000000000").unwrap();
        assert_eq!(
            rd.path,
            root.join(&sid).join("runs").join("01HRUNFIXTURE0000000000000")
        );
        assert!(rd.path.exists());
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn discard_removes_run_dirs_with_the_session() {
        // `rm -rf <session>` is a clean discard — and `Session::discard`
        // already does that. After discarding, no Run dirs survive
        // outside the (now-tombstoned) Session tree.
        use crate::run_dir::RunDir;
        let host = make_host_repo("rd-discard");
        let root = make_temp_dir("rd-discard-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();
        RunDir::create(&session_dir, "01HRUNA0000000000000000000").unwrap();
        RunDir::create(&session_dir, "01HRUNB0000000000000000000").unwrap();
        assert!(session_dir.join("runs").exists());

        s.discard().unwrap();

        // Tombstone keeps the session dir but the runs/ subtree is gone.
        assert!(session_dir.exists());
        assert!(!session_dir.join("runs").exists());
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn purge_removes_run_dirs_too() {
        // Same property via purge: a closed Session's `rm -rf` removes
        // every Run dir it owns.
        use crate::run_dir::RunDir;
        let host = make_host_repo("rd-purge");
        let root = make_temp_dir("rd-purge-root");
        let id = "01CLOSEDRUNS00000000000000".to_string();
        let dir = root.join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        BranchPool::init(dir.join("pool")).await.unwrap();
        let meta = SessionMeta {
            id: id.clone(),
            state: SessionState::Closed,
            host_repo: host.clone(),
            mirror_refs: vec!["main".into()],
            labels: vec![],
            created_at: "2026-01-01T00:00:00.000Z".into(),
            discarded_at: None,
            last_close_failure: None,
        };
        write_meta_atomic(&dir, &meta).unwrap();
        RunDir::create(&dir, "01HRUNINSIDE000000000000000").unwrap();
        assert!(dir.join("runs").exists());

        let s = Session::attach_in(&root, &id).unwrap();
        s.purge().unwrap();
        assert!(!dir.exists(), "purge wipes the session dir and all run dirs");
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn purge_rejects_failed_to_close_session() {
        let host = make_host_repo("purge-ftc");
        let root = make_temp_dir("purge-ftc-root");
        let id = "01FAILED000000000000000000".to_string();
        let dir = root.join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        BranchPool::init(dir.join("pool")).await.unwrap();
        let meta = SessionMeta {
            id: id.clone(),
            state: SessionState::FailedToClose,
            host_repo: host.clone(),
            mirror_refs: vec!["main".into()],
            labels: vec![],
            created_at: "2026-01-01T00:00:00.000Z".into(),
            discarded_at: None,
            last_close_failure: Some("manifest validation failed".into()),
        };
        write_meta_atomic(&dir, &meta).unwrap();

        let s = Session::attach_in(&root, &id).unwrap();
        let err = s.purge().unwrap_err();
        assert!(
            matches!(err, SessionError::PurgeRequiresClosedState { .. }),
            "got {err:?}"
        );
        assert!(dir.exists());
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    // ── Session::close (slice 10) ──────────────────────────────────────────
    //
    // The pure manifest-validation function is tested in branch_pool's tests
    // against synthetic SHA triples. These tests pin the Session-level
    // disk effects: state transitions, on-disk failure annotation, audit-
    // ref filtering through the pool, retry-after-failure, and the no-
    // implicit-close invariant.

    fn make_bare_host_repo(suffix: &str) -> PathBuf {
        let dir = make_temp_dir(suffix);
        let status = StdCommand::new("git")
            .args(["init", "--bare", "-b", "main", "--quiet", dir.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(status.success());
        dir
    }

    /// Seeds a bare host with one commit on `main`. Returns nothing — the
    /// host repo is the unit being inspected.
    fn seed_bare_host(bare: &Path) {
        let work = make_temp_dir("close-seed-work");
        let status = StdCommand::new("git")
            .args(["init", "-b", "main", "--quiet", work.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(status.success());
        run_git_sync_in(&work, &["config", "user.email", "seed@test"]);
        run_git_sync_in(&work, &["config", "user.name", "Seed"]);
        std::fs::write(work.join("seed.txt"), "seed\n").unwrap();
        run_git_sync_in(&work, &["add", "seed.txt"]);
        run_git_sync_in(&work, &["commit", "-m", "seed", "--quiet"]);
        run_git_sync_in(&work, &["push", bare.to_str().unwrap(), "main:main"]);
        std::fs::remove_dir_all(&work).ok();
    }

    fn host_branch_sha(host: &Path, full_ref: &str) -> String {
        let out = StdCommand::new("git")
            .current_dir(host)
            .args(["rev-parse", full_ref])
            .output()
            .unwrap();
        assert!(out.status.success(), "rev-parse {full_ref} failed");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn host_branch_names(host: &Path) -> Vec<String> {
        let out = StdCommand::new("git")
            .current_dir(host)
            .args(["for-each-ref", "--format=%(refname:short)", "refs/heads/"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect()
    }

    /// Open a Session whose host is `host_bare` under `sessions_root` and
    /// create a pool branch `pool_branch` that fast-forwards from
    /// `host/main` by one extra commit. Returns the SHA the pool branch
    /// ends up at, so tests can assert that exact SHA lands on the host.
    async fn open_with_ff_pool_branch(
        sessions_root: &Path,
        host_bare: &Path,
        pool_branch: &str,
    ) -> (Session, String) {
        let s = Session::open_in(sessions_root, host_bare, vec!["main".into()], None)
            .await
            .unwrap();
        let pool_dir = s.path().join("pool");
        // Build a working clone of the pool, add a commit, push back as
        // refs/heads/<pool_branch>. This gives the pool a branch that is
        // an FF descendant of host/main.
        let work = make_temp_dir("ff-pool-work");
        let pool_url = format!("file://{}", pool_dir.display());
        let status = StdCommand::new("git")
            .args(["clone", "--quiet", "--branch", "host/main", &pool_url, work.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(status.success(), "clone of pool failed");
        run_git_sync_in(&work, &["config", "user.email", "w@test"]);
        run_git_sync_in(&work, &["config", "user.name", "W"]);
        run_git_sync_in(&work, &["checkout", "-b", pool_branch]);
        std::fs::write(work.join(format!("{}.txt", pool_branch.replace('/', "_"))), "advance\n")
            .unwrap();
        run_git_sync_in(&work, &["add", "-A"]);
        run_git_sync_in(&work, &["commit", "-m", "advance", "--quiet"]);
        let sha_out = StdCommand::new("git")
            .current_dir(&work)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let sha = String::from_utf8_lossy(&sha_out.stdout).trim().to_string();
        run_git_sync_in(
            &work,
            &["push", pool_dir.to_str().unwrap(), &format!("{pool_branch}:{pool_branch}")],
        );
        std::fs::remove_dir_all(&work).ok();
        (s, sha)
    }

    #[tokio::test]
    async fn close_ff_manifest_succeeds_and_transitions_to_closed() {
        let host = make_bare_host_repo("close-ok-host");
        seed_bare_host(&host);
        let root = make_temp_dir("close-ok-root");

        let (mut s, pool_sha) =
            open_with_ff_pool_branch(&root, &host, "feature/ship").await;
        let id = s.id().to_string();
        assert_eq!(s.state(), SessionState::Open);

        let manifest = vec![ManifestEntry {
            pool_ref: "feature/ship".into(),
            host_ref: "release/ship".into(),
            force: false,
        }];
        s.close(&manifest).await.unwrap();
        assert_eq!(s.state(), SessionState::Closed);
        assert!(s.last_close_failure().is_none());

        // Disk reflects in-memory state.
        let on_disk = read_meta(s.path()).unwrap();
        assert_eq!(on_disk.state, SessionState::Closed);
        assert!(on_disk.last_close_failure.is_none());

        // Host actually received the push.
        let host_sha = host_branch_sha(&host, "refs/heads/release/ship");
        assert_eq!(host_sha, pool_sha);

        // list with --all surfaces the now-closed Session.
        let listed = Session::list_in(
            &root,
            ListFilter { include_closed: true, include_tombstones: false },
        )
        .unwrap();
        assert!(listed.iter().any(|x| x.id == id && x.state == SessionState::Closed));

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn close_non_ff_without_force_lands_in_failed_to_close() {
        // Pool has a "stale" branch at host/main's seed SHA. Host's
        // `protected` branch has advanced past that. A FF-only push of
        // stale → protected is non-FF and must abort.
        let host = make_bare_host_repo("close-nff-host");
        seed_bare_host(&host);
        // Advance host's `protected` ref past seed.
        let work = make_temp_dir("close-nff-work");
        StdCommand::new("git")
            .args(["clone", "--quiet", host.to_str().unwrap(), work.to_str().unwrap()])
            .status()
            .unwrap();
        run_git_sync_in(&work, &["config", "user.email", "w@test"]);
        run_git_sync_in(&work, &["config", "user.name", "W"]);
        run_git_sync_in(&work, &["checkout", "-b", "protected"]);
        std::fs::write(work.join("p.txt"), "advance\n").unwrap();
        run_git_sync_in(&work, &["add", "p.txt"]);
        run_git_sync_in(&work, &["commit", "-m", "advance", "--quiet"]);
        run_git_sync_in(&work, &["push", host.to_str().unwrap(), "protected:protected"]);
        let protected_sha = host_branch_sha(&host, "refs/heads/protected");
        std::fs::remove_dir_all(&work).ok();

        let root = make_temp_dir("close-nff-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();
        let pool_dir = session_dir.join("pool");
        // Stale branch in pool = host/main (older than protected).
        let stale_status = StdCommand::new("git")
            .current_dir(&pool_dir)
            .args(["branch", "stale", "host/main"])
            .status()
            .unwrap();
        assert!(stale_status.success());

        let manifest = vec![ManifestEntry {
            pool_ref: "stale".into(),
            host_ref: "protected".into(),
            force: false,
        }];
        let err = s.close(&manifest).await.unwrap_err();
        assert!(matches!(err, SessionError::Pool(BranchPoolError::NotFastForward { .. })));

        // Session lands in FailedToClose, in-memory and on disk.
        assert_eq!(s.state(), SessionState::FailedToClose);
        let on_disk = read_meta(&session_dir).unwrap();
        assert_eq!(on_disk.state, SessionState::FailedToClose);
        let annot = s.last_close_failure().expect("failure annotation must be set");
        assert!(annot.contains("non-fast-forward"), "annotation was: {annot}");
        assert_eq!(on_disk.last_close_failure.as_deref(), Some(annot));

        // Host refs are untouched.
        assert_eq!(host_branch_sha(&host, "refs/heads/protected"), protected_sha);

        // list (default = live) surfaces the FailedToClose Session.
        let live = Session::list_in(&root, ListFilter::default()).unwrap();
        let id = s.id().to_string();
        assert!(
            live.iter()
                .any(|x| x.id == id && x.state == SessionState::FailedToClose),
            "default list must surface failed_to_close",
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn close_per_pair_force_allows_non_ff_pair() {
        // One pair force=true (non-FF) + one pair FF=true; both succeed.
        let host = make_bare_host_repo("close-force-host");
        seed_bare_host(&host);
        // Advance host's `to-rewrite` past seed.
        let work = make_temp_dir("close-force-work");
        StdCommand::new("git")
            .args(["clone", "--quiet", host.to_str().unwrap(), work.to_str().unwrap()])
            .status()
            .unwrap();
        run_git_sync_in(&work, &["config", "user.email", "w@test"]);
        run_git_sync_in(&work, &["config", "user.name", "W"]);
        run_git_sync_in(&work, &["checkout", "-b", "to-rewrite"]);
        std::fs::write(work.join("r.txt"), "head\n").unwrap();
        run_git_sync_in(&work, &["add", "r.txt"]);
        run_git_sync_in(&work, &["commit", "-m", "head", "--quiet"]);
        run_git_sync_in(&work, &["push", host.to_str().unwrap(), "to-rewrite:to-rewrite"]);
        std::fs::remove_dir_all(&work).ok();

        let root = make_temp_dir("close-force-root");
        let (mut s, ff_sha) =
            open_with_ff_pool_branch(&root, &host, "feature/keep").await;
        // Pool also has a "rewrite" branch at host/main (older than to-rewrite).
        let pool_dir = s.path().join("pool");
        StdCommand::new("git")
            .current_dir(&pool_dir)
            .args(["branch", "rewrite", "host/main"])
            .status()
            .unwrap();
        let rewrite_sha = {
            let out = StdCommand::new("git")
                .current_dir(&pool_dir)
                .args(["rev-parse", "refs/heads/rewrite"])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        let manifest = vec![
            ManifestEntry { pool_ref: "feature/keep".into(), host_ref: "release/keep".into(), force: false },
            ManifestEntry { pool_ref: "rewrite".into(),      host_ref: "to-rewrite".into(),   force: true },
        ];
        s.close(&manifest).await.unwrap();
        assert_eq!(s.state(), SessionState::Closed);

        assert_eq!(host_branch_sha(&host, "refs/heads/release/keep"), ff_sha);
        assert_eq!(host_branch_sha(&host, "refs/heads/to-rewrite"), rewrite_sha);

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn close_silently_skips_audit_refs_in_manifest() {
        // Manifest contains a `runs/<id>` pool_ref. Close must succeed
        // without pushing anything in the runs/* namespace to the host.
        let host = make_bare_host_repo("close-runs-host");
        seed_bare_host(&host);
        let root = make_temp_dir("close-runs-root");
        let (mut s, ff_sha) = open_with_ff_pool_branch(&root, &host, "feature/y").await;

        // Seed a synthetic audit ref in the pool by pointing it at the FF tip.
        let pool_dir = s.path().join("pool");
        StdCommand::new("git")
            .current_dir(&pool_dir)
            .args(["update-ref", "refs/heads/runs/01HABC", "refs/heads/feature/y"])
            .status()
            .unwrap();

        let manifest = vec![
            ManifestEntry { pool_ref: "runs/01HABC".into(), host_ref: "runs/01HABC".into(), force: false },
            ManifestEntry { pool_ref: "feature/y".into(),   host_ref: "release/y".into(),   force: false },
        ];
        s.close(&manifest).await.unwrap();
        assert_eq!(s.state(), SessionState::Closed);

        let names = host_branch_names(&host);
        assert!(names.contains(&"release/y".to_string()));
        assert!(
            !names.iter().any(|n| n.starts_with("runs/")),
            "no runs/* refs should land on the host: {names:?}",
        );
        assert_eq!(host_branch_sha(&host, "refs/heads/release/y"), ff_sha);

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn close_from_failed_to_close_retry_succeeds() {
        // First close fails (non-FF). Second close with a clean (FF-only)
        // manifest succeeds and the Session reaches Closed. Failure
        // annotation is cleared on the successful retry.
        let host = make_bare_host_repo("close-retry-host");
        seed_bare_host(&host);
        // Advance host's `protected` past seed.
        let work = make_temp_dir("close-retry-work");
        StdCommand::new("git")
            .args(["clone", "--quiet", host.to_str().unwrap(), work.to_str().unwrap()])
            .status()
            .unwrap();
        run_git_sync_in(&work, &["config", "user.email", "w@test"]);
        run_git_sync_in(&work, &["config", "user.name", "W"]);
        run_git_sync_in(&work, &["checkout", "-b", "protected"]);
        std::fs::write(work.join("p.txt"), "advance\n").unwrap();
        run_git_sync_in(&work, &["add", "p.txt"]);
        run_git_sync_in(&work, &["commit", "-m", "advance", "--quiet"]);
        run_git_sync_in(&work, &["push", host.to_str().unwrap(), "protected:protected"]);
        std::fs::remove_dir_all(&work).ok();

        let root = make_temp_dir("close-retry-root");
        let (mut s, ff_sha) = open_with_ff_pool_branch(&root, &host, "feature/z").await;
        let pool_dir = s.path().join("pool");
        StdCommand::new("git")
            .current_dir(&pool_dir)
            .args(["branch", "stale", "host/main"])
            .status()
            .unwrap();

        // First attempt: includes a non-FF stale → protected; fails.
        let bad = vec![
            ManifestEntry { pool_ref: "stale".into(),      host_ref: "protected".into(),    force: false },
            ManifestEntry { pool_ref: "feature/z".into(), host_ref: "release/z".into(),    force: false },
        ];
        let _ = s.close(&bad).await.unwrap_err();
        assert_eq!(s.state(), SessionState::FailedToClose);
        assert!(s.last_close_failure().is_some());
        // Host received nothing (push is --atomic in the pool layer).
        let names = host_branch_names(&host);
        assert!(!names.contains(&"release/z".to_string()));

        // Retry: drop the bad pair. Close succeeds, state = Closed,
        // failure annotation is cleared.
        let good = vec![ManifestEntry {
            pool_ref: "feature/z".into(),
            host_ref: "release/z".into(),
            force: false,
        }];
        s.close(&good).await.unwrap();
        assert_eq!(s.state(), SessionState::Closed);
        assert!(s.last_close_failure().is_none());
        let on_disk = read_meta(s.path()).unwrap();
        assert_eq!(on_disk.state, SessionState::Closed);
        assert!(on_disk.last_close_failure.is_none());
        assert_eq!(host_branch_sha(&host, "refs/heads/release/z"), ff_sha);

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn dropping_a_session_does_not_change_on_disk_state() {
        // No-implicit-close, observed at runtime: open a Session, drop the
        // handle without calling close, and assert the on-disk state is
        // still Open. (The compile-time check that no impl Drop exists is
        // session_has_no_custom_destructor_impl above.)
        let host = make_bare_host_repo("close-nodrop-host");
        seed_bare_host(&host);
        let root = make_temp_dir("close-nodrop-root");
        let s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let id = s.id().to_string();
        let dir = s.path().to_path_buf();
        drop(s);
        let on_disk = read_meta(&dir).unwrap();
        assert_eq!(on_disk.state, SessionState::Open);
        // attach still works (it's a live Session).
        let re = Session::attach_in(&root, &id).unwrap();
        assert_eq!(re.state(), SessionState::Open);
        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }
}
