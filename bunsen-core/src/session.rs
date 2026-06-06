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
use crate::encoder::Encoder;
use crate::events::{BUNSEN_VERSION, SCHEMA_VERSION};
use crate::redactor::Redactor;
use crate::run_dir::{MetaJson, ResourceLimits, RunDir};
use crate::run_spec::{BranchingStrategy, RunSpec};
use crate::sandbox_fetch::{
    copy_agent_history_narrow, fetch_pool_from_git_dir, SandboxFetchError,
};
use crate::ulid;
use crate::workspace_materializer::{self, WorkspaceMaterializerError};

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
    Materialize(WorkspaceMaterializerError),
    SandboxFetch(SandboxFetchError),
    AgentExit { stderr: String },
    BadRedactor(String),
    /// The caller requested the Firecracker sandbox backend (kernel set on
    /// the [`RunBackend`]) on a host that does not support it. Today the
    /// supported set is Linux + KVM (see ADR-0001). The host-subprocess
    /// backend (default `RunBackend`) is still reachable on every platform.
    SandboxUnsupportedOnPlatform,
    /// The host's iptables INPUT chain is DROP-by-default and no covering
    /// allow rule for `169.254.0.0/16` exists, and the caller did not opt
    /// in via `RunBackend.manage_firewall`. The Run would otherwise boot
    /// fine, then time out 30 s into the agent step when the L7 proxy
    /// couldn't be reached from the guest. Returned upfront — before any
    /// run-dir / transcript / Pool side-effects — so the failure mode
    /// matches the legacy CLI (slice 13).
    ///
    /// `message` is the human-readable explanation (the byte-for-byte
    /// [`crate::firewall_check::BLOCKED_MESSAGE`]); Python callers can
    /// route on the variant and surface `message` to the user.
    HostFirewallBlocked { message: String },
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
            Self::Materialize(e) => write!(f, "workspace materialize error: {e}"),
            Self::SandboxFetch(e) => write!(f, "sandbox fetch error: {e}"),
            Self::AgentExit { stderr } => write!(f, "agent supervisor error: {stderr}"),
            Self::BadRedactor(e) => write!(f, "redactor build error: {e}"),
            Self::SandboxUnsupportedOnPlatform => write!(
                f,
                "sandbox backend (Firecracker) requires Linux + KVM; use the default \
                 RunBackend to keep the host-subprocess path"
            ),
            Self::HostFirewallBlocked { message } => write!(f, "{message}"),
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

impl From<WorkspaceMaterializerError> for SessionError {
    fn from(e: WorkspaceMaterializerError) -> Self {
        Self::Materialize(e)
    }
}

impl From<SandboxFetchError> for SessionError {
    fn from(e: SandboxFetchError) -> Self {
        Self::SandboxFetch(e)
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

/// Outcome of a [`Session::run`].
///
/// `pool_sha` is the SHA the Pool's `runs/<run-id>` audit ref points at after
/// the agent's commits are extracted. `None` when the agent produced zero
/// commits (a successful, but warning-annotated, Run). When `output_branch`
/// was declared on the [`RunSpec`] and the Run produced commits, the same
/// SHA also lives under that branch name in the Pool — `output_branch_pushed`
/// echoes the name back.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub run_id: String,
    pub pool_sha: Option<String>,
    pub output_branch_pushed: Option<String>,
    pub uncommitted_paths: Vec<String>,
}

/// Internal outcome of the dispatch decision inside
/// [`Session::run_with_backend`]. The variant tells the caller whether the
/// agent ran in the host-subprocess supervisor (in which case the caller
/// still needs to inspect the host-side workspace and push to the Pool)
/// or in the Firecracker sandbox (in which case the Pool has already
/// received the agent's commits via the ext4 extraction).
enum DispatchOutcome {
    HostSubprocess {
        supervisor_result: Result<(), SessionError>,
    },
    Sandbox {
        sandbox_result: std::io::Result<()>,
    },
}

/// Per-Run backend override for [`Session::run_with_backend`].
///
/// All fields are optional — the default `RunBackend` lets the Session
/// decide the backend from the [`RunSpec`]: when `spec.oci_image` is set
/// (or any of the override fields below is supplied), the Run boots in
/// the Firecracker sandbox; otherwise it goes through the host-subprocess
/// supervisor. This matches the legacy CLI's "trigger for sandbox is
/// `--rootfs` or `spec.oci_image`" rule.
///
/// Each field is an explicit override of the lazy-resolution default:
///
/// - `kernel` — bypass [`crate::kernel::ensure_kernel`] and use this path.
/// - `rootfs` — bypass [`crate::oci_cache::resolve_rootfs`] and use this
///   path. Required when the [`RunSpec`] has no `oci_image`.
/// - `firecracker_bin` — override `firecracker` resolution from `$PATH`.
/// - `manage_firewall` — same as the CLI `--manage-firewall` flag.
///
/// On non-Linux platforms, any sandbox-intent input (explicit kernel /
/// rootfs / firecracker_bin OR `spec.oci_image`) returns
/// [`SessionError::SandboxUnsupportedOnPlatform`] without leaving a Run on
/// disk. The host-subprocess path stays reachable on every platform via a
/// spec with no `oci_image` and a default backend.
///
/// [ADR-0011]: ../../../docs/adr/0011-hardened-git-fetch-from-sandbox.md
#[derive(Debug, Clone, Default)]
pub struct RunBackend {
    /// Explicit guest kernel path. When `None` and sandbox is intended,
    /// `Session::run_with_backend` lazily fetches the pinned
    /// Firecracker-CI vmlinux via [`crate::kernel::ensure_kernel`].
    pub kernel: Option<PathBuf>,
    /// Explicit rootfs ext4 image. When `None` and sandbox is intended,
    /// the rootfs is resolved from `spec.oci_image` through the OCI cache.
    /// One of the two (this field OR `spec.oci_image`) must be supplied
    /// to enter the sandbox.
    pub rootfs: Option<PathBuf>,
    /// Override the `firecracker` binary location. `None` ⇒ search `$PATH`.
    pub firecracker_bin: Option<PathBuf>,
    /// Authorise bunsen to install the per-TAP iptables allow rule for the
    /// lifetime of the Run when the host's INPUT chain is DROP-by-default.
    /// Matches the CLI's `--manage-firewall` flag.
    pub manage_firewall: bool,
}

impl RunBackend {
    /// Whether the caller has supplied an override that, by itself, asks
    /// for the sandbox backend regardless of what the [`RunSpec`] says.
    ///
    /// `firecracker_bin` is **not** a trigger — it's purely a `$PATH`
    /// override of the `firecracker` binary location, and without
    /// kernel/rootfs/oci_image there's nothing to feed it. Matches the
    /// legacy CLI's "sandbox iff `--kernel` or `--rootfs` or
    /// `spec.oci_image`" rule.
    fn requests_sandbox(&self) -> bool {
        self.kernel.is_some() || self.rootfs.is_some()
    }
}

/// Lazy-resolved sandbox inputs, computed once at the top of
/// [`Session::run_with_backend`] when sandbox intent is detected. Carries
/// the post-resolution kernel and rootfs paths so the dispatch site can
/// hand them straight to `sandbox_run::run` without re-querying the cache.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ResolvedSandbox {
    kernel: PathBuf,
    rootfs: PathBuf,
}

/// Apply [`RunBackend`]'s lazy-resolution defaults: missing kernel →
/// [`crate::kernel::ensure_kernel`]; missing rootfs → OCI pull from
/// `spec.oci_image` via [`crate::oci_cache::resolve_rootfs`]. Either failure
/// surfaces as a [`SessionError`] before any Run-dir side-effects in the
/// caller, so a resolution failure leaves the Session bit-identical on disk.
#[cfg(target_os = "linux")]
async fn resolve_sandbox_inputs(
    backend: &RunBackend,
    spec: &RunSpec,
) -> Result<ResolvedSandbox, SessionError> {
    let kernel = match backend.kernel.clone() {
        Some(p) => p,
        None => crate::kernel::ensure_kernel().await.map_err(|e| {
            SessionError::Git {
                context: "ensure_kernel".into(),
                stderr: format!("{e:#}"),
            }
        })?,
    };
    let rootfs = match backend.rootfs.clone() {
        Some(p) => p,
        None => {
            let oci_ref = spec.resolve_oci_image().ok_or_else(|| SessionError::Git {
                context: "resolve_sandbox_inputs".into(),
                stderr: "sandbox mode requires a rootfs: set RunBackend.rootfs, RunSpec.oci_image, or use an adapter that declares an OCI image"
                    .into(),
            })?;
            crate::oci_cache::resolve_rootfs(oci_ref)
                .await
                .map_err(|e| SessionError::Git {
                    context: format!("resolve_rootfs({oci_ref})"),
                    stderr: format!("{e:#}"),
                })?
        }
    };
    Ok(ResolvedSandbox { kernel, rootfs })
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

    /// Orchestrate a Run end-to-end: materialise the Workspace from the
    /// Session's Pool, run the agent, extract the agent's commits back into
    /// the Pool via Sandbox Fetch, and emit transcript warnings for
    /// zero-commit or uncommitted-changes outcomes.
    ///
    /// Per [ADR-0010] and [ADR-0011]:
    ///
    /// - The host repo is **never** read at materialise time; sourcing
    ///   happens entirely from the Pool. A [`BranchingStrategy`] that names a
    ///   ref the Session did not mirror at open fails loudly.
    /// - On Linux + Firecracker (a future wiring), the Workspace lives
    ///   inside an ext4 Sandbox disk and is extracted via the hardened
    ///   [`crate::sandbox_fetch::sandbox_fetch_from_ext4`]. On the
    ///   host-subprocess fallback (the dev path on macOS, and the path
    ///   tested here), the Workspace materialises into an ephemeral
    ///   directory outside `runs/<run-id>/` and is consumed via
    ///   [`crate::sandbox_fetch::fetch_pool_from_git_dir`].
    /// - The host-side `runs/<id>/workspace/` directory is **not** created.
    ///   The Pool is the source of truth for Run output; the User Script
    ///   inspects files via `git worktree add` from a Pool ref (slice 11
    ///   documents the helper).
    /// - A Run that produces zero commits is a **successful** completion
    ///   with a `run_warning` event marking the empty Run.
    /// - A Run that ends with uncommitted Workspace files is also
    ///   successful; the file list is emitted as a `run_warning`, and the
    ///   uncommitted files are dropped — only committed state lands in the
    ///   Pool.
    /// - Concurrent Runs publishing to **different** `output_branch` refs
    ///   both succeed. Concurrent Runs racing on the **same**
    ///   `output_branch` produce a [`BranchPoolError::RefAlreadyExists`]
    ///   for the loser via [`BranchPool::validate_run_output_targets`].
    ///
    /// [ADR-0010]: ../../../docs/adr/0010-session-and-branch-pool.md
    /// [ADR-0011]: ../../../docs/adr/0011-hardened-git-fetch-from-sandbox.md
    pub async fn run(&mut self, spec: RunSpec) -> Result<RunResult, SessionError> {
        self.run_with_backend(spec, RunBackend::default()).await
    }

    /// Run the spec under a caller-chosen backend.
    ///
    /// **Dispatch rules** (mirror the legacy CLI):
    ///
    /// - Sandbox is intended when the [`RunSpec`] has `oci_image` **or**
    ///   the caller supplied any override on `backend` (kernel, rootfs,
    ///   firecracker_bin). Otherwise the host-subprocess supervisor runs.
    /// - When the sandbox is intended but a field is missing, lazy
    ///   resolution kicks in: missing kernel ⇒
    ///   [`crate::kernel::ensure_kernel`]; missing rootfs ⇒
    ///   [`crate::oci_cache::resolve_rootfs`] against `spec.oci_image`.
    /// - Sandbox intent on non-Linux returns
    ///   [`SessionError::SandboxUnsupportedOnPlatform`] before any disk
    ///   side-effects.
    ///
    /// With a default `RunBackend` and a spec without `oci_image`, this is
    /// equivalent to [`Session::run`].
    pub async fn run_with_backend(
        &mut self,
        spec: RunSpec,
        backend: RunBackend,
    ) -> Result<RunResult, SessionError> {
        // Sandbox intent: explicit backend override OR an OCI image in the
        // spec. This mirrors the legacy CLI's rule.
        let sandbox_intended = backend.requests_sandbox() || spec.oci_image.is_some();

        // Platform gate first: asking for Firecracker on non-Linux must
        // fail before any disk side-effects so the Session and `runs/` dir
        // are untouched for the caller. The host-subprocess fallback stays
        // reachable on every platform when neither the spec nor the
        // backend asks for the sandbox.
        #[cfg(not(target_os = "linux"))]
        if sandbox_intended {
            return Err(SessionError::SandboxUnsupportedOnPlatform);
        }

        // Lazy resolution of the kernel (and rootfs from spec.oci_image)
        // happens here, BEFORE any run_dir / transcript / encoder
        // side-effects, so a resolution failure leaves the Session bit-
        // identical on disk. The host-subprocess path skips this entire
        // block — no network, no fs writes.
        #[cfg(target_os = "linux")]
        let resolved = if sandbox_intended {
            Some(resolve_sandbox_inputs(&backend, &spec).await?)
        } else {
            None
        };

        // Spawn the PrivilegedNet actor for the sandbox path. On Linux the
        // actor is always created (even for non-sandbox runs) so the Session
        // doesn't need to know which path it will take at this point; the
        // actor thread is cheap to start and stays alive for the lifetime of
        // this Session invocation.
        #[cfg(target_os = "linux")]
        let actor = crate::privileged_net::start_actor();

        // Host firewall probe (slice 13): the legacy CLI refuses upfront
        // on a DROP-by-default INPUT chain without `--manage-firewall`,
        // and the Session path must do the same so callers don't see a
        // 30-second timeout deep into the agent step. Runs only when the
        // sandbox is intended (host-subprocess path doesn't share a
        // kernel with the L7 proxy and has nothing to probe), AFTER
        // input resolution (so a missing kernel/rootfs — the more common
        // mistake — surfaces first), and BEFORE `accept_new_run` so the
        // Session state machine is untouched on Blocked.
        #[cfg(target_os = "linux")]
        if sandbox_intended {
            if let Err(message) =
                crate::firewall::enforce_host_firewall_policy(backend.manage_firewall, &actor)
                    .await
            {
                return Err(SessionError::HostFirewallBlocked { message });
            }
        }

        // State check: open | failed_to_close accept new Runs; everything else
        // refuses. The state does not change as a result of the Run itself.
        let _ = self.meta.state.accept_new_run()?;

        let run_id = ulid::generate();
        let run_dir = RunDir::create(&self.path, &run_id)?;

        // Ephemeral Workspace dir. We deliberately do NOT place it under
        // `run_dir.path/workspace/` — that would resurrect the host-side
        // workspace tree the slice exists to remove. A temp sibling outside
        // the Session tree keeps the Run-dir on-disk shape as defined in
        // slice 08.
        let workspace_path = transient_workspace_path(&self.path, &run_id);
        if workspace_path.exists() {
            std::fs::remove_dir_all(&workspace_path)?;
        }

        workspace_materializer::materialize(
            self.pool.path(),
            &spec.branching_strategy,
            &workspace_path,
            &run_id,
            spec.output_branch.as_deref(),
        )
        .await?;

        // Persist the spec next to the Run dir so reattach/audit can see it.
        run_dir.write_spec(
            &serde_json::to_string(&serde_json::to_value(serialize_run_spec_lite(&spec))?)?,
        )
        .ok();

        let started_at = now_iso8601();
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
                Redactor::new(spec.secrets.clone())
                    .map_err(|e| SessionError::BadRedactor(e.to_string()))?,
            )
        };
        let mut enc = Encoder::new(&run_id, &run_dir.transcript_path(), redactor)?;

        enc.emit(
            "run_started",
            serde_json::json!({
                "adapter": spec.adapter,
                "session_id": self.meta.id,
                "transcript_path": run_dir.transcript_path().to_string_lossy().into_owned(),
            }),
        )?;

        // Run the agent. Host-subprocess supervisor or Firecracker sandbox,
        // depending on what `sandbox_intended` decided above. The sandbox
        // path performs ext4 extraction into the Pool inline, so the
        // host-subprocess `extract_run_output` step is replaced with a
        // Pool-side read of the audit ref to compute `pool_sha`.
        let agent_history_path = run_dir.agent_history_path();
        #[cfg(target_os = "linux")]
        let dispatch = self
            .run_dispatch(
                backend,
                resolved,
                &spec,
                &run_id,
                &mut enc,
                &workspace_path,
                &agent_history_path,
                &actor,
            )
            .await;
        #[cfg(not(target_os = "linux"))]
        let dispatch = self
            .run_dispatch(backend, &spec, &run_id, &mut enc, &workspace_path, &agent_history_path)
            .await;
        let (supervisor_result, extraction): (
            Result<(), SessionError>,
            Result<RunResult, SessionError>,
        ) = match dispatch {
            DispatchOutcome::HostSubprocess { supervisor_result } => {
                let extraction = self
                    .extract_run_output(
                        &workspace_path,
                        &run_id,
                        &spec,
                        &mut enc,
                        &agent_history_path,
                    )
                    .await;
                (supervisor_result, extraction)
            }
            DispatchOutcome::Sandbox { sandbox_result } => {
                // The sandbox lifecycle (sandbox_run::run) drove both the
                // supervisor and the Pool extraction. Build a RunResult by
                // reading the Pool's audit ref back. Uncommitted paths are
                // not available — the ext4 is gone by the time we return —
                // so we report an empty list for the sandbox path.
                match sandbox_result {
                    Ok(()) => {
                        // `sandbox_supervisor::run` already emitted
                        // `run_ended` at vsock EOF; do NOT emit a second
                        // one here. The transcript invariant is one
                        // `run_ended` per Run, carried by the supervisor
                        // layer with its richer `exit_code` payload.
                        let pool_sha = self
                            .read_pool_ref_sha(&format!("refs/heads/runs/{run_id}"))
                            .await
                            .ok();
                        (
                            Ok(()),
                            Ok(RunResult {
                                run_id: run_id.clone(),
                                pool_sha,
                                output_branch_pushed: spec.output_branch.clone(),
                                uncommitted_paths: Vec::new(),
                            }),
                        )
                    }
                    Err(e) => (
                        Err(SessionError::AgentExit { stderr: e.to_string() }),
                        Err(SessionError::AgentExit { stderr: e.to_string() }),
                    ),
                }
            }
        };

        // Final meta with end timestamps.
        let ended_at = now_iso8601();
        let exit_reason = match (&supervisor_result, &extraction) {
            (Ok(()), Ok(_)) => "agent_exit",
            (Err(_), _) => "supervisor_error",
            (_, Err(_)) => "extraction_error",
        };
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

        // Tear down the transient Workspace regardless of how the Run
        // ended. The agent's commits already live in the Pool (when
        // extraction succeeded); the dir is no longer needed.
        let _ = std::fs::remove_dir_all(&workspace_path);

        supervisor_result?;
        extraction
    }

    /// Dispatch to either the host-subprocess supervisor or the Firecracker
    /// sandbox. The caller has already done the dispatch decision and the
    /// lazy resolution; on Linux it passes `resolved` to ask for the
    /// sandbox path, or `None` for the host-subprocess fallback.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    async fn run_dispatch(
        &self,
        backend: RunBackend,
        resolved: Option<ResolvedSandbox>,
        spec: &RunSpec,
        run_id: &str,
        enc: &mut Encoder,
        workspace_path: &Path,
        agent_history_dst: &Path,
        actor: &crate::privileged_net::PrivilegedNetHandle,
    ) -> DispatchOutcome {
        if let Some(r) = resolved {
            let user_script_uid = current_uid();
            // Resolve the owner user for TAP creation. Use the current user's
            // name, which (after Module B's privilege drop) will be the User
            // Script user rather than root.
            let owner_user = resolve_current_username();
            let sandbox_result = crate::sandbox_run::run(
                r.kernel,
                r.rootfs,
                backend.firecracker_bin,
                backend.manage_firewall,
                spec,
                run_id,
                enc,
                workspace_path,
                Some(crate::sandbox_run::PoolExtraction {
                    pool: &self.pool,
                    output_branch: spec.output_branch.as_deref(),
                    agent_history_dst: Some(agent_history_dst),
                    user_script_uid,
                }),
                actor,
                &owner_user,
            )
            .await;
            return DispatchOutcome::Sandbox { sandbox_result };
        }
        let supervisor_result = crate::supervisor::run(spec, run_id, enc, workspace_path, None)
            .await
            .map_err(|e| SessionError::AgentExit { stderr: e.to_string() });
        DispatchOutcome::HostSubprocess { supervisor_result }
    }

    /// Non-Linux dispatch: sandbox intent is already rejected by the platform
    /// gate, so this only ever runs the host-subprocess supervisor.
    #[cfg(not(target_os = "linux"))]
    async fn run_dispatch(
        &self,
        backend: RunBackend,
        spec: &RunSpec,
        run_id: &str,
        enc: &mut Encoder,
        workspace_path: &Path,
        agent_history_dst: &Path,
    ) -> DispatchOutcome {
        let supervisor_result = crate::supervisor::run(spec, run_id, enc, workspace_path, None)
            .await
            .map_err(|e| SessionError::AgentExit { stderr: e.to_string() });
        // On non-Linux the sandbox branch is unreachable (the platform gate in
        // run_with_backend returned early), so the backend overrides aren't
        // load-bearing on this platform. Silence unused-field warnings.
        let _ = (
            backend.kernel,
            backend.rootfs,
            backend.firecracker_bin,
            backend.manage_firewall,
            agent_history_dst,
        );
        DispatchOutcome::HostSubprocess { supervisor_result }
    }

    /// Read a ref's SHA out of this Session's Pool, used by the sandbox
    /// dispatch path to populate `RunResult.pool_sha` after
    /// `extract_workspace_from_ext4` has written `refs/heads/runs/<run-id>`
    /// into the Pool.
    async fn read_pool_ref_sha(&self, full_ref: &str) -> Result<String, SessionError> {
        let out = tokio::process::Command::new("git")
            .current_dir(self.pool.path())
            .args(["rev-parse", "--verify", full_ref])
            .output()
            .await?;
        if !out.status.success() {
            return Err(SessionError::Git {
                context: format!("rev-parse {full_ref}"),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    async fn extract_run_output(
        &self,
        workspace_path: &Path,
        run_id: &str,
        spec: &RunSpec,
        enc: &mut Encoder,
        agent_history_dst: &Path,
    ) -> Result<RunResult, SessionError> {
        // Best-effort: preserve agent-native history (claude-code's
        // `.claude/`, aider's `.aider.*.history` files). Failures are
        // logged but do not fail the Run.
        if let Err(e) = copy_agent_history_narrow(&spec.adapter, workspace_path, agent_history_dst)
        {
            eprintln!("[session] agent-history narrow copy warning: {e}");
        }

        // BranchingStrategy::None produces a workspace with no `.git`, so
        // there is nothing to extract. A future slice may revisit this if
        // we want such Runs to leave any audit trace at all; today they
        // simply do not produce a Pool ref.
        // The supervisor layer (`crate::supervisor::run` for host-subprocess,
        // `crate::sandbox_supervisor::run` for Firecracker) already emitted
        // `run_ended` at agent exit. Warnings from the extraction phase are
        // emitted AFTER that — they're post-mortem annotations rather than
        // events on the agent timeline — and there is no second `run_ended`.
        let git_dir = workspace_path.join(".git");
        if !git_dir.exists() {
            enc.emit(
                "run_warning",
                serde_json::json!({
                    "reason": "no_git_in_workspace",
                    "detail": "BranchingStrategy::None — no commits possible",
                }),
            )?;
            return Ok(RunResult {
                run_id: run_id.into(),
                pool_sha: None,
                output_branch_pushed: None,
                uncommitted_paths: Vec::new(),
            });
        }

        let head_sha = rev_parse(workspace_path, "HEAD").await?;
        let base_sha = resolve_base_sha_for_strategy(workspace_path, &spec.branching_strategy)
            .await
            .unwrap_or_else(|_| head_sha.clone());
        let produced_commits = head_sha != base_sha;

        let uncommitted_paths = list_uncommitted(workspace_path).await.unwrap_or_default();
        if !uncommitted_paths.is_empty() {
            enc.emit(
                "run_warning",
                serde_json::json!({
                    "reason": "uncommitted_changes",
                    "count": uncommitted_paths.len(),
                    "paths": uncommitted_paths,
                    "detail": "uncommitted files are dropped — Pool ref reflects commits only",
                }),
            )?;
        }

        if !produced_commits {
            enc.emit(
                "run_warning",
                serde_json::json!({
                    "reason": "no_commits",
                    "detail": "agent produced no commits; no Pool ref written",
                }),
            )?;
            return Ok(RunResult {
                run_id: run_id.into(),
                pool_sha: None,
                output_branch_pushed: None,
                uncommitted_paths,
            });
        }

        let uid = current_uid();
        fetch_pool_from_git_dir(
            &self.pool,
            &git_dir,
            run_id,
            spec.output_branch.as_deref(),
            uid,
        )
        .await?;

        Ok(RunResult {
            run_id: run_id.into(),
            pool_sha: Some(head_sha),
            output_branch_pushed: spec.output_branch.clone(),
            uncommitted_paths,
        })
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
    crate::bunsen_paths::sessions_root()
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

/// Path the Run's transient Workspace materialises into. Deliberately a
/// sibling of the Session tree, NOT a child of `runs/<run-id>/`, so the
/// "no host-side workspace under runs/" invariant from slice 09 is
/// observable: after the Run, this dir is removed unconditionally.
fn transient_workspace_path(session_path: &Path, run_id: &str) -> PathBuf {
    let parent = session_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    parent.join(".workspace").join(format!(
        "{}-{}",
        session_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        run_id,
    ))
}

/// Snapshot of the user-relevant fields of a [`RunSpec`] for `spec.json`.
/// The spec carries non-serializable bits (a `HashMap<String, String>` of
/// secrets) and we redact those out of the on-disk record so a stray reader
/// of `runs/<id>/spec.json` cannot recover them.
fn serialize_run_spec_lite(spec: &RunSpec) -> serde_json::Value {
    serde_json::json!({
        "adapter": spec.adapter,
        "cmd": spec.cmd,
        "env_keys": spec.env.keys().collect::<Vec<_>>(),
        "branching_strategy": match &spec.branching_strategy {
            BranchingStrategy::None => serde_json::json!({"kind": "none"}),
            BranchingStrategy::PoolClone { base, import } => serde_json::json!({
                "kind": "pool-clone",
                "base": base,
                "import": import,
            }),
        },
        "output_branch": spec.output_branch,
        "wall_clock_seconds": spec.wall_clock_seconds,
    })
}

async fn rev_parse(workspace: &Path, ref_name: &str) -> Result<String, SessionError> {
    let out = tokio::process::Command::new("git")
        .current_dir(workspace)
        .args(["rev-parse", ref_name])
        .output()
        .await?;
    if !out.status.success() {
        return Err(SessionError::Git {
            context: format!("rev-parse {ref_name} in {}", workspace.display()),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn resolve_base_sha_for_strategy(
    workspace: &Path,
    strategy: &BranchingStrategy,
) -> Result<String, SessionError> {
    let base_ref = match strategy {
        BranchingStrategy::PoolClone { base, .. } => base.clone(),
        BranchingStrategy::None => return rev_parse(workspace, "HEAD").await,
    };
    // The materialiser fetched the base into the workspace as a local branch
    // with the same name. If lookup fails (e.g. someone renamed it), fall
    // back to HEAD — produced_commits then trivially evaluates to false and
    // the no-commits warning fires.
    rev_parse(workspace, &format!("refs/heads/{base_ref}")).await
}

async fn list_uncommitted(workspace: &Path) -> Result<Vec<String>, SessionError> {
    let out = tokio::process::Command::new("git")
        .current_dir(workspace)
        .args(["status", "--porcelain"])
        .output()
        .await?;
    if !out.status.success() {
        return Err(SessionError::Git {
            context: format!("status --porcelain in {}", workspace.display()),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    let mut paths = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // Porcelain v1 format: "XY <path>" — strip the two status chars
        // plus the space. `?? ` (untracked) is the most common shape; renames
        // are rare here since the workspace is fresh.
        if line.len() > 3 {
            paths.push(line[3..].to_string());
        }
    }
    Ok(paths)
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

/// Return the username for the process's current uid, falling back to "root".
/// Used to set TAP ownership so Firecracker (running as the same user after
/// Module B's privilege drop) can open the device without CAP_NET_ADMIN.
#[cfg(target_os = "linux")]
fn resolve_current_username() -> String {
    let uid = nix::unistd::getuid();
    nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| "root".to_string())
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

    // ── Session::run (slice 09) ─────────────────────────────────────────────
    //
    // Cover the AC for slice 09 by exercising the host-subprocess fallback
    // path (the Firecracker integration is identical post-extraction and
    // cannot run on macOS CI). Each test builds a real host repo, opens a
    // Session, runs a small shell agent that produces a commit (or
    // doesn't), and inspects both the transcript and the Pool.

    fn run_spec_with_cmd(cmd: &str, base_ref: &str, output_branch: Option<&str>) -> RunSpec {
        let body = match output_branch {
            Some(b) => serde_json::json!({
                "adapter": "black-box",
                "cmd": ["sh", "-c", cmd],
                "branching-strategy": {"kind": "pool-clone", "base": base_ref},
                "output-branch": b,
            }),
            None => serde_json::json!({
                "adapter": "black-box",
                "cmd": ["sh", "-c", cmd],
                "branching-strategy": {"kind": "pool-clone", "base": base_ref},
            }),
        };
        RunSpec::from_json(&serde_json::to_string(&body).unwrap()).unwrap()
    }

    fn pool_ref_sha(pool_dir: &Path, full_ref: &str) -> String {
        let out = StdCommand::new("git")
            .current_dir(pool_dir)
            .args(["rev-parse", full_ref])
            .output()
            .unwrap();
        assert!(out.status.success(), "rev-parse {full_ref} failed: {}",
                String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn pool_has_ref(pool_dir: &Path, full_ref: &str) -> bool {
        StdCommand::new("git")
            .current_dir(pool_dir)
            .args(["rev-parse", "--verify", "--quiet", full_ref])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn transcript_contains(run_dir: &Path, marker: &str) -> bool {
        let t = run_dir.join("transcript.ndjson");
        std::fs::read_to_string(&t)
            .map(|s| s.contains(marker))
            .unwrap_or(false)
    }

    const AGENT_COMMIT_CMD: &str = "\
        git config user.email agent@test && \
        git config user.name Agent && \
        echo hello > agent.txt && \
        git add agent.txt && \
        git commit -m 'agent work' --quiet";

    const AGENT_NOOP_CMD: &str = "true";

    const AGENT_DIRTY_CMD: &str = "\
        git config user.email agent@test && \
        git config user.name Agent && \
        echo committed > committed.txt && \
        git add committed.txt && \
        git commit -m 'one commit' --quiet && \
        echo dirty > leftover.txt";

    #[tokio::test]
    async fn run_writes_audit_ref_and_output_branch_at_same_sha() {
        let host = make_host_repo("sr-ok");
        let root = make_temp_dir("sr-ok-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let pool_dir = s.path().join("pool");

        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", Some("feature/done"));
        let res = s.run(spec).await.unwrap();

        assert!(res.pool_sha.is_some(), "expected a Pool SHA after a real commit");
        assert_eq!(res.output_branch_pushed.as_deref(), Some("feature/done"));
        assert!(res.uncommitted_paths.is_empty());

        let audit = format!("refs/heads/runs/{}", res.run_id);
        let user = "refs/heads/feature/done";
        assert!(pool_has_ref(&pool_dir, &audit), "audit ref missing");
        assert!(pool_has_ref(&pool_dir, user), "output_branch missing");
        assert_eq!(
            pool_ref_sha(&pool_dir, &audit),
            pool_ref_sha(&pool_dir, user),
            "audit ref and output_branch must point at the same SHA"
        );
        assert_eq!(pool_ref_sha(&pool_dir, &audit), res.pool_sha.unwrap());

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn run_with_no_commits_succeeds_and_emits_warning() {
        let host = make_host_repo("sr-empty");
        let root = make_temp_dir("sr-empty-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();
        let pool_dir = session_dir.join("pool");

        let spec = run_spec_with_cmd(AGENT_NOOP_CMD, "host/main", Some("feature/x"));
        let res = s.run(spec).await.unwrap();

        assert!(res.pool_sha.is_none(), "zero-commit Runs must not write a Pool ref");

        // Pool has no audit ref and no output_branch.
        let audit = format!("refs/heads/runs/{}", res.run_id);
        assert!(!pool_has_ref(&pool_dir, &audit));
        assert!(!pool_has_ref(&pool_dir, "refs/heads/feature/x"));

        // Transcript carries the warning marker.
        let run_dir = session_dir.join("runs").join(&res.run_id);
        assert!(
            transcript_contains(&run_dir, "no_commits"),
            "transcript must carry the no_commits warning"
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn run_with_uncommitted_changes_emits_warning_with_file_list() {
        let host = make_host_repo("sr-dirty");
        let root = make_temp_dir("sr-dirty-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();
        let pool_dir = session_dir.join("pool");

        let spec = run_spec_with_cmd(AGENT_DIRTY_CMD, "host/main", Some("feature/y"));
        let res = s.run(spec).await.unwrap();

        // Successful Run with a Pool SHA from the one committed file.
        assert!(res.pool_sha.is_some());
        assert!(
            res.uncommitted_paths.iter().any(|p| p.contains("leftover.txt")),
            "leftover.txt must appear in uncommitted_paths: {:?}",
            res.uncommitted_paths,
        );

        let audit = format!("refs/heads/runs/{}", res.run_id);
        assert!(pool_has_ref(&pool_dir, &audit));

        let run_dir = session_dir.join("runs").join(&res.run_id);
        assert!(
            transcript_contains(&run_dir, "uncommitted_changes"),
            "transcript must carry uncommitted_changes warning"
        );
        assert!(
            transcript_contains(&run_dir, "leftover.txt"),
            "transcript must list the uncommitted file by name"
        );

        // Inspect the Pool ref's tree — leftover.txt must NOT be there.
        let ls = StdCommand::new("git")
            .current_dir(&pool_dir)
            .args(["ls-tree", "-r", "--name-only", &audit])
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&ls.stdout);
        assert!(listing.contains("committed.txt"));
        assert!(
            !listing.contains("leftover.txt"),
            "uncommitted leftover must not be in the Pool ref: {listing}",
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn run_does_not_create_workspace_subdir_under_run_dir() {
        let host = make_host_repo("sr-no-ws");
        let root = make_temp_dir("sr-no-ws-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();

        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", None);
        let res = s.run(spec).await.unwrap();

        let run_dir = session_dir.join("runs").join(&res.run_id);
        assert!(run_dir.exists(), "run dir must exist");
        assert!(
            !run_dir.join("workspace").exists(),
            "host-side workspace/ under runs/<id>/ must not be created (slice 09)"
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn run_cleans_up_transient_workspace_after_extraction() {
        let host = make_host_repo("sr-transient");
        let root = make_temp_dir("sr-transient-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();

        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", None);
        let res = s.run(spec).await.unwrap();

        // The transient workspace dir under the sessions root is wiped on
        // run completion. We don't expose the exact path; instead we
        // assert the sibling `.workspace/` directory holds nothing for
        // this Run.
        let transient_parent = root.join(".workspace");
        if transient_parent.exists() {
            let remaining: Vec<_> = std::fs::read_dir(&transient_parent)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().contains(&res.run_id))
                .collect();
            assert!(
                remaining.is_empty(),
                "transient workspace for run {} must be removed",
                res.run_id
            );
        }

        // And just to be sure the Run actually wrote a Pool ref so we know
        // the test isn't trivially passing on an early-exit path.
        assert!(res.pool_sha.is_some());

        std::fs::remove_dir_all(session_dir.parent().unwrap()).ok();
        std::fs::remove_dir_all(&host).ok();
    }

    #[tokio::test]
    async fn two_runs_to_different_output_branches_both_succeed() {
        let host = make_host_repo("sr-par-diff");
        let root = make_temp_dir("sr-par-diff-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let pool_dir = s.path().join("pool");

        let spec_a = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", Some("feature/a"));
        let res_a = s.run(spec_a).await.unwrap();
        let spec_b = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", Some("feature/b"));
        let res_b = s.run(spec_b).await.unwrap();

        assert!(res_a.pool_sha.is_some() && res_b.pool_sha.is_some());
        assert!(pool_has_ref(&pool_dir, "refs/heads/feature/a"));
        assert!(pool_has_ref(&pool_dir, "refs/heads/feature/b"));
        assert!(pool_has_ref(&pool_dir, &format!("refs/heads/runs/{}", res_a.run_id)));
        assert!(pool_has_ref(&pool_dir, &format!("refs/heads/runs/{}", res_b.run_id)));

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn two_runs_to_same_output_branch_second_fails_loudly() {
        let host = make_host_repo("sr-par-same");
        let root = make_temp_dir("sr-par-same-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let pool_dir = s.path().join("pool");

        let spec_a = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", Some("feature/contested"));
        let res_a = s.run(spec_a).await.unwrap();
        assert!(res_a.pool_sha.is_some());

        let spec_b = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", Some("feature/contested"));
        let err = s.run(spec_b).await.unwrap_err();
        match err {
            SessionError::SandboxFetch(SandboxFetchError::Pool(
                BranchPoolError::RefAlreadyExists { name },
            )) => {
                assert_eq!(name, "feature/contested");
            }
            other => panic!("expected RefAlreadyExists for loser, got {other:?}"),
        }

        // Winner's ref survives untouched.
        let winner_sha = res_a.pool_sha.unwrap();
        assert_eq!(
            pool_ref_sha(&pool_dir, "refs/heads/feature/contested"),
            winner_sha,
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn run_refuses_when_session_is_closed() {
        // Hand-build a Closed Session on disk and assert Session::run rejects
        // any new Run from that state (the state machine's accept_new_run).
        let host = make_host_repo("sr-closed");
        let root = make_temp_dir("sr-closed-root");
        let id = "01CLOSEDSRUN0000000000000A".to_string();
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

        let mut s = Session::attach_in(&root, &id).unwrap();
        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", None);
        let err = s.run(spec).await.unwrap_err();
        assert!(
            matches!(err, SessionError::Transition(_)),
            "Closed → Run must be a Transition error, got {err:?}",
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn run_preserves_agent_history_to_run_dir() {
        // The narrow agent-history copy: the agent's `.claude/` dir under
        // the Workspace is preserved into the Run dir's agent-history/.
        let host = make_host_repo("sr-history");
        let root = make_temp_dir("sr-history-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();

        let cmd = "\
            git config user.email a@b && \
            git config user.name A && \
            mkdir -p .claude && \
            echo memo > .claude/notes.json && \
            echo committed > x.txt && \
            git add x.txt && \
            git commit -m c --quiet";

        let spec = run_spec_with_cmd(cmd, "host/main", None);
        let res = s.run(spec).await.unwrap();

        let history = session_dir
            .join("runs")
            .join(&res.run_id)
            .join("agent-history")
            .join(".claude")
            .join("notes.json");
        assert!(history.exists(), "agent .claude/notes.json must be preserved");
        assert_eq!(std::fs::read_to_string(&history).unwrap().trim(), "memo");

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    // ── Session::run_with_backend (Firecracker dispatch wiring) ─────────────

    /// The transcript contract: exactly one `run_ended` event per Run. The
    /// supervisor layer (`crate::supervisor::run` for host-subprocess,
    /// `crate::sandbox_supervisor::run` for Firecracker) is responsible for
    /// emitting it; no other layer may add a second.
    #[tokio::test]
    async fn run_emits_exactly_one_run_ended_event() {
        let host = make_host_repo("sr-one-run-ended");
        let root = make_temp_dir("sr-one-run-ended-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();

        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", None);
        let res = s.run(spec).await.unwrap();

        let transcript = session_dir
            .join("runs")
            .join(&res.run_id)
            .join("transcript.ndjson");
        let body = std::fs::read_to_string(&transcript).unwrap();
        let count = body
            .lines()
            .filter(|l| l.contains("\"type\":\"run_ended\""))
            .count();
        assert_eq!(
            count, 1,
            "transcript must carry exactly one run_ended event; got {count}\n{body}"
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// Tracer bullet for the Firecracker dispatch wiring: the new
    /// `Session::run_with_backend` entry point, given the default backend
    /// (no kernel/rootfs), behaves exactly like the existing
    /// `Session::run` — it goes through the host-subprocess supervisor and
    /// extracts to the Pool through `fetch_pool_from_git_dir`.
    #[tokio::test]
    async fn run_with_backend_default_matches_run_for_host_subprocess() {
        let host = make_host_repo("sr-rwb-default");
        let root = make_temp_dir("sr-rwb-default-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let pool_dir = s.path().join("pool");

        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", Some("feature/rwb"));
        let res = s.run_with_backend(spec, RunBackend::default()).await.unwrap();

        // Same observable result as `Session::run` produces on this AGENT_COMMIT_CMD:
        // a populated pool_sha and the output_branch echoed back.
        assert!(res.pool_sha.is_some(), "expected a Pool SHA after a real commit");
        assert_eq!(res.output_branch_pushed.as_deref(), Some("feature/rwb"));
        assert!(res.uncommitted_paths.is_empty());

        let audit = format!("refs/heads/runs/{}", res.run_id);
        let user = "refs/heads/feature/rwb";
        assert!(pool_has_ref(&pool_dir, &audit), "audit ref missing");
        assert!(pool_has_ref(&pool_dir, user), "output_branch missing");
        assert_eq!(
            pool_ref_sha(&pool_dir, &audit),
            pool_ref_sha(&pool_dir, user),
            "audit ref and output_branch must point at the same SHA"
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// Linux dispatch proof: a backend with a kernel routes through the
    /// Firecracker path, not the host-subprocess supervisor. The
    /// host-subprocess path would trivially succeed on a `cmd: ["true"]`
    /// spec; the Firecracker path with a non-existent kernel must fail.
    /// Distinguishing the two error paths proves dispatch happened.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn run_with_backend_kernel_dispatches_into_firecracker_on_linux() {
        let host = make_host_repo("sr-rwb-fc");
        let root = make_temp_dir("sr-rwb-fc-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();

        let nonexistent_kernel = root.join("does-not-exist-vmlinux");
        let nonexistent_rootfs = root.join("does-not-exist-rootfs.ext4");
        let backend = RunBackend {
            kernel: Some(nonexistent_kernel),
            rootfs: Some(nonexistent_rootfs),
            ..RunBackend::default()
        };

        // The host-subprocess path would happily run `true` and return Ok;
        // the Firecracker path can't boot a non-existent kernel and must
        // surface an error. Treat that asymmetry as the dispatch proof.
        let spec = run_spec_with_cmd("true", "host/main", None);
        let result = s.run_with_backend(spec, backend).await;
        assert!(
            result.is_err(),
            "with a non-existent kernel the Firecracker path must fail, \
             not silently fall through to the host-subprocess supervisor"
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// `firecracker_bin` alone is NOT a sandbox trigger — it's a `$PATH`
    /// override, not a "use the sandbox" signal. Matches the legacy CLI's
    /// behaviour where `bunsen-core --firecracker /path/to/firecracker
    /// --spec ...` (without `--kernel` or `--rootfs` or `oci_image`) stays
    /// in the host-subprocess path.
    #[tokio::test]
    async fn run_with_firecracker_bin_alone_does_not_trigger_sandbox() {
        let host = make_host_repo("sr-fcbin-noop");
        let root = make_temp_dir("sr-fcbin-noop-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();

        // `firecracker_bin` set, but no kernel/rootfs/oci_image. The Run
        // should go through the host-subprocess supervisor on every
        // platform, including non-Linux (no SandboxUnsupportedOnPlatform).
        let backend = RunBackend {
            firecracker_bin: Some(PathBuf::from("/usr/local/bin/firecracker")),
            ..RunBackend::default()
        };
        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", None);
        let res = s.run_with_backend(spec, backend).await.unwrap();
        assert!(res.pool_sha.is_some(), "host-subprocess path produced no Pool ref");

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// `spec.oci_image` alone (no kernel/rootfs in the backend) triggers
    /// sandbox intent — the legacy CLI's "trigger for sandbox is rootfs
    /// or oci_image" rule, lifted into the Session layer.
    ///
    /// On non-Linux this surfaces as `SandboxUnsupportedOnPlatform`, which
    /// is the cleanest cross-platform proof that the spec's `oci_image`
    /// field was consulted by the dispatch logic. (On Linux the same input
    /// triggers real OCI resolution + Firecracker; that path is exercised
    /// by the end-to-end smoke on a real Linux box.)
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn run_with_oci_image_in_spec_triggers_sandbox_intent() {
        let host = make_host_repo("sr-oci-intent");
        let root = make_temp_dir("sr-oci-intent-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();

        // Spec with oci_image set; default RunBackend (no explicit kernel).
        let body = serde_json::json!({
            "adapter": "black-box",
            "cmd": ["true"],
            "branching-strategy": {"kind": "pool-clone", "base": "host/main"},
            "oci-image": "ghcr.io/example/agent@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        });
        let spec = RunSpec::from_json(&serde_json::to_string(&body).unwrap()).unwrap();
        let err = s.run_with_backend(spec, RunBackend::default()).await.unwrap_err();
        assert!(
            matches!(err, SessionError::SandboxUnsupportedOnPlatform),
            "expected SandboxUnsupportedOnPlatform from spec.oci_image alone, got {err:?}"
        );

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// Slice 13: a DROP-by-default INPUT chain with no covering rule and
    /// `manage_firewall=false` must fail upfront with the typed
    /// `HostFirewallBlocked` error, BEFORE the run dir / transcript / Pool
    /// side-effects land. The legacy CLI already does this in main.rs; this
    /// test pins the parity for `Session::run_with_backend`.
    ///
    /// Linux-only because the iptables probe is Linux-only and the env-var
    /// test hook lives in `crate::firewall`. The hook + the
    /// `TEST_IPTABLES_SAVE_LOCK` mutex serialize concurrent tests touching
    /// the global env var.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn run_with_backend_returns_host_firewall_blocked_on_drop_policy() {
        const UBUNTU_UFW_DROP: &str = "\
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT
";

        let host = make_host_repo("sr-fw-blocked");
        let root = make_temp_dir("sr-fw-blocked-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();

        // Real-looking kernel/rootfs paths so `resolve_sandbox_inputs`
        // succeeds (it only checks for `Some`, not whether the files boot).
        // The probe is what we expect to gate the Run.
        let kernel = root.join("fake-vmlinux");
        let rootfs = root.join("fake-rootfs.ext4");
        std::fs::write(&kernel, b"not-a-kernel").unwrap();
        std::fs::write(&rootfs, b"not-a-rootfs").unwrap();
        let backend = RunBackend {
            kernel: Some(kernel),
            rootfs: Some(rootfs),
            firecracker_bin: None,
            manage_firewall: false,
        };
        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", None);

        // Serialise around the global env var.
        let _guard = crate::firewall::TEST_IPTABLES_SAVE_LOCK.lock().unwrap();
        std::env::set_var(crate::firewall::TEST_IPTABLES_SAVE_ENV, UBUNTU_UFW_DROP);
        let err = s.run_with_backend(spec, backend).await.unwrap_err();
        std::env::remove_var(crate::firewall::TEST_IPTABLES_SAVE_ENV);
        drop(_guard);

        let message = match &err {
            SessionError::HostFirewallBlocked { message } => message.clone(),
            other => panic!("expected HostFirewallBlocked, got {other:?}"),
        };
        assert_eq!(message, crate::firewall_check::BLOCKED_MESSAGE);

        // Probe failure must leave the Session bit-identical on disk: no run
        // dir, no transient workspace. The state machine was never advanced.
        let runs_dir = session_dir.join("runs");
        if runs_dir.exists() {
            let leftover: Vec<_> = std::fs::read_dir(&runs_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            assert!(leftover.is_empty(), "no run dir leftover on HostFirewallBlocked");
        }
        let transient = root.join(".workspace");
        if transient.exists() {
            let leftover: Vec<_> = std::fs::read_dir(&transient)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            assert!(leftover.is_empty(), "no transient workspace leftover");
        }

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// Slice 13: opting into `manage_firewall=true` makes the same Blocked
    /// dump pass the probe — the per-TAP allow rule is installed later by
    /// `sandbox_run::run`. The Run then fails for a *different* reason
    /// (the fake kernel/rootfs can't boot Firecracker), proving the probe
    /// no longer short-circuits.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn run_with_backend_manage_firewall_true_passes_probe_on_drop_policy() {
        const UBUNTU_UFW_DROP: &str = "\
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT
";

        let host = make_host_repo("sr-fw-mgmt");
        let root = make_temp_dir("sr-fw-mgmt-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();

        let kernel = root.join("fake-vmlinux");
        let rootfs = root.join("fake-rootfs.ext4");
        std::fs::write(&kernel, b"not-a-kernel").unwrap();
        std::fs::write(&rootfs, b"not-a-rootfs").unwrap();
        let backend = RunBackend {
            kernel: Some(kernel),
            rootfs: Some(rootfs),
            firecracker_bin: None,
            manage_firewall: true,
        };
        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", None);

        let _guard = crate::firewall::TEST_IPTABLES_SAVE_LOCK.lock().unwrap();
        std::env::set_var(crate::firewall::TEST_IPTABLES_SAVE_ENV, UBUNTU_UFW_DROP);
        let result = s.run_with_backend(spec, backend).await;
        std::env::remove_var(crate::firewall::TEST_IPTABLES_SAVE_ENV);
        drop(_guard);

        // Probe must NOT short-circuit when manage_firewall is true. The Run
        // can still fail downstream — fake kernel can't boot Firecracker —
        // but the *kind* of error must be anything other than
        // HostFirewallBlocked.
        match result {
            Ok(_) => {} // unlikely with a bogus kernel, but acceptable
            Err(SessionError::HostFirewallBlocked { .. }) => {
                panic!("manage_firewall=true must bypass the host-firewall probe")
            }
            Err(_) => {} // any other failure (sandbox boot, etc.) is fine
        }

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }

    /// On non-Linux platforms, asking for the sandbox backend must fail
    /// loudly without leaving a Run dir or a Pool ref behind. Linux callers
    /// reach the real Firecracker path; everyone else gets a typed error
    /// they can route on.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn run_with_backend_sandbox_unsupported_on_non_linux() {
        let host = make_host_repo("sr-rwb-unsupp");
        let root = make_temp_dir("sr-rwb-unsupp-root");
        let mut s = Session::open_in(&root, &host, vec!["main".into()], None)
            .await
            .unwrap();
        let session_dir = s.path().to_path_buf();

        // Any path is fine — the check is platform-gated, the path is never
        // dereferenced on macOS.
        let backend = RunBackend {
            kernel: Some(PathBuf::from("/nonexistent/vmlinux")),
            rootfs: Some(PathBuf::from("/nonexistent/rootfs.ext4")),
            ..RunBackend::default()
        };
        let spec = run_spec_with_cmd(AGENT_COMMIT_CMD, "host/main", None);
        let err = s.run_with_backend(spec, backend).await.unwrap_err();
        assert!(
            matches!(err, SessionError::SandboxUnsupportedOnPlatform),
            "expected SandboxUnsupportedOnPlatform, got {err:?}"
        );

        // No transient workspace, no Run dir.
        let transient = root.join(".workspace");
        if transient.exists() {
            let leftover: Vec<_> = std::fs::read_dir(&transient)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            assert!(leftover.is_empty(), "no transient workspace leftover");
        }
        let runs_dir = session_dir.join("runs");
        if runs_dir.exists() {
            let leftover: Vec<_> = std::fs::read_dir(&runs_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            assert!(leftover.is_empty(), "no run dir leftover");
        }

        std::fs::remove_dir_all(&host).ok();
        std::fs::remove_dir_all(&root).ok();
    }
}
