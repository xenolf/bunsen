//! RunDir — the per-Run on-disk directory, nested under a Session.
//!
//! From [ADR-0010] and slice 08: a Run dir lives at
//! `~/.local/share/bunsen/sessions/<session-id>/runs/<run-id>/`. The
//! `runs/` subdirectory is created lazily — `Session::open` does not
//! materialise it, so a Session with no Runs has no `runs/` on disk.
//! `rm -rf` of one Session dir cleans the Session and every Run it owns
//! by construction; there are no orphan Run dirs.
//!
//! `RunDir::workspace_path()` was removed in this slice: callers that
//! want to inspect Workspace files create a `git worktree` from a Pool
//! ref instead (slice 11 documents the helper).
//!
//! [ADR-0010]: ../../../docs/adr/0010-session-and-branch-pool.md

use std::path::{Path, PathBuf};
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct ResourceLimits {
    pub memory_mb: u32,
    pub vcpus: u32,
    pub workspace_disk_mb: u32,
    pub wall_clock_seconds: u64,
}

pub struct RunDir {
    pub path: PathBuf,
    #[allow(dead_code)]
    pub run_id: String,
}

#[derive(Serialize)]
pub struct MetaJson {
    pub run_id: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_reason: Option<String>,
    pub schema_version: u32,
    pub bunsen_version: String,
    pub parent_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,
}

impl RunDir {
    /// Create `<session_path>/runs/<run_id>/`, lazily materialising the
    /// `runs/` parent if this is the Session's first Run. Returns the
    /// handle; no `workspace/` subdirectory is created — the Workspace
    /// is materialised inside the Sandbox from a Pool clone (slice 06)
    /// and never lives on the host alongside the Run dir.
    pub fn create(session_path: &Path, run_id: &str) -> std::io::Result<Self> {
        let base = session_path.join("runs").join(run_id);
        std::fs::create_dir_all(&base)?;
        Ok(RunDir { path: base, run_id: run_id.to_string() })
    }

    pub fn transcript_path(&self) -> PathBuf {
        self.path.join("transcript.ndjson")
    }

    pub fn write_spec(&self, spec_json: &str) -> std::io::Result<()> {
        std::fs::write(self.path.join("spec.json"), spec_json)
    }

    pub fn agent_history_path(&self) -> PathBuf {
        self.path.join("agent-history")
    }

    pub fn write_meta(&self, meta: &MetaJson) -> std::io::Result<()> {
        let s = serde_json::to_string_pretty(meta).unwrap();
        std::fs::write(self.path.join("meta.json"), s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{SCHEMA_VERSION, BUNSEN_VERSION};
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
            "bunsen-rundir-{suffix}-{pid}-{nanos}-{n}"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resource_limits_serialized_in_meta() {
        let meta = MetaJson {
            run_id: "test-run".to_string(),
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            ended_at: None,
            exit_reason: None,
            schema_version: SCHEMA_VERSION,
            bunsen_version: BUNSEN_VERSION.to_string(),
            parent_run_id: None,
            resource_limits: Some(ResourceLimits {
                memory_mb: 512,
                vcpus: 1,
                workspace_disk_mb: 1024,
                wall_clock_seconds: 300,
            }),
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&meta).unwrap()).unwrap();
        assert_eq!(v["resource_limits"]["memory_mb"], 512);
        assert_eq!(v["resource_limits"]["vcpus"], 1);
        assert_eq!(v["resource_limits"]["workspace_disk_mb"], 1024);
        assert_eq!(v["resource_limits"]["wall_clock_seconds"], 300);
    }

    #[test]
    fn agent_history_path_is_under_run_dir() {
        let rd = RunDir {
            path: PathBuf::from("/tmp/sessions/01HSESSION/runs/01HRUN"),
            run_id: "01HRUN".into(),
        };
        assert_eq!(
            rd.agent_history_path(),
            PathBuf::from("/tmp/sessions/01HSESSION/runs/01HRUN/agent-history"),
        );
    }

    #[test]
    fn resource_limits_absent_when_none() {
        let meta = MetaJson {
            run_id: "test-run".to_string(),
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            ended_at: None,
            exit_reason: None,
            schema_version: SCHEMA_VERSION,
            bunsen_version: BUNSEN_VERSION.to_string(),
            parent_run_id: None,
            resource_limits: None,
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&meta).unwrap()).unwrap();
        assert!(v.get("resource_limits").is_none());
    }

    // ── New layout: <session>/runs/<run-id>/ (slice 08) ──────────────────

    #[test]
    fn create_nests_run_under_session_runs_subdir() {
        let session = make_temp_dir("create-nest");
        let rd = RunDir::create(&session, "01HRUNA").unwrap();
        assert_eq!(rd.path, session.join("runs").join("01HRUNA"));
        assert!(rd.path.exists());
        assert!(session.join("runs").exists(), "runs/ parent must exist after first Run");
        std::fs::remove_dir_all(&session).ok();
    }

    #[test]
    fn create_does_not_make_workspace_subdir() {
        // Slice 08 removed `workspace_path()` — there is no host-side
        // workspace tree under the Run dir. The Workspace is materialised
        // inside the Sandbox from a Pool clone and is never copied back
        // here (the host-side `cp -a` is replaced by Sandbox Fetch in
        // slice 09).
        let session = make_temp_dir("no-workspace");
        let rd = RunDir::create(&session, "01HRUNB").unwrap();
        assert!(!rd.path.join("workspace").exists());
        std::fs::remove_dir_all(&session).ok();
    }

    #[test]
    fn create_is_idempotent_across_sibling_runs() {
        // Two Runs in the same Session share the runs/ parent; the
        // second Run does not error on the existing directory.
        let session = make_temp_dir("two-runs");
        let _a = RunDir::create(&session, "01HRUNX").unwrap();
        let _b = RunDir::create(&session, "01HRUNY").unwrap();
        let mut runs: Vec<String> = std::fs::read_dir(session.join("runs"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        runs.sort();
        assert_eq!(runs, vec!["01HRUNX".to_string(), "01HRUNY".to_string()]);
        std::fs::remove_dir_all(&session).ok();
    }

    #[test]
    fn rm_rf_of_session_dir_removes_all_run_dirs() {
        // The clean-discard property: `rm -rf <session>` is a complete
        // wipe of the Session and every Run it owns, by construction.
        let session = make_temp_dir("rm-rf");
        RunDir::create(&session, "01HRUN1").unwrap();
        RunDir::create(&session, "01HRUN2").unwrap();
        assert!(session.join("runs").join("01HRUN1").exists());
        assert!(session.join("runs").join("01HRUN2").exists());
        std::fs::remove_dir_all(&session).unwrap();
        assert!(!session.exists());
    }

    #[test]
    fn transcript_and_spec_and_meta_land_inside_run_dir() {
        let session = make_temp_dir("paths");
        let rd = RunDir::create(&session, "01HRUNZ").unwrap();
        rd.write_spec(r#"{"adapter":"x","cmd":["y"]}"#).unwrap();
        let meta = MetaJson {
            run_id: "01HRUNZ".into(),
            started_at: "2026-01-01T00:00:00.000Z".into(),
            ended_at: None,
            exit_reason: None,
            schema_version: SCHEMA_VERSION,
            bunsen_version: BUNSEN_VERSION.to_string(),
            parent_run_id: None,
            resource_limits: None,
        };
        rd.write_meta(&meta).unwrap();
        assert!(rd.path.join("spec.json").exists());
        assert!(rd.path.join("meta.json").exists());
        assert_eq!(rd.transcript_path(), rd.path.join("transcript.ndjson"));
        assert_eq!(rd.agent_history_path(), rd.path.join("agent-history"));
        std::fs::remove_dir_all(&session).ok();
    }
}
