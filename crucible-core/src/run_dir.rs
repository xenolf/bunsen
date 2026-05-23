use std::path::PathBuf;
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
    pub crucible_version: String,
    pub parent_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,
}

impl RunDir {
    pub fn create(run_id: &str) -> std::io::Result<Self> {
        let base = xdg_data_home().join("crucible").join("runs").join(run_id);
        std::fs::create_dir_all(&base)?;
        std::fs::create_dir_all(base.join("workspace"))?;
        Ok(RunDir { path: base, run_id: run_id.to_string() })
    }

    pub fn workspace_path(&self) -> PathBuf {
        self.path.join("workspace")
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

fn xdg_data_home() -> PathBuf {
    if let Ok(v) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(v)
    } else {
        dirs_home().join(".local").join("share")
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{SCHEMA_VERSION, CRUCIBLE_VERSION};

    #[test]
    fn resource_limits_serialized_in_meta() {
        let meta = MetaJson {
            run_id: "test-run".to_string(),
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            ended_at: None,
            exit_reason: None,
            schema_version: SCHEMA_VERSION,
            crucible_version: CRUCIBLE_VERSION.to_string(),
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
        let rd = RunDir { path: PathBuf::from("/tmp/runs/TESTRUN"), run_id: "TESTRUN".into() };
        assert_eq!(rd.agent_history_path(), PathBuf::from("/tmp/runs/TESTRUN/agent-history"));
    }

    #[test]
    fn resource_limits_absent_when_none() {
        let meta = MetaJson {
            run_id: "test-run".to_string(),
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            ended_at: None,
            exit_reason: None,
            schema_version: SCHEMA_VERSION,
            crucible_version: CRUCIBLE_VERSION.to_string(),
            parent_run_id: None,
            resource_limits: None,
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&meta).unwrap()).unwrap();
        assert!(v.get("resource_limits").is_none());
    }
}
