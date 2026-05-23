use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RunSpec {
    pub adapter: String,
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub secrets: HashMap<String, String>,
    #[serde(default)]
    pub branching_strategy: Option<String>,
    #[serde(default)]
    pub host_repo_path: Option<String>,
    #[serde(default = "default_stop_grace_seconds")]
    pub stop_grace_seconds: u64,
    #[serde(default = "default_wall_clock_seconds")]
    pub wall_clock_seconds: u64,
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u32,
    #[serde(default = "default_vcpus")]
    pub vcpus: u32,
    #[serde(default = "default_workspace_disk_mb")]
    pub workspace_disk_mb: u32,
    #[serde(default)]
    pub oci_image: Option<String>,
}

fn default_stop_grace_seconds() -> u64 { 10 }
fn default_wall_clock_seconds() -> u64 { 1800 }
fn default_memory_mb() -> u32 { 4096 }
fn default_vcpus() -> u32 { 2 }
fn default_workspace_disk_mb() -> u32 { 10240 }

impl RunSpec {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_wall_clock_seconds_is_1800() {
        let spec = RunSpec::from_json(r#"{"adapter":"black-box","cmd":["echo"]}"#).unwrap();
        assert_eq!(spec.wall_clock_seconds, 1800);
    }

    #[test]
    fn explicit_wall_clock_seconds_parsed() {
        let spec = RunSpec::from_json(r#"{"adapter":"black-box","cmd":["echo"],"wall-clock-seconds":42}"#).unwrap();
        assert_eq!(spec.wall_clock_seconds, 42);
    }

    #[test]
    fn default_resource_limits() {
        let spec = RunSpec::from_json(r#"{"adapter":"black-box","cmd":["echo"]}"#).unwrap();
        assert_eq!(spec.memory_mb, 4096);
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.workspace_disk_mb, 10240);
    }

    #[test]
    fn explicit_resource_limits_parsed() {
        let spec = RunSpec::from_json(r#"{"adapter":"black-box","cmd":["echo"],"memory-mb":512,"vcpus":4,"workspace-disk-mb":2048}"#).unwrap();
        assert_eq!(spec.memory_mb, 512);
        assert_eq!(spec.vcpus, 4);
        assert_eq!(spec.workspace_disk_mb, 2048);
    }

    // Cycle 6: oci-image field is deserialized.
    #[test]
    fn oci_image_in_run_spec() {
        const HEX64: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let json = format!(
            r#"{{"adapter":"black-box","cmd":["echo"],"oci-image":"ghcr.io/x/y@sha256:{HEX64}"}}"#
        );
        let spec = RunSpec::from_json(&json).unwrap();
        assert_eq!(
            spec.oci_image.as_deref(),
            Some(&format!("ghcr.io/x/y@sha256:{HEX64}") as &str)
        );
    }

    // Cycle 7: oci_image is None when field is absent.
    #[test]
    fn oci_image_absent_in_run_spec() {
        let spec = RunSpec::from_json(r#"{"adapter":"black-box","cmd":["echo"]}"#).unwrap();
        assert!(spec.oci_image.is_none());
    }
}
