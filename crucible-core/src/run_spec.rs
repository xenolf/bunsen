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
}

fn default_stop_grace_seconds() -> u64 { 10 }
fn default_wall_clock_seconds() -> u64 { 1800 }

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
}
