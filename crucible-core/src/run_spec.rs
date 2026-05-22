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
}

fn default_stop_grace_seconds() -> u64 { 10 }

impl RunSpec {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}
