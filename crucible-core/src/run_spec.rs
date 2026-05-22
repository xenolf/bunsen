use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RunSpec {
    pub adapter: String,
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl RunSpec {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}
