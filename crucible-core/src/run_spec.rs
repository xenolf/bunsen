use serde::Deserialize;
use std::collections::HashMap;

use crate::egress::EgressPolicy;

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
    /// User-Script-supplied egress allowlist additions. Composed with the
    /// adapter's declared endpoints by [`RunSpec::effective_egress_policy`].
    #[serde(default)]
    pub egress_endpoints: Vec<String>,
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

    /// Compose the effective Egress Policy for this Run: the adapter's
    /// declared required endpoints unioned with `spec.egress_endpoints`.
    /// Unknown adapters contribute no declared endpoints — the User Script
    /// is responsible for the entire allowlist.
    pub fn effective_egress_policy(&self) -> EgressPolicy {
        let adapter_declared: &[&str] = match self.adapter.as_str() {
            "claude-code" => crate::claude_code_adapter::EGRESS_ENDPOINTS,
            "aider" => {
                // Aider's required endpoint depends on the configured model
                // (Anthropic vs OpenAI vs Gemini). Extract `--model X` from
                // the user-supplied cmd and look it up. When no model is
                // declared — or it's unknown — the user-script's
                // `egress-endpoints` is the only source.
                match crate::aider_adapter::extract_model_from_cmd(&self.cmd) {
                    Some(m) => crate::aider_adapter::egress_endpoints_for_model(&m),
                    None => &[],
                }
            }
            _ => &[],
        };
        EgressPolicy::compose(adapter_declared, &self.egress_endpoints)
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

    // ── Slice 10a: egress endpoints ───────────────────────────────────────

    #[test]
    fn egress_endpoints_default_empty() {
        let spec = RunSpec::from_json(r#"{"adapter":"black-box","cmd":["echo"]}"#).unwrap();
        assert!(spec.egress_endpoints.is_empty());
    }

    #[test]
    fn egress_endpoints_parsed_kebab_case() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"black-box","cmd":["x"],"egress-endpoints":["github.com","pypi.org"]}"#,
        )
        .unwrap();
        assert_eq!(spec.egress_endpoints, vec!["github.com", "pypi.org"]);
    }

    #[test]
    fn effective_policy_for_claude_code_includes_anthropic_default() {
        let spec = RunSpec::from_json(r#"{"adapter":"claude-code","cmd":["claude"]}"#).unwrap();
        let policy = spec.effective_egress_policy();
        assert!(policy.allows("api.anthropic.com"));
        assert!(!policy.allows("github.com"));
    }

    #[test]
    fn effective_policy_unions_adapter_and_user_additions() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"claude-code","cmd":["claude"],"egress-endpoints":["github.com"]}"#,
        )
        .unwrap();
        let policy = spec.effective_egress_policy();
        assert!(policy.allows("api.anthropic.com"));
        assert!(policy.allows("github.com"));
    }

    #[test]
    fn effective_policy_for_aider_with_openai_model_includes_openai() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"aider","cmd":["aider","--model","gpt-4o","--message","hi"]}"#,
        )
        .unwrap();
        let policy = spec.effective_egress_policy();
        assert!(policy.allows("api.openai.com"));
        assert!(!policy.allows("api.anthropic.com"));
    }

    #[test]
    fn effective_policy_for_aider_with_claude_model_includes_anthropic() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"aider","cmd":["aider","--model=claude-3-5-sonnet"]}"#,
        )
        .unwrap();
        let policy = spec.effective_egress_policy();
        assert!(policy.allows("api.anthropic.com"));
    }

    #[test]
    fn effective_policy_for_aider_without_model_is_user_only() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"aider","cmd":["aider","--message","hi"],"egress-endpoints":["api.openai.com"]}"#,
        )
        .unwrap();
        let policy = spec.effective_egress_policy();
        assert!(policy.allows("api.openai.com"));
        assert!(!policy.allows("api.anthropic.com"));
    }

    #[test]
    fn effective_policy_for_aider_unions_adapter_and_user_additions() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"aider","cmd":["aider","--model","gpt-4o"],"egress-endpoints":["github.com"]}"#,
        )
        .unwrap();
        let policy = spec.effective_egress_policy();
        assert!(policy.allows("api.openai.com"));
        assert!(policy.allows("github.com"));
    }

    #[test]
    fn effective_policy_for_unknown_adapter_is_user_only() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"black-box","cmd":["x"],"egress-endpoints":["pypi.org"]}"#,
        )
        .unwrap();
        let policy = spec.effective_egress_policy();
        assert!(policy.allows("pypi.org"));
        assert!(!policy.allows("api.anthropic.com"));
    }
}
