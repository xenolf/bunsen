#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde::Deserialize;
use std::collections::HashMap;

use crate::branch_pool::{RESERVED_HOST, RESERVED_RUNS};
use crate::egress::EgressPolicy;

/// How a Workspace gets its initial state. Sourced from the Session's
/// [`crate::branch_pool::BranchPool`] — never directly from the host repo.
///
/// `None` produces an empty Workspace with no `.git`. `PoolClone` clones the
/// Pool at `base` and additionally fetches each ref in `import` as a local
/// ref under the same name. A `base` or `import` ref that is not present in
/// the Pool fails loudly — there is no lazy fallback that fetches from the
/// host repo at materialise time.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BranchingStrategy {
    #[default]
    None,
    PoolClone {
        base: String,
        #[serde(default)]
        import: Vec<String>,
    },
}

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
    pub branching_strategy: BranchingStrategy,
    /// User-named ref to publish the Run's commits under in the Pool.
    /// Validated at parse time against legal git branch names and against
    /// the reserved `host/*` and `runs/*` namespaces.
    #[serde(default)]
    pub output_branch: Option<String>,
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

#[derive(Debug)]
pub enum RunSpecError {
    Serde(serde_json::Error),
    ReservedNamespace { name: String, namespace: &'static str },
    IllegalBranchName(String),
}

impl std::fmt::Display for RunSpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serde(e) => write!(f, "{e}"),
            Self::ReservedNamespace { name, namespace } => write!(
                f,
                "output_branch {name:?} falls in reserved namespace {namespace:?}"
            ),
            Self::IllegalBranchName(name) => write!(
                f,
                "output_branch {name:?} is not a legal git branch name"
            ),
        }
    }
}

impl std::error::Error for RunSpecError {}

impl From<serde_json::Error> for RunSpecError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}

impl RunSpec {
    pub fn from_json(s: &str) -> Result<Self, RunSpecError> {
        let spec: Self = serde_json::from_str(s)?;
        if let Some(ref name) = spec.output_branch {
            validate_output_branch(name)?;
        }
        Ok(spec)
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
            "codex" => crate::codex_adapter::EGRESS_ENDPOINTS,
            _ => &[],
        };
        EgressPolicy::compose(adapter_declared, &self.egress_endpoints)
    }
}

/// Validate a user-supplied `output_branch` name. Rejects refs in the
/// reserved `host/*` and `runs/*` namespaces (which the Pool owns) and
/// names that are not legal git branch names.
pub(crate) fn validate_output_branch(name: &str) -> Result<(), RunSpecError> {
    if name.starts_with(RESERVED_HOST) {
        return Err(RunSpecError::ReservedNamespace {
            name: name.into(),
            namespace: RESERVED_HOST,
        });
    }
    if name.starts_with(RESERVED_RUNS) {
        return Err(RunSpecError::ReservedNamespace {
            name: name.into(),
            namespace: RESERVED_RUNS,
        });
    }
    if !is_legal_git_branch_name(name) {
        return Err(RunSpecError::IllegalBranchName(name.into()));
    }
    Ok(())
}

/// Apply git's `check-ref-format --branch` rules without shelling out.
/// Mirrors the constraints from `git-check-ref-format(1)`.
fn is_legal_git_branch_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name == "@" || name == "HEAD" {
        return false;
    }
    if name.starts_with('-') {
        return false;
    }
    if name.starts_with('/') || name.ends_with('/') {
        return false;
    }
    if name.ends_with('.') {
        return false;
    }
    if name.contains("..") || name.contains("@{") || name.contains("//") {
        return false;
    }
    for c in name.chars() {
        if (c as u32) < 0x20 || c == 0x7f as char {
            return false;
        }
        if matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\') {
            return false;
        }
    }
    for comp in name.split('/') {
        if comp.is_empty() {
            return false;
        }
        if comp.starts_with('.') {
            return false;
        }
        if comp.ends_with(".lock") {
            return false;
        }
    }
    true
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
    fn effective_policy_for_codex_includes_openai() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"codex","cmd":["codex","exec","--json","--ephemeral","do the thing"]}"#,
        )
        .unwrap();
        let policy = spec.effective_egress_policy();
        assert!(policy.allows("api.openai.com"));
        assert!(!policy.allows("api.anthropic.com"));
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

    // ── Slice 06: typed branching strategy ────────────────────────────────

    #[test]
    fn branching_strategy_defaults_to_none() {
        let spec = RunSpec::from_json(r#"{"adapter":"black-box","cmd":["echo"]}"#).unwrap();
        assert_eq!(spec.branching_strategy, BranchingStrategy::None);
    }

    #[test]
    fn branching_strategy_none_parsed_with_explicit_kind() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"black-box","cmd":["x"],"branching-strategy":{"kind":"none"}}"#,
        )
        .unwrap();
        assert_eq!(spec.branching_strategy, BranchingStrategy::None);
    }

    #[test]
    fn branching_strategy_pool_clone_parsed() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"black-box","cmd":["x"],"branching-strategy":{"kind":"pool-clone","base":"host/main","import":["feature/a","feature/b"]}}"#,
        )
        .unwrap();
        assert_eq!(
            spec.branching_strategy,
            BranchingStrategy::PoolClone {
                base: "host/main".into(),
                import: vec!["feature/a".into(), "feature/b".into()],
            },
        );
    }

    #[test]
    fn branching_strategy_pool_clone_import_defaults_empty() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"black-box","cmd":["x"],"branching-strategy":{"kind":"pool-clone","base":"host/main"}}"#,
        )
        .unwrap();
        match spec.branching_strategy {
            BranchingStrategy::PoolClone { base, import } => {
                assert_eq!(base, "host/main");
                assert!(import.is_empty());
            }
            other => panic!("expected PoolClone, got {other:?}"),
        }
    }

    // ── Slice 06: output_branch validation ────────────────────────────────

    #[test]
    fn output_branch_defaults_to_none() {
        let spec = RunSpec::from_json(r#"{"adapter":"black-box","cmd":["x"]}"#).unwrap();
        assert!(spec.output_branch.is_none());
    }

    #[test]
    fn output_branch_parsed() {
        let spec = RunSpec::from_json(
            r#"{"adapter":"black-box","cmd":["x"],"output-branch":"feature/ok"}"#,
        )
        .unwrap();
        assert_eq!(spec.output_branch.as_deref(), Some("feature/ok"));
    }

    #[test]
    fn output_branch_rejects_reserved_host_namespace() {
        let err = RunSpec::from_json(
            r#"{"adapter":"black-box","cmd":["x"],"output-branch":"host/sneaky"}"#,
        )
        .unwrap_err();
        match err {
            RunSpecError::ReservedNamespace { name, namespace } => {
                assert_eq!(name, "host/sneaky");
                assert_eq!(namespace, "host/");
            }
            other => panic!("expected ReservedNamespace, got {other:?}"),
        }
    }

    #[test]
    fn output_branch_rejects_reserved_runs_namespace() {
        let err = RunSpec::from_json(
            r#"{"adapter":"black-box","cmd":["x"],"output-branch":"runs/forged"}"#,
        )
        .unwrap_err();
        match err {
            RunSpecError::ReservedNamespace { name, namespace } => {
                assert_eq!(name, "runs/forged");
                assert_eq!(namespace, "runs/");
            }
            other => panic!("expected ReservedNamespace, got {other:?}"),
        }
    }

    #[test]
    fn output_branch_rejects_illegal_git_branch_names() {
        // A representative cross-section of the git check-ref-format rules.
        for bad in [
            "",            // empty
            "@",           // single @ is reserved
            "HEAD",        // reserved name
            "-leading",    // git rejects leading dash
            "/leading",    // can't start with /
            "trailing/",   // can't end with /
            "double//slash",
            "trailing.",   // can't end with .
            "with..dots",
            "with@{brace",
            "with space",
            "with~tilde",
            "with^caret",
            "with:colon",
            "with?question",
            "with*star",
            "with[bracket",
            "with\\backslash",
            "with\x01control",
            ".dotcomp/start",
            "ok/.dotcomp",
            "comp.lock/end",
            "ok/end.lock",
        ] {
            let json = format!(
                r#"{{"adapter":"black-box","cmd":["x"],"output-branch":{}}}"#,
                serde_json::to_string(bad).unwrap()
            );
            let err = RunSpec::from_json(&json).unwrap_err();
            assert!(
                matches!(err, RunSpecError::IllegalBranchName(_)),
                "expected IllegalBranchName for {bad:?}, got {err:?}",
            );
        }
    }

    #[test]
    fn output_branch_accepts_typical_names() {
        for good in [
            "feature/x",
            "release/v1.0",
            "fix-123",
            "user/branch_name",
        ] {
            let json = format!(
                r#"{{"adapter":"black-box","cmd":["x"],"output-branch":{}}}"#,
                serde_json::to_string(good).unwrap()
            );
            let spec = RunSpec::from_json(&json).unwrap_or_else(|e| {
                panic!("expected {good:?} to be a legal name, got {e}")
            });
            assert_eq!(spec.output_branch.as_deref(), Some(good));
        }
    }
}
