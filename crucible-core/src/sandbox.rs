use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::run_spec::RunSpec;

// ─── vsock port assignments ────────────────────────────────────────────────
/// Guest→host: raw bytes from the agent's stdout.
pub const VSOCK_STDOUT_PORT: u32 = 5001;
/// Guest→host: raw bytes from the agent's stderr.
pub const VSOCK_STDERR_PORT: u32 = 5002;
/// Host→guest: line-delimited JSON control commands.
pub const VSOCK_CONTROL_PORT: u32 = 5003;

// ─── Firecracker API request bodies ───────────────────────────────────────
// These structs are compiled on all platforms so serialization tests run on macOS.

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct FcMachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub smt: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct FcBootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct FcDriveConfig {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct FcNetworkInterface {
    pub iface_id: String,
    pub guest_mac: String,
    pub host_dev_name: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct FcVsockConfig {
    pub vsock_id: String,
    pub guest_cid: u32,
    pub uds_path: String,
}

#[derive(Debug, Serialize)]
pub struct FcActionStart {
    pub action_type: &'static str,
}

impl Default for FcActionStart {
    fn default() -> Self {
        FcActionStart { action_type: "InstanceStart" }
    }
}

// ─── Host-side sandbox configuration ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    /// Host directory to expose as /workspace inside the guest.
    pub workspace_host_path: PathBuf,
    pub spec_json: String,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub workspace_disk_mib: u32,
    pub run_id: String,
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/// Build the kernel boot args string, embedding the spec as base64.
///
/// When the host process has `CRUCIBLE_INIT_DEBUG=1` in its environment, append
/// `crucible_init_debug=1` so the guest init writes a per-run init.log to
/// /workspace. Off by default — the diagnostics are noisy and meant for
/// development.
pub fn build_boot_args(spec_json: &str) -> String {
    let encoded = STANDARD.encode(spec_json.as_bytes());
    let debug = if std::env::var("CRUCIBLE_INIT_DEBUG").as_deref() == Ok("1") {
        " crucible_init_debug=1"
    } else {
        ""
    };
    format!(
        "console=ttyS0 reboot=k panic=1 pci=off nomodule \
         root=/dev/vda rw init=/sbin/crucible-init \
         crucible_spec={encoded}{debug}"
    )
}

/// Build the spec JSON to embed in the VM's kernel boot args.
///
/// The guest init understands `cmd`, `env`, and `stop-grace-seconds`.
/// Secrets are merged into `env` so the init exports them as env vars on the agent.
/// The top-level `secrets` field is deliberately omitted.
///
/// When `proxy_addr` is `Some(addr)`, the L7 egress proxy URL is injected as
/// `HTTP_PROXY` / `HTTPS_PROXY` (and lowercase variants) so well-behaved
/// agents route HTTP(S) through the proxy. The proxy URL overrides any
/// user-supplied value — the proxy is the security boundary, not a hint.
/// `NO_PROXY` is set to `localhost,127.0.0.1` only when the user has not
/// supplied their own value.
pub fn build_sandbox_spec_json(spec: &RunSpec, proxy_addr: Option<SocketAddr>) -> String {
    let mut env = spec.env.clone();
    // Secrets overlay env (secrets win on collision).
    for (k, v) in &spec.secrets {
        env.insert(k.clone(), v.clone());
    }
    if let Some(addr) = proxy_addr {
        let url = format!("http://{addr}");
        // Force the proxy variables — the agent must not be able to opt out.
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            env.insert(k.to_string(), url.clone());
        }
        // Localhost bypass is a usability default; let users override.
        for k in ["NO_PROXY", "no_proxy"] {
            env.entry(k.to_string())
                .or_insert_with(|| "localhost,127.0.0.1".to_string());
        }
    }
    let obj = serde_json::json!({
        "cmd": spec.cmd,
        "env": env,
        "stop-grace-seconds": spec.stop_grace_seconds,
    });
    serde_json::to_string(&obj).expect("spec serialization is infallible")
}

/// Derive the per-port vsock UDS path Firecracker uses for guest→host connections.
/// Firecracker appends `_{port}` to the base vsock UDS path.
pub fn vsock_socket_path(base: &Path, port: u32) -> PathBuf {
    let name = format!(
        "{}_{port}",
        base.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vsock.sock")
    );
    base.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cycle 2: Firecracker config serialization ──────────────────────────

    #[test]
    fn machine_config_serializes_correctly() {
        let cfg = FcMachineConfig { vcpu_count: 2, mem_size_mib: 4096, smt: false };
        let v = serde_json::to_value(&cfg).unwrap();
        assert_eq!(v["vcpu_count"], 2);
        assert_eq!(v["mem_size_mib"], 4096);
        assert_eq!(v["smt"], false);
    }

    #[test]
    fn drive_config_root_device_flag() {
        let d = FcDriveConfig {
            drive_id: "rootfs".to_string(),
            path_on_host: "/tmp/rootfs.ext4".to_string(),
            is_root_device: true,
            is_read_only: true,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["drive_id"], "rootfs");
        assert_eq!(v["is_root_device"], true);
        assert_eq!(v["is_read_only"], true);
    }

    #[test]
    fn vsock_config_serializes_correctly() {
        let vc = FcVsockConfig {
            vsock_id: "vsock0".to_string(),
            guest_cid: 3,
            uds_path: "/tmp/crucible-vsock.sock".to_string(),
        };
        let v = serde_json::to_value(&vc).unwrap();
        assert_eq!(v["guest_cid"], 3);
        assert_eq!(v["uds_path"], "/tmp/crucible-vsock.sock");
    }

    // ── Cycle 3: boot args builder ─────────────────────────────────────────

    #[test]
    fn boot_args_contain_init_path() {
        let args = build_boot_args(r#"{"cmd":["echo"]}"#);
        assert!(args.contains("init=/sbin/crucible-init"));
    }

    #[test]
    fn boot_args_contain_encoded_spec_roundtrips() {
        let spec = r#"{"adapter":"black-box","cmd":["echo","hi"]}"#;
        let args = build_boot_args(spec);
        let token = args.split_whitespace()
            .find(|t| t.starts_with("crucible_spec="))
            .expect("crucible_spec token missing");
        let encoded = token.strip_prefix("crucible_spec=").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), spec);
    }

    // ── Cycle 5: sandbox spec JSON ────────────────────────────────────────

    #[test]
    fn build_sandbox_spec_json_merges_secrets_into_env() {
        let spec = crate::run_spec::RunSpec::from_json(r#"{
            "adapter": "black-box",
            "cmd": ["echo"],
            "env": {"A": "1"},
            "secrets": {"SECRET": "sk-xxx"}
        }"#).unwrap();
        let json_str = build_sandbox_spec_json(&spec, None);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["env"]["A"], "1");
        assert_eq!(v["env"]["SECRET"], "sk-xxx");
        assert!(v.get("secrets").is_none(), "secrets must not appear as a top-level field");
    }

    #[test]
    fn build_sandbox_spec_json_stop_grace_seconds() {
        let spec = crate::run_spec::RunSpec::from_json(r#"{
            "adapter": "black-box",
            "cmd": ["true"],
            "stop-grace-seconds": 42
        }"#).unwrap();
        let v: serde_json::Value = serde_json::from_str(&build_sandbox_spec_json(&spec, None)).unwrap();
        assert_eq!(v["stop-grace-seconds"], 42);
    }

    #[test]
    fn build_sandbox_spec_json_env_key_wins_over_secret_on_collision() {
        let spec = crate::run_spec::RunSpec::from_json(r#"{
            "adapter": "black-box",
            "cmd": ["true"],
            "env": {"K": "from-env"},
            "secrets": {"K": "from-secret"}
        }"#).unwrap();
        let v: serde_json::Value = serde_json::from_str(&build_sandbox_spec_json(&spec, None)).unwrap();
        // secrets overlay env: secret value wins (it's additive from secret store)
        assert_eq!(v["env"]["K"], "from-secret");
    }

    // ── Cycle 10d: HTTP_PROXY / HTTPS_PROXY env injection ──────────────────

    #[test]
    fn build_sandbox_spec_json_no_proxy_addr_leaves_proxy_env_unset() {
        let spec = crate::run_spec::RunSpec::from_json(r#"{
            "adapter": "black-box",
            "cmd": ["true"]
        }"#).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&build_sandbox_spec_json(&spec, None)).unwrap();
        assert!(v["env"].get("HTTP_PROXY").is_none());
        assert!(v["env"].get("HTTPS_PROXY").is_none());
        assert!(v["env"].get("NO_PROXY").is_none());
    }

    #[test]
    fn build_sandbox_spec_json_with_proxy_injects_http_and_https_proxy() {
        let spec = crate::run_spec::RunSpec::from_json(r#"{
            "adapter": "black-box",
            "cmd": ["true"]
        }"#).unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&build_sandbox_spec_json(&spec, Some(addr))).unwrap();
        assert_eq!(v["env"]["HTTP_PROXY"], "http://127.0.0.1:8080");
        assert_eq!(v["env"]["HTTPS_PROXY"], "http://127.0.0.1:8080");
        assert_eq!(v["env"]["http_proxy"], "http://127.0.0.1:8080");
        assert_eq!(v["env"]["https_proxy"], "http://127.0.0.1:8080");
    }

    #[test]
    fn build_sandbox_spec_json_with_proxy_overrides_user_supplied_proxy_env() {
        // The proxy is the security boundary; an agent (or user) cannot opt
        // out by setting HTTPS_PROXY in the spec env.
        let spec = crate::run_spec::RunSpec::from_json(r#"{
            "adapter": "black-box",
            "cmd": ["true"],
            "env": {"HTTPS_PROXY": "http://evil.example:1"}
        }"#).unwrap();
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&build_sandbox_spec_json(&spec, Some(addr))).unwrap();
        assert_eq!(v["env"]["HTTPS_PROXY"], "http://127.0.0.1:9000");
    }

    #[test]
    fn build_sandbox_spec_json_with_proxy_sets_default_no_proxy_when_unset() {
        let spec = crate::run_spec::RunSpec::from_json(r#"{
            "adapter": "black-box",
            "cmd": ["true"]
        }"#).unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&build_sandbox_spec_json(&spec, Some(addr))).unwrap();
        assert_eq!(v["env"]["NO_PROXY"], "localhost,127.0.0.1");
        assert_eq!(v["env"]["no_proxy"], "localhost,127.0.0.1");
    }

    #[test]
    fn build_sandbox_spec_json_with_proxy_preserves_user_no_proxy() {
        // NO_PROXY is a usability hint, not a security control — the user
        // can extend it (e.g. add their internal mirror).
        let spec = crate::run_spec::RunSpec::from_json(r#"{
            "adapter": "black-box",
            "cmd": ["true"],
            "env": {"NO_PROXY": "localhost,internal.example"}
        }"#).unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&build_sandbox_spec_json(&spec, Some(addr))).unwrap();
        assert_eq!(v["env"]["NO_PROXY"], "localhost,internal.example");
    }

    // ── Cycle 4: vsock path derivation ────────────────────────────────────

    #[test]
    fn vsock_port_constants() {
        assert_eq!(VSOCK_STDOUT_PORT, 5001);
        assert_eq!(VSOCK_STDERR_PORT, 5002);
        assert_eq!(VSOCK_CONTROL_PORT, 5003);
    }

    #[test]
    fn vsock_socket_path_appends_port() {
        let base = Path::new("/tmp/crucible-vsock.sock");
        assert_eq!(
            vsock_socket_path(base, 5001),
            PathBuf::from("/tmp/crucible-vsock.sock_5001")
        );
        assert_eq!(
            vsock_socket_path(base, 5002),
            PathBuf::from("/tmp/crucible-vsock.sock_5002")
        );
    }
}
