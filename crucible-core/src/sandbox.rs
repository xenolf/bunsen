use std::path::{Path, PathBuf};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

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
pub fn build_boot_args(spec_json: &str) -> String {
    let encoded = STANDARD.encode(spec_json.as_bytes());
    format!(
        "console=ttyS0 reboot=k panic=1 pci=off nomodule \
         root=/dev/vda rw init=/sbin/crucible-init \
         crucible_spec={encoded}"
    )
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
