#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use base64::{Engine, engine::general_purpose::STANDARD};

/// Extract and base64-decode the `crucible_spec=` token from the kernel cmdline.
pub fn extract_spec(cmdline: &str) -> Option<String> {
    for token in cmdline.split_whitespace() {
        if let Some(encoded) = token.strip_prefix("crucible_spec=") {
            let bytes = STANDARD.decode(encoded).ok()?;
            return String::from_utf8(bytes).ok();
        }
    }
    None
}

/// True if the kernel cmdline contains `crucible_init_debug=1`.
pub fn debug_enabled(cmdline: &str) -> bool {
    cmdline.split_whitespace().any(|t| t == "crucible_init_debug=1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_spec_decodes_base64_token() {
        let spec = r#"{"adapter":"black-box","cmd":["echo","hello"]}"#;
        let encoded = STANDARD.encode(spec);
        let cmdline = format!("console=ttyS0 root=/dev/vda crucible_spec={encoded} rw");
        assert_eq!(extract_spec(&cmdline).as_deref(), Some(spec));
    }

    #[test]
    fn extract_spec_returns_none_when_absent() {
        assert!(extract_spec("console=ttyS0 root=/dev/vda rw").is_none());
    }

    #[test]
    fn extract_spec_handles_first_token() {
        let spec = r#"{"cmd":["sh"]}"#;
        let encoded = STANDARD.encode(spec);
        let cmdline = format!("crucible_spec={encoded}");
        assert_eq!(extract_spec(&cmdline).as_deref(), Some(spec));
    }

    #[test]
    fn extract_spec_ignores_invalid_base64() {
        assert!(extract_spec("crucible_spec=!!!invalid!!!").is_none());
    }

    #[test]
    fn debug_enabled_detects_token() {
        assert!(debug_enabled("console=ttyS0 crucible_init_debug=1 rw"));
        assert!(debug_enabled("crucible_init_debug=1"));
    }

    #[test]
    fn debug_enabled_false_when_absent_or_other_value() {
        assert!(!debug_enabled("console=ttyS0 rw"));
        assert!(!debug_enabled("crucible_init_debug=0"));
        assert!(!debug_enabled("crucible_init_debug=true"));
    }
}
