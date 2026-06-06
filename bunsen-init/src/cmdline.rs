#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// True if the kernel cmdline contains `bunsen_init_debug=1`.
pub fn debug_enabled(cmdline: &str) -> bool {
    cmdline.split_whitespace().any(|t| t == "bunsen_init_debug=1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_enabled_detects_token() {
        assert!(debug_enabled("console=ttyS0 bunsen_init_debug=1 rw"));
        assert!(debug_enabled("bunsen_init_debug=1"));
    }

    #[test]
    fn debug_enabled_false_when_absent_or_other_value() {
        assert!(!debug_enabled("console=ttyS0 rw"));
        assert!(!debug_enabled("bunsen_init_debug=0"));
        assert!(!debug_enabled("bunsen_init_debug=true"));
    }
}
