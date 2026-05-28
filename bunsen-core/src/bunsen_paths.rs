//! Single source of truth for bunsen data and cache directory paths.
//!
//! Replaces the four duplicated `xdg_data_home()`/`cache_dir()` resolution
//! sites (main.rs, session.rs, kernel.rs, oci_cache.rs) with one module.
//!
//! When the target-user resolution triggers an environment fix-up (the
//! `sudo`/privilege-drop path), the `HOME`/`XDG_DATA_HOME`/`XDG_CACHE_HOME`
//! env vars are overwritten from the resolved account's passwd entry before
//! any of these functions are called. On the non-root dev path (no fix-up),
//! the functions read the current environment as-is, preserving today's
//! behaviour.

use std::path::PathBuf;

pub fn data_home() -> PathBuf {
    if let Ok(v) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(v)
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
            .join(".local")
            .join("share")
    }
}

pub fn cache_home() -> PathBuf {
    if let Ok(v) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(v)
    } else {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
            .join(".cache")
    }
}

pub fn sessions_root() -> PathBuf {
    data_home().join("bunsen").join("sessions")
}

pub fn kernel_cache() -> PathBuf {
    cache_home().join("bunsen").join("kernel")
}

pub fn rootfs_cache() -> PathBuf {
    cache_home().join("bunsen").join("rootfs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_root_ends_with_expected_suffix() {
        let p = sessions_root();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("bunsen/sessions"),
            "expected bunsen/sessions suffix, got {s}"
        );
    }

    #[test]
    fn kernel_cache_ends_with_expected_suffix() {
        let p = kernel_cache();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("bunsen/kernel"),
            "expected bunsen/kernel suffix, got {s}"
        );
    }

    #[test]
    fn rootfs_cache_ends_with_expected_suffix() {
        let p = rootfs_cache();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("bunsen/rootfs"),
            "expected bunsen/rootfs suffix, got {s}"
        );
    }
}
