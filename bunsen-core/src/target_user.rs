//! Target-user resolution: resolve the User Script user from invocation
//! context (CLI args, environment, uid/euid, passwd database) and perform
//! environment fix-up and optional privilege drop.
//!
//! The pure resolution core ([`resolve`]) takes all inputs as parameters
//! so it is exhaustively unit-testable without root.

use std::path::{Path, PathBuf};

// ── Passwd entry (minimal subset) ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PasswdEntry {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}

// ── Resolution inputs ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ResolutionInputs {
    pub as_user: Option<String>,
    pub euid: u32,
    pub ruid: u32,
    pub sudo_uid: Option<u32>,
    pub sudo_gid: Option<u32>,
    pub sudo_user: Option<String>,
}

// ── Resolution outcome ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResolvedUser {
    pub uid: u32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub supplementary_groups: Vec<u32>,
}

#[derive(Debug, Clone)]
pub enum ResolutionOutcome {
    Drop(ResolvedUser),
    NoDrop,
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ResolutionError {
    RootWithoutContext,
    DropToRoot { source: String },
    HomeMissing { home: PathBuf },
    UserNotFound { query: String },
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootWithoutContext => write!(
                f,
                "bunsen-core is running as root but cannot determine which user to \
                 drop to. Either:\n  \
                 • run via sudo (e.g. `sudo python my_script.py`), or\n  \
                 • pass --as-user <name|uid> explicitly"
            ),
            Self::DropToRoot { source } => write!(
                f,
                "resolved target user is root (uid 0) via {source} — \
                 dropping to root is not permitted"
            ),
            Self::HomeMissing { home } => write!(
                f,
                "resolved user's home directory {} does not exist",
                home.display()
            ),
            Self::UserNotFound { query } => {
                write!(f, "user {query:?} not found in the password database")
            }
        }
    }
}

impl std::error::Error for ResolutionError {}

// ── System context trait (for testability) ───────────────────────────────────

pub trait SystemContext {
    fn lookup_user_by_uid(&self, uid: u32) -> Option<PasswdEntry>;
    fn lookup_user_by_name(&self, name: &str) -> Option<PasswdEntry>;
    fn get_supplementary_groups(&self, name: &str, primary_gid: u32) -> Vec<u32>;
    fn home_exists(&self, path: &Path) -> bool;
}

// ── Pure resolution core ─────────────────────────────────────────────────────

pub fn resolve(
    inputs: &ResolutionInputs,
    ctx: &dyn SystemContext,
) -> Result<ResolutionOutcome, ResolutionError> {
    // Branch 4: effective-uid non-zero → no drop (today's dev path).
    if inputs.euid != 0 {
        return Ok(ResolutionOutcome::NoDrop);
    }

    // We are root. Determine which user to drop to.

    // Branch 1: explicit --as-user <name|uid>.
    if let Some(ref as_user) = inputs.as_user {
        let entry = if let Ok(uid) = as_user.parse::<u32>() {
            ctx.lookup_user_by_uid(uid)
        } else {
            ctx.lookup_user_by_name(as_user)
        };
        let entry = entry.ok_or_else(|| ResolutionError::UserNotFound {
            query: as_user.clone(),
        })?;
        return finalize(entry, None, ctx);
    }

    // Branch 2: SUDO_UID / SUDO_GID / SUDO_USER.
    if let Some(sudo_uid) = inputs.sudo_uid {
        let entry = if let Some(ref sudo_user) = inputs.sudo_user {
            ctx.lookup_user_by_name(sudo_user)
        } else {
            ctx.lookup_user_by_uid(sudo_uid)
        };
        let entry = entry.ok_or_else(|| ResolutionError::UserNotFound {
            query: inputs
                .sudo_user
                .clone()
                .unwrap_or_else(|| sudo_uid.to_string()),
        })?;
        return finalize(entry, inputs.sudo_gid, ctx);
    }

    // Branch 3: euid == 0 but ruid != 0 → setuid/file-caps install.
    if inputs.ruid != 0 {
        let entry = ctx
            .lookup_user_by_uid(inputs.ruid)
            .ok_or_else(|| ResolutionError::UserNotFound {
                query: inputs.ruid.to_string(),
            })?;
        return finalize(entry, None, ctx);
    }

    // Branch 5: root with no context → fail closed.
    Err(ResolutionError::RootWithoutContext)
}

fn finalize(
    entry: PasswdEntry,
    override_gid: Option<u32>,
    ctx: &dyn SystemContext,
) -> Result<ResolutionOutcome, ResolutionError> {
    if entry.uid == 0 {
        return Err(ResolutionError::DropToRoot {
            source: entry.name.clone(),
        });
    }
    if !ctx.home_exists(&entry.home) {
        return Err(ResolutionError::HomeMissing {
            home: entry.home.clone(),
        });
    }
    let gid = override_gid.unwrap_or(entry.gid);
    let groups = ctx.get_supplementary_groups(&entry.name, gid);
    Ok(ResolutionOutcome::Drop(ResolvedUser {
        uid: entry.uid,
        gid,
        name: entry.name,
        home: entry.home,
        supplementary_groups: groups,
    }))
}

// ── Environment fix-up ───────────────────────────────────────────────────────

pub fn apply_env_fixup(user: &ResolvedUser) {
    std::env::set_var("HOME", &user.home);
    std::env::set_var("USER", &user.name);
    std::env::set_var("LOGNAME", &user.name);
    std::env::set_var(
        "XDG_DATA_HOME",
        user.home.join(".local").join("share"),
    );
    std::env::set_var("XDG_CACHE_HOME", user.home.join(".cache"));
    std::env::set_var(
        "XDG_RUNTIME_DIR",
        format!("/run/user/{}", user.uid),
    );
}

// ── Privilege drop (Linux only) ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn drop_privileges(user: &ResolvedUser) -> Result<(), String> {
    use nix::unistd::{setresgid, setresuid, Gid, Uid};

    let cname = std::ffi::CString::new(user.name.clone())
        .map_err(|e| format!("invalid username for initgroups: {e}"))?;
    nix::unistd::initgroups(&cname, Gid::from_raw(user.gid))
        .map_err(|e| format!("initgroups failed: {e}"))?;
    setresgid(
        Gid::from_raw(user.gid),
        Gid::from_raw(user.gid),
        Gid::from_raw(user.gid),
    )
    .map_err(|e| format!("setresgid failed: {e}"))?;
    setresuid(
        Uid::from_raw(user.uid),
        Uid::from_raw(user.uid),
        Uid::from_raw(user.uid),
    )
    .map_err(|e| format!("setresuid failed: {e}"))?;
    Ok(())
}

// ── Real system context ──────────────────────────────────────────────────────

pub struct RealSystemContext;

impl SystemContext for RealSystemContext {
    fn lookup_user_by_uid(&self, uid: u32) -> Option<PasswdEntry> {
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| PasswdEntry {
                uid: u.uid.as_raw(),
                gid: u.gid.as_raw(),
                name: u.name,
                home: u.dir,
            })
    }

    fn lookup_user_by_name(&self, name: &str) -> Option<PasswdEntry> {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|u| PasswdEntry {
                uid: u.uid.as_raw(),
                gid: u.gid.as_raw(),
                name: u.name,
                home: u.dir,
            })
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fn get_supplementary_groups(&self, name: &str, primary_gid: u32) -> Vec<u32> {
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return vec![primary_gid],
        };
        nix::unistd::getgrouplist(&cname, nix::unistd::Gid::from_raw(primary_gid))
            .map(|gs| gs.into_iter().map(|g| g.as_raw()).collect())
            .unwrap_or_else(|_| vec![primary_gid])
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn get_supplementary_groups(&self, _name: &str, primary_gid: u32) -> Vec<u32> {
        vec![primary_gid]
    }

    fn home_exists(&self, path: &Path) -> bool {
        path.is_dir()
    }
}

// ── Live inputs from the running process ─────────────────────────────────────

pub fn inputs_from_process(as_user: Option<String>) -> ResolutionInputs {
    ResolutionInputs {
        as_user,
        euid: nix::unistd::geteuid().as_raw(),
        ruid: nix::unistd::getuid().as_raw(),
        sudo_uid: std::env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse().ok()),
        sudo_gid: std::env::var("SUDO_GID")
            .ok()
            .and_then(|s| s.parse().ok()),
        sudo_user: std::env::var("SUDO_USER").ok(),
    }
}

// ── Resolve and optionally drop (the one-call entry point for CLI) ───────────

pub fn resolve_and_drop(as_user: Option<String>) -> Result<ResolutionOutcome, String> {
    let inputs = inputs_from_process(as_user);
    let ctx = RealSystemContext;
    let outcome = resolve(&inputs, &ctx).map_err(|e| e.to_string())?;
    if let ResolutionOutcome::Drop(ref user) = outcome {
        apply_env_fixup(user);
        #[cfg(target_os = "linux")]
        drop_privileges(user)?;
    }
    Ok(outcome)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeContext {
        entries: Vec<PasswdEntry>,
    }

    impl FakeContext {
        fn new(entries: Vec<PasswdEntry>) -> Self {
            Self { entries }
        }

        fn with_alice() -> Self {
            Self::new(vec![PasswdEntry {
                uid: 1000,
                gid: 1000,
                name: "alice".into(),
                home: PathBuf::from("/home/alice"),
            }])
        }

        fn with_root_and_alice() -> Self {
            Self::new(vec![
                PasswdEntry {
                    uid: 0,
                    gid: 0,
                    name: "root".into(),
                    home: PathBuf::from("/root"),
                },
                PasswdEntry {
                    uid: 1000,
                    gid: 1000,
                    name: "alice".into(),
                    home: PathBuf::from("/home/alice"),
                },
            ])
        }
    }

    impl SystemContext for FakeContext {
        fn lookup_user_by_uid(&self, uid: u32) -> Option<PasswdEntry> {
            self.entries.iter().find(|e| e.uid == uid).cloned()
        }

        fn lookup_user_by_name(&self, name: &str) -> Option<PasswdEntry> {
            self.entries.iter().find(|e| e.name == name).cloned()
        }

        fn get_supplementary_groups(&self, _name: &str, primary_gid: u32) -> Vec<u32> {
            vec![primary_gid]
        }

        fn home_exists(&self, _path: &Path) -> bool {
            true
        }
    }

    struct NoHomeContext {
        inner: FakeContext,
    }

    impl SystemContext for NoHomeContext {
        fn lookup_user_by_uid(&self, uid: u32) -> Option<PasswdEntry> {
            self.inner.lookup_user_by_uid(uid)
        }
        fn lookup_user_by_name(&self, name: &str) -> Option<PasswdEntry> {
            self.inner.lookup_user_by_name(name)
        }
        fn get_supplementary_groups(&self, name: &str, gid: u32) -> Vec<u32> {
            self.inner.get_supplementary_groups(name, gid)
        }
        fn home_exists(&self, _path: &Path) -> bool {
            false
        }
    }

    // ── Branch 4: non-root → NoDrop ──────────────────────────────────────

    #[test]
    fn nonroot_user_returns_no_drop() {
        let inputs = ResolutionInputs {
            euid: 1000,
            ruid: 1000,
            ..Default::default()
        };
        let ctx = FakeContext::new(vec![]);
        let outcome = resolve(&inputs, &ctx).unwrap();
        assert!(matches!(outcome, ResolutionOutcome::NoDrop));
    }

    // ── Branch 1: --as-user by name ──────────────────────────────────────

    #[test]
    fn as_user_by_name_resolves_to_drop() {
        let inputs = ResolutionInputs {
            as_user: Some("alice".into()),
            euid: 0,
            ruid: 0,
            ..Default::default()
        };
        let ctx = FakeContext::with_alice();
        let outcome = resolve(&inputs, &ctx).unwrap();
        match outcome {
            ResolutionOutcome::Drop(u) => {
                assert_eq!(u.uid, 1000);
                assert_eq!(u.gid, 1000);
                assert_eq!(u.name, "alice");
                assert_eq!(u.home, PathBuf::from("/home/alice"));
            }
            ResolutionOutcome::NoDrop => panic!("expected Drop"),
        }
    }

    // ── Branch 1: --as-user by numeric uid ───────────────────────────────

    #[test]
    fn as_user_by_uid_resolves_to_drop() {
        let inputs = ResolutionInputs {
            as_user: Some("1000".into()),
            euid: 0,
            ruid: 0,
            ..Default::default()
        };
        let ctx = FakeContext::with_alice();
        let outcome = resolve(&inputs, &ctx).unwrap();
        match outcome {
            ResolutionOutcome::Drop(u) => {
                assert_eq!(u.uid, 1000);
                assert_eq!(u.name, "alice");
            }
            ResolutionOutcome::NoDrop => panic!("expected Drop"),
        }
    }

    // ── Branch 1: --as-user unknown user ─────────────────────────────────

    #[test]
    fn as_user_unknown_user_is_error() {
        let inputs = ResolutionInputs {
            as_user: Some("nobody_real".into()),
            euid: 0,
            ruid: 0,
            ..Default::default()
        };
        let ctx = FakeContext::new(vec![]);
        let err = resolve(&inputs, &ctx).unwrap_err();
        assert!(matches!(err, ResolutionError::UserNotFound { .. }));
    }

    // ── Branch 2: SUDO_UID/GID/USER ──────────────────────────────────────

    #[test]
    fn sudo_env_resolves_to_drop() {
        let inputs = ResolutionInputs {
            euid: 0,
            ruid: 0,
            sudo_uid: Some(1000),
            sudo_gid: Some(1000),
            sudo_user: Some("alice".into()),
            ..Default::default()
        };
        let ctx = FakeContext::with_alice();
        let outcome = resolve(&inputs, &ctx).unwrap();
        match outcome {
            ResolutionOutcome::Drop(u) => {
                assert_eq!(u.uid, 1000);
                assert_eq!(u.name, "alice");
            }
            ResolutionOutcome::NoDrop => panic!("expected Drop"),
        }
    }

    // ── Branch 2: SUDO_GID preferred over passwd primary gid ─────────────

    #[test]
    fn sudo_gid_preferred_over_passwd_gid() {
        let inputs = ResolutionInputs {
            euid: 0,
            ruid: 0,
            sudo_uid: Some(1000),
            sudo_gid: Some(2000),
            sudo_user: Some("alice".into()),
            ..Default::default()
        };
        let ctx = FakeContext::with_alice();
        let outcome = resolve(&inputs, &ctx).unwrap();
        match outcome {
            ResolutionOutcome::Drop(u) => {
                assert_eq!(u.gid, 2000, "SUDO_GID should override passwd gid");
            }
            ResolutionOutcome::NoDrop => panic!("expected Drop"),
        }
    }

    // ── Branch 2: SUDO_UID without SUDO_USER falls back to uid lookup ────

    #[test]
    fn sudo_uid_without_sudo_user_uses_uid_lookup() {
        let inputs = ResolutionInputs {
            euid: 0,
            ruid: 0,
            sudo_uid: Some(1000),
            sudo_gid: Some(1000),
            ..Default::default()
        };
        let ctx = FakeContext::with_alice();
        let outcome = resolve(&inputs, &ctx).unwrap();
        match outcome {
            ResolutionOutcome::Drop(u) => {
                assert_eq!(u.uid, 1000);
                assert_eq!(u.name, "alice");
            }
            ResolutionOutcome::NoDrop => panic!("expected Drop"),
        }
    }

    // ── Branch 3: setuid/file-caps (euid==0, ruid!=0) ────────────────────

    #[test]
    fn setuid_path_drops_to_real_uid() {
        let inputs = ResolutionInputs {
            euid: 0,
            ruid: 1000,
            ..Default::default()
        };
        let ctx = FakeContext::with_alice();
        let outcome = resolve(&inputs, &ctx).unwrap();
        match outcome {
            ResolutionOutcome::Drop(u) => {
                assert_eq!(u.uid, 1000);
                assert_eq!(u.name, "alice");
            }
            ResolutionOutcome::NoDrop => panic!("expected Drop"),
        }
    }

    // ── Branch 5: root without context → fail closed ─────────────────────

    #[test]
    fn root_without_context_fails_closed() {
        let inputs = ResolutionInputs {
            euid: 0,
            ruid: 0,
            ..Default::default()
        };
        let ctx = FakeContext::new(vec![]);
        let err = resolve(&inputs, &ctx).unwrap_err();
        assert!(matches!(err, ResolutionError::RootWithoutContext));
        let msg = err.to_string();
        assert!(msg.contains("sudo"), "error should mention sudo: {msg}");
        assert!(
            msg.contains("--as-user"),
            "error should mention --as-user: {msg}"
        );
    }

    // ── Validation: drop to root rejected ────────────────────────────────

    #[test]
    fn drop_to_root_is_rejected() {
        let inputs = ResolutionInputs {
            as_user: Some("root".into()),
            euid: 0,
            ruid: 0,
            ..Default::default()
        };
        let ctx = FakeContext::with_root_and_alice();
        let err = resolve(&inputs, &ctx).unwrap_err();
        assert!(matches!(err, ResolutionError::DropToRoot { .. }));
    }

    #[test]
    fn drop_to_uid_zero_is_rejected() {
        let inputs = ResolutionInputs {
            as_user: Some("0".into()),
            euid: 0,
            ruid: 0,
            ..Default::default()
        };
        let ctx = FakeContext::with_root_and_alice();
        let err = resolve(&inputs, &ctx).unwrap_err();
        assert!(matches!(err, ResolutionError::DropToRoot { .. }));
    }

    // ── Validation: missing home rejected ────────────────────────────────

    #[test]
    fn missing_home_is_rejected() {
        let inputs = ResolutionInputs {
            as_user: Some("alice".into()),
            euid: 0,
            ruid: 0,
            ..Default::default()
        };
        let ctx = NoHomeContext {
            inner: FakeContext::with_alice(),
        };
        let err = resolve(&inputs, &ctx).unwrap_err();
        assert!(matches!(err, ResolutionError::HomeMissing { .. }));
    }

    // ── --as-user takes priority over SUDO_* ─────────────────────────────

    #[test]
    fn as_user_takes_priority_over_sudo() {
        let ctx = FakeContext::new(vec![
            PasswdEntry {
                uid: 1000,
                gid: 1000,
                name: "alice".into(),
                home: PathBuf::from("/home/alice"),
            },
            PasswdEntry {
                uid: 2000,
                gid: 2000,
                name: "bob".into(),
                home: PathBuf::from("/home/bob"),
            },
        ]);
        let inputs = ResolutionInputs {
            as_user: Some("bob".into()),
            euid: 0,
            ruid: 0,
            sudo_uid: Some(1000),
            sudo_user: Some("alice".into()),
            ..Default::default()
        };
        let outcome = resolve(&inputs, &ctx).unwrap();
        match outcome {
            ResolutionOutcome::Drop(u) => {
                assert_eq!(u.name, "bob", "--as-user should override SUDO_USER");
            }
            ResolutionOutcome::NoDrop => panic!("expected Drop"),
        }
    }

    // ── Environment fix-up ───────────────────────────────────────────────

    #[test]
    fn env_fixup_sets_correct_vars() {
        let user = ResolvedUser {
            uid: 1000,
            gid: 1000,
            name: "alice".into(),
            home: PathBuf::from("/home/alice"),
            supplementary_groups: vec![1000],
        };
        apply_env_fixup(&user);
        assert_eq!(std::env::var("HOME").unwrap(), "/home/alice");
        assert_eq!(std::env::var("USER").unwrap(), "alice");
        assert_eq!(std::env::var("LOGNAME").unwrap(), "alice");
        assert_eq!(
            std::env::var("XDG_DATA_HOME").unwrap(),
            "/home/alice/.local/share"
        );
        assert_eq!(
            std::env::var("XDG_CACHE_HOME").unwrap(),
            "/home/alice/.cache"
        );
        assert_eq!(std::env::var("XDG_RUNTIME_DIR").unwrap(), "/run/user/1000");
    }
}
