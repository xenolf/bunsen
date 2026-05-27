//! `bunsen-core session ...` CLI subcommand dispatch.
//!
//! Slice 11: exposes [`Session`] verbs to User Scripts via the CLI surface.
//! Each subcommand prints JSON on stdout (parseable from Python wrappers)
//! and human-readable errors on stderr, exiting non-zero on failure.

use std::path::PathBuf;

use serde_json::json;

use crate::branch_pool::ManifestEntry;
use crate::session::{ListFilter, Session, SessionError};

/// Entry point. `argv` is `&args[2..]` — i.e. everything after the
/// `session` literal. Returns the process exit code.
pub async fn run(argv: &[String]) -> i32 {
    let Some((sub, rest)) = argv.split_first() else {
        eprintln!("{}", usage());
        return 2;
    };
    match sub.as_str() {
        "open" => cmd_open(rest).await,
        "attach" => cmd_attach(rest),
        "list" => cmd_list(rest),
        "show" => cmd_show(rest),
        "close" => cmd_close(rest).await,
        "discard" => cmd_discard(rest),
        "label" => cmd_label(rest),
        "purge" => cmd_purge(rest),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            0
        }
        other => {
            eprintln!("unknown session subcommand: {other:?}\n\n{}", usage());
            2
        }
    }
}

fn usage() -> &'static str {
    "usage: bunsen-core session <subcommand> [...]\n\
     \n\
     subcommands:\n\
       open <host-repo> [--mirror <ref>]... [--label <label>]\n\
       attach <id>\n\
       list [--all] [--with-tombstones]\n\
       show <id>\n\
       close <id> --pair <pool>:<host>[:force] [--pair ...]\n\
       discard <id>\n\
       label <id> <label>\n\
       purge <id>"
}

async fn cmd_open(argv: &[String]) -> i32 {
    let mut host_repo: Option<PathBuf> = None;
    let mut mirror: Vec<String> = Vec::new();
    let mut label: Option<String> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--mirror" if i + 1 < argv.len() => {
                mirror.push(argv[i + 1].clone());
                i += 2;
            }
            "--label" if i + 1 < argv.len() => {
                label = Some(argv[i + 1].clone());
                i += 2;
            }
            other if other.starts_with("--") => {
                eprintln!("unknown flag for `session open`: {other}");
                return 2;
            }
            other => {
                if host_repo.is_some() {
                    eprintln!("unexpected positional arg: {other}");
                    return 2;
                }
                host_repo = Some(PathBuf::from(other));
                i += 1;
            }
        }
    }
    let Some(host_repo) = host_repo else {
        eprintln!("usage: bunsen-core session open <host-repo> [--mirror <ref>]... [--label <label>]");
        return 2;
    };
    match Session::open(&host_repo, mirror, label).await {
        Ok(s) => {
            println!("{}", json!({"id": s.id(), "path": s.path().display().to_string()}));
            0
        }
        Err(e) => {
            eprintln!("session open failed: {e}");
            1
        }
    }
}

fn cmd_attach(argv: &[String]) -> i32 {
    let Some(id) = argv.first() else {
        eprintln!("usage: bunsen-core session attach <id>");
        return 2;
    };
    match Session::attach(id) {
        Ok(s) => {
            println!("{}", summary_json(&s));
            0
        }
        Err(SessionError::NotFound { id }) => {
            eprintln!("session not found: {id}");
            1
        }
        Err(e) => {
            eprintln!("session attach failed: {e}");
            1
        }
    }
}

fn cmd_list(argv: &[String]) -> i32 {
    let mut filter = ListFilter::default();
    for a in argv {
        match a.as_str() {
            "--all" => filter.include_closed = true,
            "--with-tombstones" => filter.include_tombstones = true,
            other => {
                eprintln!("unknown flag for `session list`: {other}");
                return 2;
            }
        }
    }
    match Session::list(filter) {
        Ok(items) => {
            let arr: Vec<serde_json::Value> = items
                .into_iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "state": state_str(s.state),
                        "host_repo": s.host_repo.display().to_string(),
                        "labels": s.labels,
                        "created_at": s.created_at,
                    })
                })
                .collect();
            println!("{}", serde_json::Value::Array(arr));
            0
        }
        Err(e) => {
            eprintln!("session list failed: {e}");
            1
        }
    }
}

fn cmd_show(argv: &[String]) -> i32 {
    let Some(id) = argv.first() else {
        eprintln!("usage: bunsen-core session show <id>");
        return 2;
    };
    match Session::attach(id) {
        Ok(s) => {
            println!("{}", summary_json(&s));
            0
        }
        Err(SessionError::NotFound { id }) => {
            eprintln!("session not found: {id}");
            1
        }
        Err(e) => {
            eprintln!("session show failed: {e}");
            1
        }
    }
}

async fn cmd_close(argv: &[String]) -> i32 {
    let mut id: Option<String> = None;
    let mut pairs: Vec<ManifestEntry> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--pair" if i + 1 < argv.len() => {
                match parse_pair(&argv[i + 1]) {
                    Ok(e) => pairs.push(e),
                    Err(msg) => {
                        eprintln!("invalid --pair value {:?}: {msg}", &argv[i + 1]);
                        return 2;
                    }
                }
                i += 2;
            }
            other if other.starts_with("--") => {
                eprintln!("unknown flag for `session close`: {other}");
                return 2;
            }
            other => {
                if id.is_some() {
                    eprintln!("unexpected positional arg: {other}");
                    return 2;
                }
                id = Some(other.to_string());
                i += 1;
            }
        }
    }
    let Some(id) = id else {
        eprintln!("usage: bunsen-core session close <id> --pair <pool>:<host>[:force] [--pair ...]");
        return 2;
    };
    if pairs.is_empty() {
        eprintln!("session close requires at least one --pair");
        return 2;
    }
    let mut s = match Session::attach(&id) {
        Ok(s) => s,
        Err(SessionError::NotFound { id }) => {
            eprintln!("session not found: {id}");
            return 1;
        }
        Err(e) => {
            eprintln!("session close failed: {e}");
            return 1;
        }
    };
    match s.close(&pairs).await {
        Ok(()) => {
            println!("{}", json!({"id": s.id(), "state": "closed"}));
            0
        }
        Err(e) => {
            eprintln!("session close failed: {e}");
            1
        }
    }
}

fn cmd_discard(argv: &[String]) -> i32 {
    let Some(id) = argv.first() else {
        eprintln!("usage: bunsen-core session discard <id>");
        return 2;
    };
    let s = match Session::attach(id) {
        Ok(s) => s,
        Err(SessionError::NotFound { id }) => {
            eprintln!("session not found: {id}");
            return 1;
        }
        Err(e) => {
            eprintln!("session discard failed: {e}");
            return 1;
        }
    };
    let owned = id.clone();
    match s.discard() {
        Ok(()) => {
            println!("{}", json!({"id": owned, "state": "discarded"}));
            0
        }
        Err(e) => {
            eprintln!("session discard failed: {e}");
            1
        }
    }
}

fn cmd_label(argv: &[String]) -> i32 {
    if argv.len() < 2 {
        eprintln!("usage: bunsen-core session label <id> <label>");
        return 2;
    }
    let id = &argv[0];
    let label = &argv[1];
    let mut s = match Session::attach(id) {
        Ok(s) => s,
        Err(SessionError::NotFound { id }) => {
            eprintln!("session not found: {id}");
            return 1;
        }
        Err(e) => {
            eprintln!("session label failed: {e}");
            return 1;
        }
    };
    match s.label(label.clone()) {
        Ok(()) => {
            println!("{}", json!({"id": s.id(), "labels": s.labels()}));
            0
        }
        Err(e) => {
            eprintln!("session label failed: {e}");
            1
        }
    }
}

fn cmd_purge(argv: &[String]) -> i32 {
    let Some(id) = argv.first() else {
        eprintln!("usage: bunsen-core session purge <id>");
        return 2;
    };
    let s = match Session::attach(id) {
        Ok(s) => s,
        Err(SessionError::NotFound { id }) => {
            eprintln!("session not found: {id}");
            return 1;
        }
        Err(e) => {
            eprintln!("session purge failed: {e}");
            return 1;
        }
    };
    let owned = id.clone();
    match s.purge() {
        Ok(()) => {
            println!("{}", json!({"id": owned, "state": "purged"}));
            0
        }
        Err(e) => {
            eprintln!("session purge failed: {e}");
            1
        }
    }
}

/// Parse a `--pair pool:host[:force]` argument into a [`ManifestEntry`].
///
/// `force` is the literal string `force` in the third position. Any other
/// trailing component is rejected so a stray typo doesn't silently disable
/// the FF check.
pub(crate) fn parse_pair(s: &str) -> Result<ManifestEntry, &'static str> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 {
        return Err("expected pool:host[:force]");
    }
    if parts[0].is_empty() || parts[1].is_empty() {
        return Err("pool and host refs must be non-empty");
    }
    let force = if parts.len() == 3 {
        if parts[2] != "force" {
            return Err("third component must be the literal 'force'");
        }
        true
    } else {
        false
    };
    Ok(ManifestEntry {
        pool_ref: parts[0].into(),
        host_ref: parts[1].into(),
        force,
    })
}

fn state_str(state: crate::session::SessionState) -> &'static str {
    use crate::session::SessionState::*;
    match state {
        Open => "open",
        Closing => "closing",
        Closed => "closed",
        FailedToClose => "failed_to_close",
        Discarded => "discarded",
    }
}

fn summary_json(s: &Session) -> serde_json::Value {
    json!({
        "id": s.id(),
        "state": state_str(s.state()),
        "host_repo": s.host_repo().display().to_string(),
        "mirror_refs": s.mirror_refs(),
        "labels": s.labels(),
        "path": s.path().display().to_string(),
        "last_close_failure": s.last_close_failure(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pair_ff_default() {
        let e = parse_pair("feature/x:release/x").unwrap();
        assert_eq!(e.pool_ref, "feature/x");
        assert_eq!(e.host_ref, "release/x");
        assert!(!e.force);
    }

    #[test]
    fn parse_pair_with_force() {
        let e = parse_pair("feature/x:release/x:force").unwrap();
        assert!(e.force);
    }

    #[test]
    fn parse_pair_unknown_third_is_rejected() {
        let err = parse_pair("a:b:wat").unwrap_err();
        assert!(err.contains("force"));
    }

    #[test]
    fn parse_pair_missing_host_rejected() {
        assert!(parse_pair("only-one").is_err());
    }

    #[test]
    fn parse_pair_empty_components_rejected() {
        assert!(parse_pair(":host").is_err());
        assert!(parse_pair("pool:").is_err());
    }

    #[test]
    fn state_str_round_trip() {
        use crate::session::SessionState::*;
        assert_eq!(state_str(Open), "open");
        assert_eq!(state_str(Closing), "closing");
        assert_eq!(state_str(Closed), "closed");
        assert_eq!(state_str(FailedToClose), "failed_to_close");
        assert_eq!(state_str(Discarded), "discarded");
    }
}
