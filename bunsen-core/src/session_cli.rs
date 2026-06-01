//! `bunsen-core session ...` CLI subcommand dispatch.
//!
//! Slice 11: exposes [`Session`] verbs to User Scripts via the CLI surface.
//! Each subcommand prints JSON on stdout (parseable from Python wrappers)
//! and human-readable errors on stderr, exiting non-zero on failure.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde_json::json;

use crate::branch_pool::ManifestEntry;
use crate::session::{ListFilter, Session, SessionError};

#[derive(Args)]
pub struct SessionArgs {
    #[arg(long)]
    pub as_user: Option<String>,
    #[command(subcommand)]
    pub command: SessionCommand,
}

#[derive(Subcommand)]
pub enum SessionCommand {
    Open(OpenArgs),
    Attach(AttachArgs),
    List(ListArgs),
    Show(ShowArgs),
    Close(CloseArgs),
    Discard(DiscardArgs),
    Label(LabelArgs),
    Purge(PurgeArgs),
}

#[derive(Args)]
pub struct OpenArgs {
    pub host_repo: PathBuf,
    #[arg(long)]
    pub mirror: Vec<String>,
    #[arg(long)]
    pub label: Option<String>,
}

#[derive(Args)]
pub struct AttachArgs {
    pub id: String,
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub with_tombstones: bool,
}

#[derive(Args)]
pub struct ShowArgs {
    pub id: String,
}

fn parse_manifest_entry(s: &str) -> Result<ManifestEntry, String> {
    parse_pair(s).map_err(|e| e.to_string())
}

#[derive(Args)]
pub struct CloseArgs {
    pub id: String,
    #[arg(long, value_parser = parse_manifest_entry, required = true)]
    pub pair: Vec<ManifestEntry>,
}

#[derive(Args)]
pub struct DiscardArgs {
    pub id: String,
}

#[derive(Args)]
pub struct LabelArgs {
    pub id: String,
    pub label: String,
}

#[derive(Args)]
pub struct PurgeArgs {
    pub id: String,
}

/// Entry point called from `main`. Returns the process exit code.
pub async fn run(args: SessionArgs) -> i32 {
    if let Err(msg) = crate::target_user::resolve_and_drop(args.as_user) {
        eprintln!("{msg}");
        return 1;
    }
    match args.command {
        SessionCommand::Open(a) => cmd_open(a).await,
        SessionCommand::Attach(a) => cmd_attach(a),
        SessionCommand::List(a) => cmd_list(a),
        SessionCommand::Show(a) => cmd_show(a),
        SessionCommand::Close(a) => cmd_close(a).await,
        SessionCommand::Discard(a) => cmd_discard(a),
        SessionCommand::Label(a) => cmd_label(a),
        SessionCommand::Purge(a) => cmd_purge(a),
    }
}

async fn cmd_open(args: OpenArgs) -> i32 {
    match Session::open(&args.host_repo, args.mirror, args.label).await {
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

fn cmd_attach(args: AttachArgs) -> i32 {
    match Session::attach(&args.id) {
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

fn cmd_list(args: ListArgs) -> i32 {
    let filter = ListFilter {
        include_closed: args.all,
        include_tombstones: args.with_tombstones,
    };
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

fn cmd_show(args: ShowArgs) -> i32 {
    match Session::attach(&args.id) {
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

async fn cmd_close(args: CloseArgs) -> i32 {
    let mut s = match Session::attach(&args.id) {
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
    match s.close(&args.pair).await {
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

fn cmd_discard(args: DiscardArgs) -> i32 {
    let id = args.id.clone();
    let s = match Session::attach(&args.id) {
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
    match s.discard() {
        Ok(()) => {
            println!("{}", json!({"id": id, "state": "discarded"}));
            0
        }
        Err(e) => {
            eprintln!("session discard failed: {e}");
            1
        }
    }
}

fn cmd_label(args: LabelArgs) -> i32 {
    let mut s = match Session::attach(&args.id) {
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
    match s.label(args.label) {
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

fn cmd_purge(args: PurgeArgs) -> i32 {
    let id = args.id.clone();
    let s = match Session::attach(&args.id) {
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
    match s.purge() {
        Ok(()) => {
            println!("{}", json!({"id": id, "state": "purged"}));
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
