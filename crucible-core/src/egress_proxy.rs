//! L7 forward proxy for Sandbox egress.
//!
//! Per ADR-0005 the proxy is the single point of egress visible to a Sandbox:
//! L3 nftables (a later slice) drops everything except traffic to this proxy,
//! and the proxy enforces an exact-FQDN allowlist composed by [`EgressPolicy`].
//!
//! Slice 10b lands the host-side data plane only:
//!   - HTTPS `CONNECT` parsing.
//!   - Allow / deny decision against [`EgressPolicy`].
//!   - On allow: open the upstream socket, return `200 Connection
//!     Established`, and splice bytes both ways until either side closes.
//!   - On deny: respond `403 Forbidden` and emit a [`DenialEvent`] over the
//!     supplied channel so the Run Supervisor can fuse it into the host event
//!     stream as an `egress_denied` event.
//!
//! Wiring into the Run Supervisor and guest networking (the eth0 / nftables
//! / `HTTPS_PROXY` env in the guest) is the responsibility of the next slice.
//! This module is fully exercised by unit tests and a loopback integration
//! test on any platform — no KVM required.
//!
//! Plain HTTP proxying (absolute-URI `GET http://...`) is intentionally not
//! implemented yet: claude-code (the only built-in adapter today) only uses
//! HTTPS, and CONNECT is the only verb we need to satisfy the slice's
//! acceptance work. Adding HTTP later is a small extension to the same
//! request-parsing/decide/forward shape.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::egress::{denied_payload, DenialEvent, EgressPolicy, Protocol, EVENT_TYPE};
use crate::encoder::Encoder;

/// Parsed `CONNECT host:port HTTP/1.1` request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
}

/// Failure modes for `CONNECT` request parsing. All variants surface to the
/// client as `400 Bad Request`; we keep them separate for tests and for
/// future structured logging.
#[derive(Debug)]
pub enum ParseError {
    Io(#[allow(dead_code)] io::Error),
    Empty,
    /// Method was not CONNECT. Carries the (trimmed) first request line so the
    /// caller can attempt absolute-URI parsing for BusyBox-style wget requests.
    NotConnect(String),
    MalformedTarget,
    BadPort,
}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        ParseError::Io(e)
    }
}

/// Read and parse a `CONNECT` request line from `reader`. Consumes the
/// request line and the (possibly empty) headers up to the terminating
/// `\r\n\r\n`. Leaves the reader positioned at the start of the tunneled
/// payload.
pub async fn read_connect_request<R>(reader: &mut R) -> Result<ConnectRequest, ParseError>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(ParseError::Empty);
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(ParseError::NotConnect(trimmed.to_string()));
    }
    let (host, port_str) = target.rsplit_once(':').ok_or(ParseError::MalformedTarget)?;
    if host.is_empty() {
        return Err(ParseError::MalformedTarget);
    }
    let port: u16 = port_str.parse().map_err(|_| ParseError::BadPort)?;

    // Consume headers until blank line.
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).await?;
        if n == 0 {
            break;
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
    }

    Ok(ConnectRequest {
        host: host.to_string(),
        port,
    })
}

/// Extract `(host, port)` from an absolute-URI request line such as
/// `GET https://github.com/ HTTP/1.1`. Returns `None` for relative URIs or
/// unknown schemes so the caller can fall back to a plain 400.
fn extract_abs_uri_host(first_line: &str) -> Option<(String, u16)> {
    let uri = first_line.split(' ').nth(1)?;
    let (rest, default_port): (&str, u16) = if let Some(s) = uri.strip_prefix("https://") {
        (s, 443)
    } else if let Some(s) = uri.strip_prefix("http://") {
        (s, 80)
    } else {
        return None;
    };
    // Strip path: rest is "github.com/path" or "github.com:8080/path"
    let host_part = rest.split('/').next().unwrap_or(rest);
    if let Some((host, port_str)) = host_part.rsplit_once(':') {
        if !host.is_empty() {
            return Some((host.to_string(), port_str.parse().unwrap_or(default_port)));
        }
    }
    if !host_part.is_empty() {
        Some((host_part.to_string(), default_port))
    } else {
        None
    }
}

/// Decision for a parsed `CONNECT` request.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

/// Pure decision function: split out so the policy half is unit-testable
/// without any I/O.
pub fn evaluate(req: &ConnectRequest, policy: &EgressPolicy) -> Decision {
    if policy.allows(&req.host) {
        Decision::Allow
    } else {
        Decision::Deny {
            reason: "not in allowlist".to_string(),
        }
    }
}

/// Connector abstraction. Production uses [`TokioTcpConnector`]; tests
/// substitute a fake. Returns a duplex byte stream to the upstream service.
#[async_trait::async_trait]
pub trait Connector: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;
    async fn connect(&self, host: &str, port: u16) -> io::Result<Self::Stream>;
}

/// Default connector: opens a real TCP socket.
pub struct TokioTcpConnector;

#[async_trait::async_trait]
impl Connector for TokioTcpConnector {
    type Stream = TcpStream;
    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        TcpStream::connect((host, port)).await
    }
}

const RESP_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const RESP_FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_BAD_REQUEST: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Drive a single client connection: parse, decide, and either splice or
/// reject. Errors that originate from the client (closed connection, bad
/// request) are not propagated up — the caller is the listener and only
/// cares about systemic failures, of which there are none here.
pub async fn serve_connection<C, S>(
    client: S,
    policy: &EgressPolicy,
    connector: &C,
    denied_tx: &mpsc::UnboundedSender<DenialEvent>,
) where
    C: Connector,
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut client = BufReader::new(client);
    let req = match read_connect_request(&mut client).await {
        Ok(r) => r,
        Err(ParseError::NotConnect(first_line)) => {
            // BusyBox wget sends absolute-URI GETs instead of CONNECT. Apply
            // the egress policy so blocked domains still produce EgressDenied.
            if let Some((host, port)) = extract_abs_uri_host(&first_line) {
                let pseudo = ConnectRequest { host: host.clone(), port };
                if let Decision::Deny { reason } = evaluate(&pseudo, policy) {
                    let _ = client.write_all(RESP_FORBIDDEN).await;
                    let _ = client.shutdown().await;
                    let proto = match port {
                        443 => Protocol::Https,
                        80 => Protocol::Http,
                        _ => Protocol::RawTcp,
                    };
                    let _ = denied_tx.send(DenialEvent {
                        destination: host,
                        protocol: proto,
                        reason,
                    });
                    return;
                }
            }
            // Allowed domain or unrecognized URI form → 400, no DenialEvent.
            let _ = client.write_all(RESP_BAD_REQUEST).await;
            let _ = client.shutdown().await;
            return;
        }
        Err(_) => {
            let _ = client.write_all(RESP_BAD_REQUEST).await;
            let _ = client.shutdown().await;
            return;
        }
    };

    match evaluate(&req, policy) {
        Decision::Allow => {
            let mut upstream = match connector.connect(&req.host, req.port).await {
                Ok(u) => u,
                Err(_) => {
                    // Upstream unreachable: report 502. This is not a policy
                    // denial — agent should see a normal connection error.
                    let _ = client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    let _ = client.shutdown().await;
                    return;
                }
            };
            if client.write_all(RESP_OK).await.is_err() {
                return;
            }
            let mut client = client.into_inner();
            // copy_bidirectional handles half-close correctly.
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
        Decision::Deny { reason } => {
            let _ = client.write_all(RESP_FORBIDDEN).await;
            let _ = client.shutdown().await;
            let proto = match req.port {
                443 => Protocol::Https,
                80 => Protocol::Http,
                _ => Protocol::RawTcp,
            };
            // The receiver may already be gone if the Run stopped; drop the
            // event silently in that case.
            let _ = denied_tx.send(DenialEvent {
                destination: req.host.clone(),
                protocol: proto,
                reason,
            });
        }
    }
}

/// Translate a [`DenialEvent`] into an `egress_denied` event on the host
/// transcript stream. The Run Supervisor calls this for each denial received
/// on the channel returned by [`spawn_listener`].
pub fn emit_denial(encoder: &mut Encoder, denial: &DenialEvent) -> io::Result<()> {
    encoder.emit(
        EVENT_TYPE,
        denied_payload(&denial.destination, denial.protocol, &denial.reason),
    )
}

/// Spawn a listener that accepts connections on `addr` and serves each one
/// with [`serve_connection`]. Returns the bound [`SocketAddr`] (so callers
/// can request port 0 and learn the assigned port) and a join handle.
pub async fn spawn_listener(
    addr: SocketAddr,
    policy: EgressPolicy,
    denied_tx: mpsc::UnboundedSender<DenialEvent>,
) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let policy = policy.clone();
            let tx = denied_tx.clone();
            tokio::spawn(async move {
                let conn = TokioTcpConnector;
                serve_connection(sock, &policy, &conn, &tx).await;
            });
        }
    });
    Ok((bound, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{duplex, AsyncReadExt, DuplexStream};
    use tokio::sync::Mutex;

    fn policy(allowed: &[&str]) -> EgressPolicy {
        EgressPolicy::compose(allowed, &[])
    }

    #[tokio::test]
    async fn parses_well_formed_connect_with_no_headers() {
        let raw = b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n";
        let mut r = BufReader::new(&raw[..]);
        let req = read_connect_request(&mut r).await.unwrap();
        assert_eq!(req.host, "api.anthropic.com");
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn parses_connect_with_headers() {
        let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: keep-alive\r\n\r\n";
        let mut r = BufReader::new(&raw[..]);
        let req = read_connect_request(&mut r).await.unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn rejects_non_connect_method() {
        let raw = b"GET / HTTP/1.1\r\n\r\n";
        let mut r = BufReader::new(&raw[..]);
        let err = read_connect_request(&mut r).await.unwrap_err();
        assert!(matches!(err, ParseError::NotConnect(_)));
    }

    #[tokio::test]
    async fn rejects_missing_port() {
        let raw = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let mut r = BufReader::new(&raw[..]);
        let err = read_connect_request(&mut r).await.unwrap_err();
        assert!(matches!(err, ParseError::MalformedTarget));
    }

    #[tokio::test]
    async fn rejects_non_numeric_port() {
        let raw = b"CONNECT example.com:notaport HTTP/1.1\r\n\r\n";
        let mut r = BufReader::new(&raw[..]);
        let err = read_connect_request(&mut r).await.unwrap_err();
        assert!(matches!(err, ParseError::BadPort));
    }

    #[tokio::test]
    async fn rejects_empty_stream() {
        let raw: &[u8] = b"";
        let mut r = BufReader::new(raw);
        let err = read_connect_request(&mut r).await.unwrap_err();
        assert!(matches!(err, ParseError::Empty));
    }

    #[test]
    fn evaluate_allows_listed_host() {
        let p = policy(&["api.anthropic.com"]);
        let req = ConnectRequest { host: "api.anthropic.com".into(), port: 443 };
        assert_eq!(evaluate(&req, &p), Decision::Allow);
    }

    #[test]
    fn evaluate_denies_unlisted_host() {
        let p = policy(&["api.anthropic.com"]);
        let req = ConnectRequest { host: "github.com".into(), port: 443 };
        match evaluate(&req, &p) {
            Decision::Deny { reason } => assert!(reason.contains("allowlist")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_is_case_insensitive_via_policy() {
        let p = policy(&["api.anthropic.com"]);
        let req = ConnectRequest { host: "API.Anthropic.COM".into(), port: 443 };
        assert_eq!(evaluate(&req, &p), Decision::Allow);
    }

    /// Connector that fails — exercises the deny path without needing a real
    /// upstream. Allow-path connector tests use a recording connector (below).
    struct UnreachableConnector;

    #[async_trait::async_trait]
    impl Connector for UnreachableConnector {
        type Stream = DuplexStream;
        async fn connect(&self, _host: &str, _port: u16) -> io::Result<DuplexStream> {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "no upstream"))
        }
    }

    /// Connector that returns a pre-canned upstream pipe and records the
    /// host/port it was asked for.
    struct RecordingConnector {
        upstream: Arc<Mutex<Option<DuplexStream>>>,
        seen: Arc<Mutex<Vec<(String, u16)>>>,
    }

    #[async_trait::async_trait]
    impl Connector for RecordingConnector {
        type Stream = DuplexStream;
        async fn connect(&self, host: &str, port: u16) -> io::Result<DuplexStream> {
            self.seen.lock().await.push((host.to_string(), port));
            self.upstream
                .lock()
                .await
                .take()
                .ok_or_else(|| io::Error::other("already taken"))
        }
    }

    #[tokio::test]
    async fn deny_path_emits_event_and_returns_403() {
        let (mut client, server) = duplex(4096);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&["api.anthropic.com"]);

        client
            .write_all(b"CONNECT github.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        let connector = UnreachableConnector;
        serve_connection(server, &p, &connector, &tx).await;

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 403"), "got: {resp_str}");

        let event = rx.try_recv().expect("denial event must be sent");
        assert_eq!(event.destination, "github.com");
        assert_eq!(event.protocol, Protocol::Https);
        assert!(event.reason.contains("allowlist"));
    }

    #[tokio::test]
    async fn deny_path_reports_http_for_port_80() {
        let (mut client, server) = duplex(4096);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&[]);

        client
            .write_all(b"CONNECT example.com:80 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        serve_connection(server, &p, &UnreachableConnector, &tx).await;
        let _ = client.read_to_end(&mut Vec::new()).await;

        let event = rx.try_recv().expect("event");
        assert_eq!(event.protocol, Protocol::Http);
    }

    #[tokio::test]
    async fn deny_path_reports_raw_tcp_for_other_ports() {
        let (mut client, server) = duplex(4096);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&[]);

        client
            .write_all(b"CONNECT example.com:5432 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        serve_connection(server, &p, &UnreachableConnector, &tx).await;
        let _ = client.read_to_end(&mut Vec::new()).await;

        let event = rx.try_recv().expect("event");
        assert_eq!(event.protocol, Protocol::RawTcp);
    }

    #[tokio::test]
    async fn allow_path_returns_200_and_splices_bytes() {
        let (mut client, server) = duplex(4096);
        let (upstream_a, mut upstream_b) = duplex(4096); // a = "as seen by proxy", b = "the upstream service"
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&["api.anthropic.com"]);

        let connector = RecordingConnector {
            upstream: Arc::new(Mutex::new(Some(upstream_a))),
            seen: Arc::new(Mutex::new(Vec::new())),
        };
        let seen = connector.seen.clone();

        // Pre-load: client writes the CONNECT line, then a payload after
        // the proxy's 200.
        client
            .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let serve = tokio::spawn(async move {
            serve_connection(server, &p, &connector, &tx).await;
        });

        // Read exactly the 200 response; can't use read_to_end because the
        // tunnel stays open.
        let mut buf = vec![0u8; RESP_OK.len()];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf[..], RESP_OK);

        // Tunnel a request both ways.
        client.write_all(b"client->upstream").await.unwrap();
        let mut upstream_buf = vec![0u8; b"client->upstream".len()];
        tokio::io::AsyncReadExt::read_exact(&mut upstream_b, &mut upstream_buf)
            .await
            .unwrap();
        assert_eq!(&upstream_buf, b"client->upstream");

        upstream_b.write_all(b"upstream->client").await.unwrap();
        let mut client_buf = vec![0u8; b"upstream->client".len()];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut client_buf)
            .await
            .unwrap();
        assert_eq!(&client_buf, b"upstream->client");

        // Closing both ends lets serve_connection drop out.
        drop(client);
        drop(upstream_b);
        serve.await.unwrap();

        let seen = seen.lock().await.clone();
        assert_eq!(seen, vec![("api.anthropic.com".to_string(), 443)]);
        assert!(rx.try_recv().is_err(), "no denial event for an allowed connection");
    }

    #[tokio::test]
    async fn malformed_request_returns_400_no_event() {
        let (mut client, server) = duplex(4096);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&[]);

        client.write_all(b"GET /\r\n\r\n").await.unwrap();
        client.flush().await.unwrap();

        serve_connection(server, &p, &UnreachableConnector, &tx).await;
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 400"), "got: {s}");
        assert!(rx.try_recv().is_err(), "malformed request is not a policy denial");
    }

    #[test]
    fn extract_abs_uri_host_https() {
        assert_eq!(
            extract_abs_uri_host("GET https://github.com/ HTTP/1.1"),
            Some(("github.com".into(), 443))
        );
    }

    #[test]
    fn extract_abs_uri_host_http() {
        assert_eq!(
            extract_abs_uri_host("GET http://example.com/path HTTP/1.1"),
            Some(("example.com".into(), 80))
        );
    }

    #[test]
    fn extract_abs_uri_host_with_explicit_port() {
        assert_eq!(
            extract_abs_uri_host("GET https://example.com:8443/foo HTTP/1.1"),
            Some(("example.com".into(), 8443))
        );
    }

    #[test]
    fn extract_abs_uri_host_relative_uri_returns_none() {
        assert_eq!(extract_abs_uri_host("GET / HTTP/1.1"), None);
    }

    #[test]
    fn extract_abs_uri_host_empty_returns_none() {
        assert_eq!(extract_abs_uri_host(""), None);
    }

    #[tokio::test]
    async fn abs_uri_blocked_domain_emits_403_and_denial_event() {
        // BusyBox wget sends GET https://github.com/ HTTP/1.1 instead of CONNECT.
        // The proxy must still enforce the egress policy and emit a denial event.
        let (mut client, server) = duplex(4096);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&[]);

        client
            .write_all(b"GET https://github.com/ HTTP/1.1\r\nHost: github.com\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        serve_connection(server, &p, &UnreachableConnector, &tx).await;
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 403"), "got: {s}");

        let event = rx.try_recv().expect("denial event must be sent");
        assert_eq!(event.destination, "github.com");
        assert_eq!(event.protocol, Protocol::Https);
    }

    #[tokio::test]
    async fn abs_uri_allowed_domain_returns_400_no_denial_event() {
        // Allowed domain with abs-URI: can't tunnel (not CONNECT), so 400,
        // but no EgressDenied since the domain is permitted.
        let (mut client, server) = duplex(4096);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&["api.anthropic.com"]);

        client
            .write_all(b"GET https://api.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        serve_connection(server, &p, &UnreachableConnector, &tx).await;
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 400"), "got: {s}");
        assert!(rx.try_recv().is_err(), "allowed domain must not produce a denial event");
    }

    #[tokio::test]
    async fn upstream_unreachable_returns_502_no_event() {
        let (mut client, server) = duplex(4096);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&["api.anthropic.com"]);

        client
            .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        serve_connection(server, &p, &UnreachableConnector, &tx).await;
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let s = String::from_utf8_lossy(&resp);
        assert!(s.starts_with("HTTP/1.1 502"), "got: {s}");
        assert!(rx.try_recv().is_err(), "upstream failure is not a policy denial");
    }

    #[tokio::test]
    async fn emit_denial_writes_egress_denied_event_to_transcript() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut enc = Encoder::new("TEST01", tmp.path(), None).unwrap();
        let denial = DenialEvent {
            destination: "github.com".into(),
            protocol: Protocol::Https,
            reason: "not in allowlist".into(),
        };
        emit_denial(&mut enc, &denial).unwrap();

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let line = content.trim();
        assert!(!line.is_empty(), "transcript must contain a line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["type"], "egress_denied");
        assert_eq!(v["destination"], "github.com");
        assert_eq!(v["protocol"], "https");
        assert_eq!(v["reason"], "not in allowlist");
        assert_eq!(v["run_id"], "TEST01");
    }

    #[tokio::test]
    async fn proxy_denial_pump_into_encoder_round_trip() {
        // Wire the proxy → channel → emit_denial → Encoder pipeline end-to-end.
        // Mirrors the production flow the Run Supervisor will drive: a denied
        // CONNECT lands a DenialEvent on the channel, which the supervisor
        // pumps into the Encoder via emit_denial.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut enc = Encoder::new("RUN02", tmp.path(), None).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let p = policy(&["api.anthropic.com"]);

        let (proxy_addr, listener_handle) =
            spawn_listener("127.0.0.1:0".parse().unwrap(), p, tx).await.unwrap();

        // Client → proxy: try a non-allowed destination.
        let mut sock = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        sock.write_all(b"CONNECT github.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 403"), "got: {resp_str}");

        // Pump the denial through the supervisor-shaped helper.
        let denial = rx.recv().await.expect("denial event");
        emit_denial(&mut enc, &denial).unwrap();

        // Tear down the listener — we're done.
        listener_handle.abort();

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let line = content.trim();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["type"], "egress_denied");
        assert_eq!(v["destination"], "github.com");
        assert_eq!(v["protocol"], "https");
        assert_eq!(v["run_id"], "RUN02");
    }

    #[tokio::test]
    async fn listener_end_to_end_loopback() {
        // Start a tiny upstream "echo" server.
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = upstream.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = tokio::io::AsyncReadExt::read(&mut s, &mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        // Allowlist 127.0.0.1 so the proxy will forward to our test upstream.
        let p = EgressPolicy::compose(&["127.0.0.1"], &[]);
        let (tx, _rx) = mpsc::unbounded_channel();
        let (proxy_addr, _h) =
            spawn_listener("127.0.0.1:0".parse().unwrap(), p, tx).await.unwrap();

        // Client → proxy.
        let mut sock = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n",
            upstream_addr.port()
        );
        sock.write_all(connect_req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; RESP_OK.len()];
        tokio::io::AsyncReadExt::read_exact(&mut sock, &mut resp)
            .await
            .unwrap();
        assert_eq!(&resp[..], RESP_OK);

        sock.write_all(b"hello").await.unwrap();
        let mut echoed = vec![0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut sock, &mut echoed)
            .await
            .unwrap();
        assert_eq!(&echoed, b"hello");
    }
}
