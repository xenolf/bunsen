//! DNS denial path (ADR-0005, [`Protocol::Dns`]).
//!
//! Per ADR-0005 a Run's egress is denied at three layers: L3 nftables drops at
//! `protocol=raw_tcp`, L7 CONNECT rejects at `protocol=http`/`https`, and DNS
//! resolution rejects at `protocol=dns`. The L7 proxy resolves names
//! server-side for HTTPS — so the DNS path matters mainly for agents that
//! probe DNS directly (an attempt to bypass the proxy via raw IPs would still
//! be caught by L3, but a curl that *just* does an A lookup against the guest
//! resolver shouldn't silently time out).
//!
//! This slice (10l) lands the pure-Rust pieces: wire-format parser for a DNS
//! query message (header + question section), a [`DnsDecision`] evaluator
//! against [`EgressPolicy`], and a builder for a `REFUSED` reply that echoes
//! the query's id + question. The UDP listener that drives them, and the
//! guest's `/etc/resolv.conf` pointing at it, are the next slices.
//!
//! The parser is intentionally strict: it refuses name compression in the
//! question section (RFC 1035 §4.1.4 forbids it in queries) and refuses
//! reserved label-length forms (`01` / `10`). Loose parsing would let a
//! hostile guest hide an allowed name behind a compression pointer.

// dead_code: a few internal qtype constants + the upstream resolver fields
// (used only through the trait) trip dead_code; the surface API of the
// module — parser, decision, refused-builder, handler, listener — is all
// consumed by run_sandbox + tests.
#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::egress::{DenialEvent, EgressPolicy, Protocol};

/// Failure modes for [`parse_dns_query`]. Surfaced for tests + future
/// structured logging; the UDP slice will respond with FORMERR for these
/// rather than emitting a denial event.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsParseError {
    /// Datagram is shorter than the 12-byte DNS header.
    TruncatedHeader,
    /// `QDCOUNT == 0` — a well-formed query must carry at least one question.
    NoQuestion,
    /// Datagram ends mid-name or mid-(qtype/qclass).
    TruncatedQuestion,
    /// Label length byte uses one of the reserved forms (`01`, `10`) or the
    /// compression pointer form (`11`). Compression is forbidden in queries.
    InvalidLabel,
    /// Label exceeds 63 bytes (RFC 1035 §2.3.4).
    LabelTooLong,
    /// Total encoded name exceeds 255 bytes (RFC 1035 §2.3.4).
    NameTooLong,
}

/// Parsed DNS message header (12 bytes, big-endian).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

/// One parsed question section entry. `name` is normalized to lowercase with
/// no trailing dot so it can be matched directly against the policy's
/// allowlist (which itself stores lowercase, trimmed FQDNs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A parsed DNS query: header + question section. `question_section_end` is
/// the byte offset just past the last parsed question — the REFUSED response
/// builder uses it to copy the question bytes verbatim into the reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub question_section_end: usize,
}

/// Common DNS QTYPEs. We don't filter on type today — an allowed name is
/// allowed for any QTYPE — but the constants are handy for tests and for
/// future expansion (e.g. blocking ANY queries to reduce amplification).
pub mod qtype {
    pub const A: u16 = 1;
    pub const AAAA: u16 = 28;
    pub const CNAME: u16 = 5;
    pub const TXT: u16 = 16;
    pub const ANY: u16 = 255;
}

/// QCLASS for "Internet" — the only class an outbound resolver will see in
/// practice. Other classes (CHAOS, HESIOD) are vestigial.
pub const QCLASS_IN: u16 = 1;

/// RCODE 5 = REFUSED. Per RFC 1035 the server is "refusing to perform the
/// specified operation for policy reasons" — exactly the shape of a denial.
pub const RCODE_REFUSED: u8 = 5;

/// Bit mask for QR (response flag) in the DNS flags word.
const FLAG_QR: u16 = 0x8000;
/// Mask preserving OPCODE (bits 11..14) and RD (bit 8) from the query.
const FLAGS_PRESERVE_FROM_QUERY: u16 = 0x7900;

/// Parse a DNS query message: header + all questions.
///
/// Strict: refuses name compression in the question section (queries don't
/// use it; permitting it would let a guest hide an allowed name behind a
/// pointer and bypass the allowlist) and refuses reserved label-length
/// forms. See [`DnsParseError`] for the failure taxonomy.
pub fn parse_dns_query(bytes: &[u8]) -> Result<DnsQuery, DnsParseError> {
    if bytes.len() < 12 {
        return Err(DnsParseError::TruncatedHeader);
    }
    let header = DnsHeader {
        id: u16::from_be_bytes([bytes[0], bytes[1]]),
        flags: u16::from_be_bytes([bytes[2], bytes[3]]),
        qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
        ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
        nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
        arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
    };
    if header.qdcount == 0 {
        return Err(DnsParseError::NoQuestion);
    }

    let mut offset = 12usize;
    let mut questions = Vec::with_capacity(header.qdcount as usize);
    for _ in 0..header.qdcount {
        let (name, new_offset) = parse_qname(bytes, offset)?;
        if new_offset + 4 > bytes.len() {
            return Err(DnsParseError::TruncatedQuestion);
        }
        let qtype = u16::from_be_bytes([bytes[new_offset], bytes[new_offset + 1]]);
        let qclass = u16::from_be_bytes([bytes[new_offset + 2], bytes[new_offset + 3]]);
        questions.push(DnsQuestion { name, qtype, qclass });
        offset = new_offset + 4;
    }

    Ok(DnsQuery {
        header,
        questions,
        question_section_end: offset,
    })
}

/// Parse a length-prefixed QNAME starting at `bytes[offset]`. Returns the
/// decoded name (lowercase, no trailing dot, dot-joined labels) and the byte
/// offset just past the terminating zero-length label.
fn parse_qname(bytes: &[u8], mut offset: usize) -> Result<(String, usize), DnsParseError> {
    let mut name = String::new();
    let mut total_len = 0usize;
    loop {
        if offset >= bytes.len() {
            return Err(DnsParseError::TruncatedQuestion);
        }
        let len_byte = bytes[offset];
        // Top two bits 11 → compression pointer. Forbidden in queries.
        // Top two bits 01 or 10 → reserved. Refuse both.
        if len_byte & 0xC0 != 0 {
            return Err(DnsParseError::InvalidLabel);
        }
        let label_len = len_byte as usize;
        offset += 1;
        if label_len == 0 {
            // Root label — name complete.
            return Ok((name, offset));
        }
        if label_len > 63 {
            // Caught by 0xC0 mask above, but keep as defense-in-depth.
            return Err(DnsParseError::LabelTooLong);
        }
        if offset + label_len > bytes.len() {
            return Err(DnsParseError::TruncatedQuestion);
        }
        // +1 for the length byte just consumed; +label_len for the label;
        // +1 for the eventual dot/terminator. The 255-byte cap is the encoded
        // wire length, not the dotted form, but bounding the dotted form by
        // the same number is conservatively correct.
        total_len += label_len + 1;
        if total_len > 255 {
            return Err(DnsParseError::NameTooLong);
        }
        if !name.is_empty() {
            name.push('.');
        }
        let label = &bytes[offset..offset + label_len];
        // Append ASCII-lowercased label. Per RFC 1035 names are
        // case-insensitive; lowercasing here lets policy matching stay exact.
        for &b in label {
            name.push(b.to_ascii_lowercase() as char);
        }
        offset += label_len;
    }
}

/// Result of evaluating a parsed query against the egress policy.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsDecision {
    Allow,
    Deny { reason: String },
}

/// Evaluate a parsed query: allow if *every* question's name is on the
/// allowlist, otherwise deny. Multi-question queries are rare in practice
/// (most resolvers send one question per datagram) but parsing accepts them;
/// requiring *all* questions to be allowed avoids accidentally permitting an
/// adjacent denied name through a multi-question packet.
pub fn evaluate_dns_query(query: &DnsQuery, policy: &EgressPolicy) -> DnsDecision {
    for q in &query.questions {
        if !policy.allows(&q.name) {
            return DnsDecision::Deny {
                reason: "not in allowlist".to_string(),
            };
        }
    }
    DnsDecision::Allow
}

/// Build a `REFUSED` reply from a parsed query. The reply echoes the query's
/// id, opcode, RD bit, and question section verbatim, sets QR=1 + RCODE=5,
/// and carries no answer / authority / additional records.
///
/// This is the wire shape the UDP slice (next) will send for a denied query.
/// Splitting it off makes the response shape unit-testable without I/O.
pub fn build_refused_response(query_bytes: &[u8]) -> Result<Vec<u8>, DnsParseError> {
    let query = parse_dns_query(query_bytes)?;
    let q_end = query.question_section_end;
    debug_assert!(q_end <= query_bytes.len());

    let mut out = Vec::with_capacity(q_end);
    // Header
    out.extend_from_slice(&query.header.id.to_be_bytes());
    let reply_flags = (query.header.flags & FLAGS_PRESERVE_FROM_QUERY)
        | FLAG_QR
        | (RCODE_REFUSED as u16);
    out.extend_from_slice(&reply_flags.to_be_bytes());
    out.extend_from_slice(&query.header.qdcount.to_be_bytes()); // QDCOUNT preserved
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section: copy bytes verbatim from the original query. We've
    // already validated this range parses cleanly.
    out.extend_from_slice(&query_bytes[12..q_end]);

    Ok(out)
}

/// Stable `reason` text for a DNS denial. Used by the UDP slice when it
/// converts a `DnsDecision::Deny` into a [`crate::egress::DenialEvent`].
pub fn dns_event_reason(qtype: u16) -> String {
    format!("DNS query denied (qtype={qtype})")
}

// ─── Slice 10m: UDP listener + upstream resolver abstraction ─────────────

/// Trait abstracting "send the query upstream and get bytes back". Production
/// uses [`TokioUdpResolver`]; tests substitute fakes to keep the deny / allow
/// shapes verifiable without a live recursive resolver.
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    /// Forward `query_bytes` to the upstream and return the upstream's
    /// response bytes verbatim. An `Err` is treated as "upstream unavailable"
    /// by the handler — symmetric with the L7 path's `502` on upstream
    /// failure, no `DenialEvent` is emitted because this isn't a policy
    /// rejection.
    async fn resolve(&self, query_bytes: &[u8]) -> io::Result<Vec<u8>>;
}

/// Production [`DnsResolver`] that sends each query to a fixed upstream
/// `(ip:port)` over UDP and reads back one response.
///
/// A fresh ephemeral source port is bound per query: long-lived sockets to a
/// single upstream are unusual for DNS and would force serialization of
/// outstanding queries. Per-query bind is cheap on Linux.
pub struct TokioUdpResolver {
    upstream: SocketAddr,
    timeout: Duration,
}

impl TokioUdpResolver {
    /// Default 5-second timeout. Matches stock `glibc` `RES_TIMEOUT` (`5s`),
    /// which is what guest resolvers in the OCI image will be configured
    /// with — picking a shorter value here would surface as a guest-side
    /// timeout rather than a graceful upstream failure.
    pub fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }
}

#[async_trait::async_trait]
impl DnsResolver for TokioUdpResolver {
    async fn resolve(&self, query_bytes: &[u8]) -> io::Result<Vec<u8>> {
        let bind: SocketAddr = if self.upstream.is_ipv6() {
            "[::]:0".parse().expect("static literal")
        } else {
            "0.0.0.0:0".parse().expect("static literal")
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(self.upstream).await?;
        sock.send(query_bytes).await?;
        // 4096 is enough for a standard UDP DNS response (the RFC 1035 limit
        // is 512 bytes; EDNS extends to ~4096; over UDP, anything larger
        // gets truncated and the client falls back to TCP).
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(self.timeout, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                buf.truncate(n);
                Ok(buf)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS upstream timed out",
            )),
        }
    }
}

/// What the per-packet handler decided. The listener uses [`Reply`] bytes to
/// drive a `send_to` back to the client and treats [`NoReply`] as "drop this
/// datagram silently" — the client will retry on its own timeout.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsHandleOutcome {
    Reply(Vec<u8>),
    NoReply,
}

/// Drive one DNS query end-to-end: parse, decide, and either forward (Allow)
/// or refuse (Deny). On Deny also emits a [`DenialEvent`] on the shared
/// channel so the supervisor surfaces it as `egress_denied(protocol=dns)`.
///
/// Splitting this off from [`spawn_dns_listener`] is the same trick slice 10b
/// used for the L7 proxy: the policy/resolver/event-shape is fully unit-
/// testable without a real `UdpSocket`. Tests pass a fake [`DnsResolver`].
///
/// Parse-error datagrams are dropped (`NoReply`, no event). Building a
/// FORMERR would require us to trust the first 12 bytes of garbage as the
/// query header — easier and safer to be silent and let the guest's resolver
/// time out.
pub async fn handle_dns_query<R: DnsResolver + ?Sized>(
    query_bytes: &[u8],
    policy: &EgressPolicy,
    resolver: &R,
    denied_tx: &mpsc::UnboundedSender<DenialEvent>,
) -> DnsHandleOutcome {
    let query = match parse_dns_query(query_bytes) {
        Ok(q) => q,
        Err(_) => return DnsHandleOutcome::NoReply,
    };
    match evaluate_dns_query(&query, policy) {
        DnsDecision::Allow => match resolver.resolve(query_bytes).await {
            Ok(bytes) => DnsHandleOutcome::Reply(bytes),
            Err(_) => DnsHandleOutcome::NoReply,
        },
        DnsDecision::Deny { .. } => {
            // Attribute the event to the first denied question so a multi-
            // question packet that mixes allowed + denied names doesn't lose
            // the violator.
            let (dest, qtype) = query
                .questions
                .iter()
                .find(|q| !policy.allows(&q.name))
                .map(|q| (q.name.clone(), q.qtype))
                .unwrap_or_else(|| (String::new(), 0));
            // Receiver may already be gone (Run stopped); drop silently.
            let _ = denied_tx.send(DenialEvent {
                destination: dest,
                protocol: Protocol::Dns,
                reason: dns_event_reason(qtype),
            });
            match build_refused_response(query_bytes) {
                Ok(reply) => DnsHandleOutcome::Reply(reply),
                Err(_) => DnsHandleOutcome::NoReply,
            }
        }
    }
}

/// Spawn a UDP listener that accepts DNS queries on `addr` and drives each
/// one through [`handle_dns_query`]. Returns the bound [`SocketAddr`] (so
/// callers can request port 0 and learn the assigned port) and the listener's
/// join handle.
///
/// Mirrors [`crate::egress_proxy::spawn_listener`]'s shape — one task accepts,
/// one task per query handles. Per-query tasks share a single `UdpSocket`
/// (via `Arc`) for the `send_to` reply because there is no per-flow socket
/// in UDP.
pub async fn spawn_dns_listener<R>(
    addr: SocketAddr,
    policy: EgressPolicy,
    resolver: R,
    denied_tx: mpsc::UnboundedSender<DenialEvent>,
) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)>
where
    R: DnsResolver + 'static,
{
    let sock = UdpSocket::bind(addr).await?;
    let bound = sock.local_addr()?;
    let sock = Arc::new(sock);
    let resolver = Arc::new(resolver);
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            // Copy the datagram off the shared buffer before spawning so the
            // next iteration of the loop can reuse it without racing.
            let bytes = buf[..n].to_vec();
            let policy = policy.clone();
            let resolver = resolver.clone();
            let tx = denied_tx.clone();
            let sock = sock.clone();
            tokio::spawn(async move {
                let outcome = handle_dns_query(&bytes, &policy, &*resolver, &tx).await;
                if let DnsHandleOutcome::Reply(reply) = outcome {
                    let _ = sock.send_to(&reply, peer).await;
                }
            });
        }
    });
    Ok((bound, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ────────────────────────────────────────────────────────────

    /// Encode a name as DNS wire labels: each label prefixed with its length,
    /// terminated by a zero-length root label. e.g. "github.com" →
    /// [6, g,i,t,h,u,b, 3, c,o,m, 0].
    fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if !name.is_empty() {
            for label in name.split('.') {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
        }
        out.push(0);
        out
    }

    /// Build a minimal DNS query: one question with the given name + qtype.
    fn build_query(id: u16, flags: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        out.extend(encode_name(name));
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&QCLASS_IN.to_be_bytes());
        out
    }

    fn policy(allowed: &[&str]) -> EgressPolicy {
        EgressPolicy::compose(allowed, &[])
    }

    // ── parse_dns_query ────────────────────────────────────────────────────

    #[test]
    fn parses_simple_a_query() {
        // Standard query: RD=1, opcode=0. Flags 0x0100.
        let q = build_query(0x1234, 0x0100, "github.com", qtype::A);
        let parsed = parse_dns_query(&q).expect("must parse");
        assert_eq!(parsed.header.id, 0x1234);
        assert_eq!(parsed.header.flags, 0x0100);
        assert_eq!(parsed.header.qdcount, 1);
        assert_eq!(parsed.questions.len(), 1);
        let qn = &parsed.questions[0];
        assert_eq!(qn.name, "github.com");
        assert_eq!(qn.qtype, qtype::A);
        assert_eq!(qn.qclass, QCLASS_IN);
    }

    #[test]
    fn parses_aaaa_query() {
        let q = build_query(0xBEEF, 0x0100, "api.anthropic.com", qtype::AAAA);
        let parsed = parse_dns_query(&q).expect("must parse");
        assert_eq!(parsed.questions[0].name, "api.anthropic.com");
        assert_eq!(parsed.questions[0].qtype, qtype::AAAA);
    }

    #[test]
    fn lowercases_qname_for_policy_match() {
        // RFC 1035: names are case-insensitive. We lowercase on parse so the
        // policy (which stores lowercase) gets a direct comparison.
        let q = build_query(0x0001, 0, "GitHub.COM", qtype::A);
        let parsed = parse_dns_query(&q).expect("must parse");
        assert_eq!(parsed.questions[0].name, "github.com");
    }

    #[test]
    fn parses_root_name() {
        // QNAME of just "." (root) — a zero-length label byte. Some queries
        // (e.g. NS .) carry this. We accept it; policy will then deny because
        // an empty name is never on the allowlist.
        let mut q = Vec::new();
        q.extend_from_slice(&0x0001u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        q.push(0); // root label only
        q.extend_from_slice(&qtype::A.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());
        let parsed = parse_dns_query(&q).expect("must parse");
        assert_eq!(parsed.questions[0].name, "");
    }

    #[test]
    fn rejects_truncated_header() {
        for len in 0..12 {
            assert_eq!(
                parse_dns_query(&vec![0u8; len]),
                Err(DnsParseError::TruncatedHeader),
                "len={len} should be TruncatedHeader",
            );
        }
    }

    #[test]
    fn rejects_zero_qdcount() {
        // Header-only datagram with QDCOUNT=0 — not a question, refuse.
        let mut q = vec![0u8; 12];
        // QDCOUNT bytes 4..6 stay zero.
        q[0] = 0xAB; // id
        q[1] = 0xCD;
        assert_eq!(parse_dns_query(&q), Err(DnsParseError::NoQuestion));
    }

    #[test]
    fn rejects_compression_pointer_in_question() {
        // Compression pointer = top two bits 11 (0xC0). RFC 1035 §4.1.4
        // explicitly forbids compression in question names; allowing it
        // would let a guest hide a name behind a pointer.
        let mut q = Vec::new();
        q.extend_from_slice(&0u16.to_be_bytes()); // id
        q.extend_from_slice(&0u16.to_be_bytes()); // flags
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        q.push(0xC0); // compression pointer marker
        q.push(0x0C); // pointer to offset 12
        q.extend_from_slice(&qtype::A.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());
        assert_eq!(parse_dns_query(&q), Err(DnsParseError::InvalidLabel));
    }

    #[test]
    fn rejects_reserved_label_length_form() {
        // Top two bits 01 or 10 are reserved (RFC 1035 §4.1.4) — refuse.
        let mut q = Vec::new();
        q.extend_from_slice(&0u16.to_be_bytes()); // id
        q.extend_from_slice(&0u16.to_be_bytes()); // flags
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        q.push(0x40); // reserved (binary 01xxxxxx)
        q.push(0x00);
        assert_eq!(parse_dns_query(&q), Err(DnsParseError::InvalidLabel));
    }

    #[test]
    fn rejects_truncated_label() {
        // Label claims 10 bytes but only 3 remain.
        let mut q = Vec::new();
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.push(10);
        q.extend_from_slice(b"xyz");
        assert_eq!(parse_dns_query(&q), Err(DnsParseError::TruncatedQuestion));
    }

    #[test]
    fn rejects_missing_qtype_qclass() {
        // Name parses cleanly, but no QTYPE/QCLASS bytes follow.
        let mut q = Vec::new();
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend(encode_name("github.com"));
        // No qtype/qclass.
        assert_eq!(parse_dns_query(&q), Err(DnsParseError::TruncatedQuestion));
    }

    #[test]
    fn rejects_overlong_name() {
        // Build a query whose name exceeds 255 wire bytes — should be
        // rejected as NameTooLong. Repeated max-label (63 bytes) chunks.
        let mut q = Vec::new();
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        // 5 × 63-byte labels = 315 bytes + 5 length bytes = 320 > 255.
        for _ in 0..5 {
            q.push(63);
            q.extend(std::iter::repeat(b'a').take(63));
        }
        q.push(0);
        q.extend_from_slice(&qtype::A.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());
        assert_eq!(parse_dns_query(&q), Err(DnsParseError::NameTooLong));
    }

    #[test]
    fn parses_multiple_questions() {
        // Most resolvers send 1 question; the protocol allows N. Parse all
        // of them so policy can deny if *any* question is unlisted.
        let mut q = Vec::new();
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&2u16.to_be_bytes()); // QDCOUNT=2
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend(encode_name("github.com"));
        q.extend_from_slice(&qtype::A.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());
        q.extend(encode_name("api.github.com"));
        q.extend_from_slice(&qtype::AAAA.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());

        let parsed = parse_dns_query(&q).expect("must parse");
        assert_eq!(parsed.questions.len(), 2);
        assert_eq!(parsed.questions[0].name, "github.com");
        assert_eq!(parsed.questions[1].name, "api.github.com");
        assert_eq!(parsed.questions[1].qtype, qtype::AAAA);
    }

    #[test]
    fn question_section_end_matches_actual_consumed_bytes() {
        // The refused-response builder copies bytes [12..question_section_end]
        // verbatim into the reply, so this offset must equal the byte length
        // of the question section we parsed.
        let q = build_query(0x0001, 0x0100, "github.com", qtype::A);
        let parsed = parse_dns_query(&q).expect("must parse");
        assert_eq!(parsed.question_section_end, q.len());
        // Manually computed: 12 header + 1 + 6 + 1 + 3 + 1 (name) + 2 + 2 = 28.
        assert_eq!(parsed.question_section_end, 28);
    }

    // ── evaluate_dns_query ─────────────────────────────────────────────────

    #[test]
    fn allow_when_name_in_policy() {
        let p = policy(&["github.com"]);
        let q = parse_dns_query(&build_query(0, 0, "github.com", qtype::A)).unwrap();
        assert_eq!(evaluate_dns_query(&q, &p), DnsDecision::Allow);
    }

    #[test]
    fn deny_when_name_not_in_policy() {
        let p = policy(&["github.com"]);
        let q = parse_dns_query(&build_query(0, 0, "evil.example", qtype::A)).unwrap();
        match evaluate_dns_query(&q, &p) {
            DnsDecision::Deny { reason } => assert!(reason.contains("allowlist")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn deny_subdomain_when_only_parent_allowed() {
        // No wildcards in v1 — same rule as the L7 proxy. A query for
        // api.github.com must NOT be allowed by a policy listing github.com.
        let p = policy(&["github.com"]);
        let q = parse_dns_query(&build_query(0, 0, "api.github.com", qtype::A)).unwrap();
        assert!(matches!(evaluate_dns_query(&q, &p), DnsDecision::Deny { .. }));
    }

    #[test]
    fn case_insensitive_match() {
        // Parser lowercases; policy stores lowercase. Sanity-check the
        // round-trip with mixed-case input.
        let p = policy(&["github.com"]);
        let q = parse_dns_query(&build_query(0, 0, "GitHub.Com", qtype::A)).unwrap();
        assert_eq!(evaluate_dns_query(&q, &p), DnsDecision::Allow);
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = policy(&[]);
        let q = parse_dns_query(&build_query(0, 0, "github.com", qtype::A)).unwrap();
        assert!(matches!(evaluate_dns_query(&q, &p), DnsDecision::Deny { .. }));
    }

    #[test]
    fn multi_question_denies_if_any_unlisted() {
        // 2-question query: first is allowed, second is not. Must deny.
        // Otherwise a hostile guest could append an allowed name to slip a
        // denied lookup through.
        let p = policy(&["github.com"]);
        let mut q = Vec::new();
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&2u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend(encode_name("github.com"));
        q.extend_from_slice(&qtype::A.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());
        q.extend(encode_name("evil.example"));
        q.extend_from_slice(&qtype::A.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());
        let parsed = parse_dns_query(&q).unwrap();
        assert!(matches!(evaluate_dns_query(&parsed, &p), DnsDecision::Deny { .. }));
    }

    // ── build_refused_response ─────────────────────────────────────────────

    #[test]
    fn refused_response_preserves_id() {
        let q = build_query(0xBEEF, 0x0100, "evil.example", qtype::A);
        let reply = build_refused_response(&q).unwrap();
        assert_eq!(&reply[0..2], &[0xBE, 0xEF]);
    }

    #[test]
    fn refused_response_sets_qr_and_rcode() {
        let q = build_query(0x0001, 0x0100, "evil.example", qtype::A);
        let reply = build_refused_response(&q).unwrap();
        let flags = u16::from_be_bytes([reply[2], reply[3]]);
        assert_ne!(flags & FLAG_QR, 0, "QR must be set: {flags:#06x}");
        assert_eq!(flags & 0x000F, RCODE_REFUSED as u16, "RCODE must be REFUSED: {flags:#06x}");
    }

    #[test]
    fn refused_response_preserves_rd_bit() {
        // RD=1 in query → RD=1 in reply. A resolver client expects the bit
        // it asked for to come back set.
        let q = build_query(0x0001, 0x0100, "evil.example", qtype::A);
        let reply = build_refused_response(&q).unwrap();
        let flags = u16::from_be_bytes([reply[2], reply[3]]);
        assert_ne!(flags & 0x0100, 0, "RD must be preserved: {flags:#06x}");
    }

    #[test]
    fn refused_response_clears_answer_counts() {
        let q = build_query(0x0001, 0x0100, "evil.example", qtype::A);
        let reply = build_refused_response(&q).unwrap();
        // QDCOUNT preserved at 1
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 1);
        // ANCOUNT, NSCOUNT, ARCOUNT all 0
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), 0);
        assert_eq!(u16::from_be_bytes([reply[10], reply[11]]), 0);
    }

    #[test]
    fn refused_response_echoes_question_section() {
        // Resolvers cross-check that the question in the reply matches the
        // question they sent. Echo bytes [12..question_section_end] verbatim.
        let q = build_query(0x0001, 0x0100, "evil.example", qtype::A);
        let reply = build_refused_response(&q).unwrap();
        assert_eq!(reply.len(), q.len(), "reply has same length as query");
        assert_eq!(&reply[12..], &q[12..], "question section echoed verbatim");
    }

    #[test]
    fn refused_response_rejects_malformed_query() {
        // Garbage bytes — must surface the parse error rather than panic.
        let bytes = [0u8; 4];
        assert!(matches!(
            build_refused_response(&bytes),
            Err(DnsParseError::TruncatedHeader)
        ));
    }

    #[test]
    fn refused_response_clears_aa_and_ra() {
        // We're not authoritative and we don't recurse. AA (bit 10) and RA
        // (bit 7) must be cleared in the reply even if a misbehaving query
        // had them set.
        let q = build_query(0x0001, 0x0480, "evil.example", qtype::A); // AA + RA set
        let reply = build_refused_response(&q).unwrap();
        let flags = u16::from_be_bytes([reply[2], reply[3]]);
        assert_eq!(flags & 0x0400, 0, "AA must be cleared: {flags:#06x}");
        assert_eq!(flags & 0x0080, 0, "RA must be cleared: {flags:#06x}");
    }

    #[test]
    fn refused_response_preserves_opcode() {
        // OPCODE occupies bits 11..14. We don't change what kind of query
        // the client asked; we just refuse it.
        let opcode_iquery_flags: u16 = 0x0800; // OPCODE=1 (legacy IQUERY)
        let q = build_query(0x0001, opcode_iquery_flags | 0x0100, "evil.example", qtype::A);
        let reply = build_refused_response(&q).unwrap();
        let flags = u16::from_be_bytes([reply[2], reply[3]]);
        assert_eq!(flags & 0x7800, opcode_iquery_flags, "OPCODE must be preserved: {flags:#06x}");
    }

    // ── dns_event_reason ───────────────────────────────────────────────────

    #[test]
    fn dns_event_reason_includes_qtype() {
        let r = dns_event_reason(qtype::AAAA);
        assert!(r.contains("28"), "reason missing qtype: {r:?}");
        let r = dns_event_reason(qtype::A);
        assert!(r.contains("1"), "reason missing qtype: {r:?}");
    }

    // ── slice 10m: handle_dns_query / spawn_dns_listener ───────────────────

    /// Fake resolver: returns canned bytes regardless of input. Used in the
    /// allow-path tests so the handler can be exercised without a live
    /// upstream resolver. The default is empty bytes, which the listener
    /// would happily forward — for tests that care about the wire shape we
    /// override `reply`.
    #[derive(Default, Clone)]
    struct FakeResolver {
        reply: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl DnsResolver for FakeResolver {
        async fn resolve(&self, _query: &[u8]) -> io::Result<Vec<u8>> {
            Ok(self.reply.clone())
        }
    }

    /// Resolver that always fails. Exercises the "upstream unavailable" path
    /// — the handler must return `NoReply` and *not* emit a denial event
    /// (upstream failure is not a policy violation).
    struct FailingResolver;

    #[async_trait::async_trait]
    impl DnsResolver for FailingResolver {
        async fn resolve(&self, _query: &[u8]) -> io::Result<Vec<u8>> {
            Err(io::Error::new(io::ErrorKind::Other, "upstream broken"))
        }
    }

    /// Resolver that records what bytes it was asked to forward. Lets a test
    /// assert that the listener forwards the client's datagram verbatim.
    struct RecordingResolver {
        seen: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
        reply: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl DnsResolver for RecordingResolver {
        async fn resolve(&self, query: &[u8]) -> io::Result<Vec<u8>> {
            self.seen.lock().await.push(query.to_vec());
            Ok(self.reply.clone())
        }
    }

    #[tokio::test]
    async fn handle_allow_returns_resolver_reply_no_event() {
        let p = policy(&["github.com"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let canned = b"upstream reply bytes".to_vec();
        let resolver = FakeResolver { reply: canned.clone() };
        let q = build_query(0x1234, 0x0100, "github.com", qtype::A);

        let outcome = handle_dns_query(&q, &p, &resolver, &tx).await;
        assert_eq!(outcome, DnsHandleOutcome::Reply(canned));
        assert!(rx.try_recv().is_err(), "no denial event for an allowed query");
    }

    #[tokio::test]
    async fn handle_allow_forwards_query_bytes_verbatim() {
        // The whole point of the resolver path: the client's query bytes
        // reach upstream unchanged so the upstream's TXIDs / EDNS / etc.
        // match what the client expects.
        let p = policy(&["github.com"]);
        let (tx, _rx) = mpsc::unbounded_channel();
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let resolver = RecordingResolver {
            seen: seen.clone(),
            reply: Vec::new(),
        };
        let q = build_query(0x1234, 0x0100, "github.com", qtype::A);

        let _ = handle_dns_query(&q, &p, &resolver, &tx).await;
        let observed = seen.lock().await.clone();
        assert_eq!(observed, vec![q]);
    }

    #[tokio::test]
    async fn handle_deny_returns_refused_and_emits_event() {
        let p = policy(&["github.com"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let q = build_query(0xBEEF, 0x0100, "evil.example", qtype::A);

        let outcome = handle_dns_query(&q, &p, &FakeResolver::default(), &tx).await;
        let reply = match outcome {
            DnsHandleOutcome::Reply(bytes) => bytes,
            other => panic!("expected Reply, got {other:?}"),
        };
        assert_eq!(&reply[0..2], &[0xBE, 0xEF], "id must be preserved");
        let flags = u16::from_be_bytes([reply[2], reply[3]]);
        assert_ne!(flags & FLAG_QR, 0, "QR must be set");
        assert_eq!(flags & 0x000F, RCODE_REFUSED as u16);

        let ev = rx.try_recv().expect("denial event");
        assert_eq!(ev.destination, "evil.example");
        assert_eq!(ev.protocol, Protocol::Dns);
        assert!(ev.reason.contains("qtype=1"), "reason should mention qtype: {}", ev.reason);
    }

    #[tokio::test]
    async fn handle_parse_error_is_noreply_no_event() {
        let p = policy(&["github.com"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        // Truncated header: parse fails. Handler must drop the packet rather
        // than try to fabricate a FORMERR from garbage.
        let outcome = handle_dns_query(&[0u8; 4], &p, &FakeResolver::default(), &tx).await;
        assert_eq!(outcome, DnsHandleOutcome::NoReply);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_upstream_failure_is_noreply_no_event() {
        // Upstream resolver is down → guest sees no reply (will time out on
        // its own). This is *not* a policy denial and must not emit an
        // egress_denied event. Mirrors the L7 proxy's 502 path.
        let p = policy(&["github.com"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let q = build_query(0x1234, 0, "github.com", qtype::A);
        let outcome = handle_dns_query(&q, &p, &FailingResolver, &tx).await;
        assert_eq!(outcome, DnsHandleOutcome::NoReply);
        assert!(rx.try_recv().is_err(), "upstream failure is not a policy denial");
    }

    #[tokio::test]
    async fn handle_multi_question_attributes_to_first_denied() {
        // 2-question query: github.com (allowed) + evil.example (denied).
        // The handler must report the violator (the unlisted name), not the
        // allowed name that happens to come first in the packet.
        let p = policy(&["github.com"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut q = Vec::new();
        q.extend_from_slice(&0x0001u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&2u16.to_be_bytes()); // QDCOUNT=2
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend(encode_name("github.com"));
        q.extend_from_slice(&qtype::A.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());
        q.extend(encode_name("evil.example"));
        q.extend_from_slice(&qtype::AAAA.to_be_bytes());
        q.extend_from_slice(&QCLASS_IN.to_be_bytes());

        let _ = handle_dns_query(&q, &p, &FakeResolver::default(), &tx).await;
        let ev = rx.try_recv().expect("denial event");
        assert_eq!(ev.destination, "evil.example");
        assert!(
            ev.reason.contains("qtype=28"),
            "reason should mention AAAA: {}",
            ev.reason
        );
    }

    #[tokio::test]
    async fn spawn_dns_listener_deny_path_loopback() {
        let p = policy(&["github.com"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (bound, h) = spawn_dns_listener(
            "127.0.0.1:0".parse().unwrap(),
            p,
            FakeResolver::default(),
            tx,
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(bound).await.unwrap();
        let q = build_query(0xCAFE, 0x0100, "evil.example", qtype::A);
        client.send(&q).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("listener should reply within timeout")
            .unwrap();
        buf.truncate(n);

        assert_eq!(&buf[0..2], &[0xCA, 0xFE], "id preserved");
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(flags & 0x000F, RCODE_REFUSED as u16);

        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("denial event should arrive")
            .expect("channel still open");
        assert_eq!(ev.destination, "evil.example");
        assert_eq!(ev.protocol, Protocol::Dns);

        h.abort();
    }

    #[tokio::test]
    async fn spawn_dns_listener_allow_path_loopback() {
        let p = policy(&["allowed.example"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let canned = b"\x00\x01canned-upstream-reply".to_vec();
        let resolver = FakeResolver { reply: canned.clone() };
        let (bound, h) = spawn_dns_listener(
            "127.0.0.1:0".parse().unwrap(),
            p,
            resolver,
            tx,
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(bound).await.unwrap();
        let q = build_query(0xAAAA, 0x0100, "allowed.example", qtype::A);
        client.send(&q).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("listener should reply within timeout")
            .unwrap();
        buf.truncate(n);
        assert_eq!(buf, canned, "allowed reply forwarded verbatim from resolver");
        assert!(rx.try_recv().is_err(), "no denial event for an allowed query");

        h.abort();
    }

    #[tokio::test]
    async fn spawn_dns_listener_drops_malformed_silently() {
        // Junk that can't possibly be a DNS query must not get a reply nor
        // emit an event. Tests the "drop silently" semantics — the client's
        // recv times out, not the test runner.
        let p = policy(&["github.com"]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (bound, h) = spawn_dns_listener(
            "127.0.0.1:0".parse().unwrap(),
            p,
            FakeResolver::default(),
            tx,
        )
        .await
        .unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(bound).await.unwrap();
        client.send(b"not a dns query").await.unwrap();

        let mut buf = vec![0u8; 512];
        let resp = tokio::time::timeout(Duration::from_millis(300), client.recv(&mut buf)).await;
        assert!(resp.is_err(), "listener must not reply to garbage");
        assert!(rx.try_recv().is_err(), "no event for garbage");

        h.abort();
    }
}
