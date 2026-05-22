use std::collections::HashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

pub struct Redactor {
    ac: AhoCorasick,
    replacements: Vec<Vec<u8>>,
    pending: Vec<u8>,
    max_pattern_len: usize,
}

#[derive(Debug)]
pub struct RedactorError(String);

impl std::fmt::Display for RedactorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RedactorError {}

impl Redactor {
    pub fn new(secrets: HashMap<String, String>) -> Result<Self, RedactorError> {
        for (name, value) in &secrets {
            if value.is_empty() {
                return Err(RedactorError(format!("secret '{}' has empty value", name)));
            }
        }

        let mut entries: Vec<(String, String)> = secrets.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let patterns: Vec<&[u8]> = entries.iter().map(|(_, v)| v.as_bytes()).collect();
        let replacements: Vec<Vec<u8>> = entries
            .iter()
            .map(|(name, _)| format!("<redacted:{}>", name).into_bytes())
            .collect();

        let max_pattern_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);

        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(|e| RedactorError(e.to_string()))?;

        Ok(Redactor {
            ac,
            replacements,
            pending: Vec::new(),
            max_pattern_len,
        })
    }

    /// Redact registered secrets from `input`, returning sanitised bytes.
    /// Streaming-safe: partial matches at the end of a buffer are held in an
    /// internal pending buffer and flushed on the next call (or via `flush`).
    pub fn redact(&mut self, input: &[u8]) -> Vec<u8> {
        if self.max_pattern_len == 0 {
            return input.to_vec();
        }

        let mut combined = std::mem::take(&mut self.pending);
        combined.extend_from_slice(input);

        let mut output = Vec::with_capacity(combined.len());
        let mut pos = 0;

        for mat in self.ac.find_iter(&combined) {
            output.extend_from_slice(&combined[pos..mat.start()]);
            output.extend_from_slice(&self.replacements[mat.pattern().as_usize()]);
            pos = mat.end();
        }

        let tail = &combined[pos..];
        // Retain the last (max_pattern_len - 1) bytes to handle secrets that
        // straddle the boundary between consecutive calls.
        let safe_len = tail.len().saturating_sub(self.max_pattern_len - 1);
        output.extend_from_slice(&tail[..safe_len]);
        self.pending = tail[safe_len..].to_vec();

        output
    }

    /// Emit any bytes held in the pending buffer. Call after the final `redact`
    /// invocation to ensure the output is complete.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor(secrets: &[(&str, &str)]) -> Redactor {
        let map = secrets
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Redactor::new(map).unwrap()
    }

    // --- Cycle 1: empty value rejected ---

    #[test]
    fn empty_secret_value_is_rejected() {
        let mut m = HashMap::new();
        m.insert("KEY".to_string(), "".to_string());
        assert!(Redactor::new(m).is_err());
    }

    // --- Cycle 2: simple redaction in the middle ---

    #[test]
    fn redacts_secret_in_middle() {
        let mut r = redactor(&[("API_KEY", "sk-abc123")]);
        let out = r.redact(b"prefix sk-abc123 suffix");
        let pending = r.flush();
        let combined = [out, pending].concat();
        assert_eq!(combined, b"prefix <redacted:API_KEY> suffix");
    }

    // --- Cycle 3: secret at start of buffer ---

    #[test]
    fn redacts_secret_at_start() {
        let mut r = redactor(&[("KEY", "secret")]);
        let out = r.redact(b"secret world");
        let pending = r.flush();
        let combined = [out, pending].concat();
        assert_eq!(combined, b"<redacted:KEY> world");
    }

    // --- Cycle 4: secret at end of buffer ---

    #[test]
    fn redacts_secret_at_end() {
        let mut r = redactor(&[("KEY", "secret")]);
        let out = r.redact(b"hello secret");
        let pending = r.flush();
        let combined = [out, pending].concat();
        assert_eq!(combined, b"hello <redacted:KEY>");
    }

    // --- Cycle 5: secret split across two consecutive calls ---

    #[test]
    fn handles_secret_split_across_two_calls() {
        let mut r = redactor(&[("KEY", "secret")]);
        // "secret" (6 bytes) — split as "sec" | "ret"
        let part1 = r.redact(b"hello sec");
        let part2 = r.redact(b"ret world");
        let pending = r.flush();
        let result = [part1, part2, pending].concat();
        assert_eq!(result, b"hello <redacted:KEY> world");
    }

    // --- Cycle 6: two distinct secrets in the same buffer ---

    #[test]
    fn redacts_two_secrets_in_same_buffer() {
        let mut r = redactor(&[("FOO", "alpha"), ("BAR", "beta")]);
        let out = r.redact(b"alpha and beta");
        let pending = r.flush();
        let combined = [out, pending].concat();
        assert_eq!(combined, b"<redacted:FOO> and <redacted:BAR>");
    }

    // --- Cycle 7: overlapping patterns — longer match wins ---

    #[test]
    fn overlapping_patterns_longer_wins() {
        let mut r = redactor(&[("SHORT", "aaa"), ("LONG", "aaaa")]);
        let out = r.redact(b"aaaa");
        let pending = r.flush();
        let combined = [out, pending].concat();
        // LeftmostLongest: "aaaa" matches over "aaa"
        assert_eq!(combined, b"<redacted:LONG>");
    }
}
