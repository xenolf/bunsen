use std::io::{self, BufWriter, Write};
use std::fs::OpenOptions;
use std::path::Path;
use serde_json::Value;
use crate::events::Envelope;
use crate::redactor::Redactor;

pub struct Encoder {
    run_id: String,
    seq: u64,
    transcript: BufWriter<std::fs::File>,
    redactor: Option<Redactor>,
}

impl Encoder {
    pub fn new(run_id: &str, transcript_path: &Path, redactor: Option<Redactor>) -> io::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(transcript_path)?;
        Ok(Encoder {
            run_id: run_id.to_string(),
            seq: 0,
            transcript: BufWriter::new(f),
            redactor,
        })
    }

    pub fn emit(&mut self, event_type: &str, payload: Value) -> io::Result<()> {
        let env = Envelope::new(&self.run_id, self.seq, event_type, payload);
        self.seq += 1;

        // Include the newline in the redacted bytes so the pending tail is
        // always flushed at line boundaries (JSON strings escape literal
        // newlines, so no secret can straddle a line boundary in practice).
        let line = format!("{}\n", serde_json::to_string(&env).unwrap());
        let bytes: &[u8] = line.as_bytes();

        let (redacted, pending) = match self.redactor.as_mut() {
            Some(r) => {
                let out = r.redact(bytes);
                let tail = r.flush();
                (out, tail)
            }
            None => (bytes.to_vec(), Vec::new()),
        };

        let stdout = io::stdout();
        let mut out = stdout.lock();
        out.write_all(&redacted)?;
        out.write_all(&pending)?;
        out.flush()?;

        self.transcript.write_all(&redacted)?;
        self.transcript.write_all(&pending)?;
        self.transcript.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;
    use tempfile::NamedTempFile;

    fn make_redactor(secrets: &[(&str, &str)]) -> Redactor {
        let map: HashMap<String, String> = secrets
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Redactor::new(map).unwrap()
    }

    #[test]
    fn encoder_redacts_secret_in_emitted_event() {
        let tmp = NamedTempFile::new().unwrap();
        let r = make_redactor(&[("API_KEY", "sk-abc123")]);
        let mut enc = Encoder::new("TEST01", tmp.path(), Some(r)).unwrap();
        enc.emit("output", serde_json::json!({"stream": "stdout", "text": "sk-abc123"}))
            .unwrap();

        let mut content = String::new();
        std::fs::File::open(tmp.path())
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        assert!(
            !content.contains("sk-abc123"),
            "raw secret must not appear in transcript"
        );
        assert!(
            content.contains("<redacted:API_KEY>"),
            "redacted placeholder must appear in transcript"
        );
    }
}
