use std::io::{self, BufWriter, Write};
use std::fs::OpenOptions;
use std::path::Path;
use serde_json::Value;
use crate::events::Envelope;

pub struct Encoder {
    run_id: String,
    seq: u64,
    transcript: BufWriter<std::fs::File>,
}

impl Encoder {
    pub fn new(run_id: &str, transcript_path: &Path) -> io::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(transcript_path)?;
        Ok(Encoder {
            run_id: run_id.to_string(),
            seq: 0,
            transcript: BufWriter::new(f),
        })
    }

    pub fn emit(&mut self, event_type: &str, payload: Value) -> io::Result<()> {
        let env = Envelope::new(&self.run_id, self.seq, event_type, payload);
        self.seq += 1;

        let line = serde_json::to_string(&env).unwrap();

        // Emit to stdout
        let stdout = io::stdout();
        let mut out = stdout.lock();
        writeln!(out, "{}", line)?;
        out.flush()?;

        // Mirror to transcript (byte-equal)
        writeln!(self.transcript, "{}", line)?;
        self.transcript.flush()?;

        Ok(())
    }
}
