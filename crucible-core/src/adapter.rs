use serde_json::{json, Value};

/// Convert raw bytes from an agent's stdout/stderr into event payloads.
pub struct BlackBoxAdapter;

impl BlackBoxAdapter {
    pub fn output_event(stream: &str, bytes: &[u8]) -> Value {
        let text = String::from_utf8_lossy(bytes).into_owned();
        json!({"stream": stream, "text": text})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_bytes_become_output_event() {
        let payload = BlackBoxAdapter::output_event("stdout", b"hello\n");
        assert_eq!(payload["stream"], "stdout");
        assert_eq!(payload["text"], "hello\n");
    }

    #[test]
    fn stderr_bytes_become_output_event() {
        let payload = BlackBoxAdapter::output_event("stderr", b"error msg");
        assert_eq!(payload["stream"], "stderr");
        assert_eq!(payload["text"], "error msg");
    }

    #[test]
    fn non_utf8_bytes_are_lossily_decoded() {
        let bytes = b"ok\xff\xfe";
        let payload = BlackBoxAdapter::output_event("stdout", bytes);
        let text = payload["text"].as_str().unwrap();
        assert!(text.contains("ok"));
    }
}
