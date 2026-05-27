use serde::Serialize;

pub const SCHEMA_VERSION: u32 = 1;
pub const BUNSEN_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Serialize)]
pub struct Envelope {
    pub schema_version: u32,
    pub run_id: String,
    pub seq: u64,
    pub ts: String,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(flatten)]
    pub payload: serde_json::Value,
}

impl Envelope {
    pub fn new(run_id: &str, seq: u64, event_type: &str, payload: serde_json::Value) -> Self {
        Envelope {
            schema_version: SCHEMA_VERSION,
            run_id: run_id.to_string(),
            seq,
            ts: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            event_type: event_type.to_string(),
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_has_all_required_fields() {
        let env = Envelope::new("TESTID", 0, "run_started", json!({"adapter": "black-box"}));
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["run_id"], "TESTID");
        assert_eq!(v["seq"], 0);
        assert!(v["ts"].as_str().unwrap().contains('T'));
        assert_eq!(v["type"], "run_started");
        assert_eq!(v["adapter"], "black-box");
    }

    #[test]
    fn envelope_type_field_not_duplicated() {
        let env = Envelope::new("X", 1, "output", json!({"stream": "stdout", "text": "hi"}));
        let s = serde_json::to_string(&env).unwrap();
        let count = s.matches("\"type\"").count();
        assert_eq!(count, 1, "type field duplicated: {s}");
    }
}
