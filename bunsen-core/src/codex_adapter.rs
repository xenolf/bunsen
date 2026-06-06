#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashSet;
use serde_json::{json, Value};

/// OCI image that provides the codex runtime environment (Node.js + @openai/codex).
/// Built from adapters/codex/Dockerfile on top of bunsen-base.
// TODO(oci): pin digest once image is published
pub const OCI_IMAGE: &str =
    "ghcr.io/xenolf/bunsen/bunsen-adapter-codex@sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Declared egress endpoints required by the codex adapter.
pub const EGRESS_ENDPOINTS: &[&str] = &["api.openai.com"];

pub struct CodexParser {
    turn_counter: u32,
    last_model: Option<String>,
    /// Item ids for which a `tool_call` event has already been emitted.
    /// Ensures exactly one `tool_call` per item id even when `item.started`
    /// and `item.completed` both arrive, or when only `item.completed` arrives.
    tool_call_emitted: HashSet<String>,
}

impl CodexParser {
    pub fn new() -> Self {
        CodexParser {
            turn_counter: 0,
            last_model: None,
            tool_call_emitted: HashSet::new(),
        }
    }

    /// Parse one line of codex `--json` JSONL output.
    pub fn parse_line(&mut self, line: &str) -> Vec<(String, Value)> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return vec![];
        }

        let v: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return vec![("output".into(), json!({"stream": "stdout", "text": line}))],
        };

        // Capture a model name from any event that carries one at the top level.
        if let Some(model) = v.get("model").and_then(|m| m.as_str()) {
            self.last_model = Some(model.to_string());
        }

        match v.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "thread.started" => {
                vec![("output".into(), json!({"stream": "stdout", "text": line}))]
            }
            "turn.started" => {
                self.turn_counter += 1;
                vec![("turn_start".into(), json!({"turn_id": self.turn_counter}))]
            }
            "item.started" => self.handle_item_started(&v),
            "item.completed" => self.handle_item_completed(&v),
            "turn.completed" => self.handle_turn_completed(&v),
            // turn.failed, error, and any unrecognised event type.
            _ => vec![("output".into(), json!({"stream": "stdout", "text": line}))],
        }
    }

    fn handle_item_started(&mut self, v: &Value) -> Vec<(String, Value)> {
        let item = match v.get("item") {
            Some(i) => i,
            None => return vec![],
        };
        let item_id = match item.get("id").and_then(|id| id.as_str()) {
            Some(s) => s.to_string(),
            None => return vec![],
        };
        let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match item_type {
            "reasoning" | "agent_message" => vec![],
            _ => {
                if self.tool_call_emitted.contains(&item_id) {
                    return vec![];
                }
                let input = build_tool_input(item);
                self.tool_call_emitted.insert(item_id.clone());
                vec![("tool_call".into(), json!({
                    "tool_call_id": item_id,
                    "name": item_type,
                    "input": input,
                }))]
            }
        }
    }

    fn handle_item_completed(&mut self, v: &Value) -> Vec<(String, Value)> {
        let item = match v.get("item") {
            Some(i) => i,
            None => return vec![],
        };
        let item_id = match item.get("id").and_then(|id| id.as_str()) {
            Some(s) => s.to_string(),
            None => return vec![],
        };
        let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");

        match item_type {
            "reasoning" => vec![],
            "agent_message" => {
                let text = item.get("text").and_then(|t| t.as_str()).unwrap_or("");
                vec![("output".into(), json!({"stream": "agent", "text": text}))]
            }
            _ => {
                let mut events = vec![];
                // Emit tool_call first if item.started was absent (pairing robustness).
                if !self.tool_call_emitted.contains(&item_id) {
                    let input = build_tool_input(item);
                    self.tool_call_emitted.insert(item_id.clone());
                    events.push(("tool_call".into(), json!({
                        "tool_call_id": item_id,
                        "name": item_type,
                        "input": input,
                    })));
                }
                let content = extract_item_output(item);
                events.push(("tool_result".into(), json!({
                    "tool_call_id": item_id,
                    "content": content,
                })));
                events
            }
        }
    }

    fn handle_turn_completed(&self, v: &Value) -> Vec<(String, Value)> {
        let turn_id = self.turn_counter;
        let mut events = vec![];

        let mut end_payload = json!({"turn_id": turn_id});
        if let Some(model) = &self.last_model {
            end_payload["model"] = json!(model);
        }
        events.push(("turn_end".into(), end_payload));

        if let Some(usage) = v.get("usage") {
            let input_tokens = usage.get("input_tokens").and_then(|n| n.as_u64()).unwrap_or(0);
            let output_tokens = usage.get("output_tokens").and_then(|n| n.as_u64()).unwrap_or(0);
            let reasoning_tokens = usage.get("reasoning_output_tokens").and_then(|n| n.as_u64()).unwrap_or(0);
            let total_output = output_tokens + reasoning_tokens;
            let cache_read = usage.get("cached_input_tokens").and_then(|n| n.as_u64());

            let mut payload = json!({
                "input_tokens": input_tokens,
                "output_tokens": total_output,
            });
            if let Some(model) = &self.last_model {
                payload["model"] = json!(model);
            }
            if let Some(cr) = cache_read {
                payload["cache_read_tokens"] = json!(cr);
            }
            events.push(("model_usage".into(), payload));
        }

        events
    }
}

/// Build the `input` value for a `tool_call` event from an item object,
/// excluding the `id` and `type` fields (which are surfaced as `tool_call_id`
/// and `name` respectively).
fn build_tool_input(item: &Value) -> Value {
    match item.as_object() {
        Some(map) => {
            let filtered: serde_json::Map<String, Value> = map
                .iter()
                .filter(|(k, _)| k.as_str() != "id" && k.as_str() != "type")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            Value::Object(filtered)
        }
        None => Value::Null,
    }
}

/// Extract the output/result content from a completed item.
fn extract_item_output(item: &Value) -> String {
    if let Some(s) = item.get("output").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(s) = item.get("text").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fixture() -> Vec<(String, Value)> {
        let fixture = include_str!("testdata/codex_fixture.ndjson");
        let mut parser = CodexParser::new();
        fixture
            .lines()
            .flat_map(|line| parser.parse_line(line))
            .collect()
    }

    fn event_types(events: &[(String, Value)]) -> Vec<&str> {
        events.iter().map(|(t, _)| t.as_str()).collect()
    }

    #[test]
    fn fixture_produces_expected_event_sequence() {
        let events = parse_fixture();
        assert_eq!(
            event_types(&events),
            &[
                "output",     // thread.started → stdout
                "turn_start",
                "tool_call",  // item.started command_execution
                "tool_result",
                "output",     // item.completed agent_message → stream: "agent"
                "turn_end",
                "model_usage",
            ]
        );
    }

    #[test]
    fn tool_call_has_correct_id_and_name() {
        let events = parse_fixture();
        let (_, payload) = events.iter().find(|(t, _)| t == "tool_call").unwrap();
        assert_eq!(payload["tool_call_id"], "item_001");
        assert_eq!(payload["name"], "command_execution");
    }

    #[test]
    fn reasoning_output_tokens_folded_into_output_tokens() {
        let events = parse_fixture();
        let (_, payload) = events.iter().find(|(t, _)| t == "model_usage").unwrap();
        // fixture: output_tokens=25, reasoning_output_tokens=10 → total 35
        assert_eq!(payload["output_tokens"], 35);
        assert_eq!(payload["input_tokens"], 150);
    }

    #[test]
    fn cache_read_tokens_maps_from_cached_input_tokens() {
        let events = parse_fixture();
        let (_, payload) = events.iter().find(|(t, _)| t == "model_usage").unwrap();
        assert_eq!(payload["cache_read_tokens"], 50);
    }

    #[test]
    fn agent_message_produces_output_not_tool_call() {
        let events = parse_fixture();
        // The agent_message item (item_002) must produce an output event with stream "agent".
        let agent_outputs: Vec<_> = events
            .iter()
            .filter(|(t, v)| t == "output" && v["stream"] == "agent")
            .collect();
        assert_eq!(agent_outputs.len(), 1);
        assert_eq!(
            agent_outputs[0].1["text"],
            "The workspace contains file1.txt and file2.py."
        );
        // No tool_call should reference the agent_message item id.
        for (t, payload) in &events {
            if t == "tool_call" {
                assert_ne!(payload["tool_call_id"], "item_002", "agent_message must not produce tool_call");
            }
        }
    }

    #[test]
    fn reasoning_items_produce_no_events() {
        let mut parser = CodexParser::new();
        let started = r#"{"type":"item.started","item":{"id":"r_001","type":"reasoning","text":"thinking..."}}"#;
        let completed = r#"{"type":"item.completed","item":{"id":"r_001","type":"reasoning","summary":"done"}}"#;
        assert!(parser.parse_line(started).is_empty(), "item.started reasoning must produce no events");
        assert!(parser.parse_line(completed).is_empty(), "item.completed reasoning must produce no events");
    }

    #[test]
    fn tool_call_emitted_when_item_started_absent() {
        // Pairing robustness: only item.completed arrives; tool_call must still precede tool_result.
        let mut parser = CodexParser::new();
        let _ = parser.parse_line(r#"{"type":"turn.started","turn_id":"t1"}"#);
        let events = parser.parse_line(
            r#"{"type":"item.completed","item":{"id":"orphan_001","type":"file_read","path":"/etc/hosts","output":"127.0.0.1 localhost\n"}}"#,
        );
        assert_eq!(event_types(&events), &["tool_call", "tool_result"]);
        assert_eq!(events[0].1["tool_call_id"], "orphan_001");
        assert_eq!(events[1].1["tool_call_id"], "orphan_001");
    }

    #[test]
    fn tool_call_not_duplicated_when_item_started_and_completed_both_arrive() {
        let mut parser = CodexParser::new();
        let _ = parser.parse_line(r#"{"type":"turn.started","turn_id":"t1"}"#);
        let started_events = parser.parse_line(
            r#"{"type":"item.started","item":{"id":"cmd_001","type":"command_execution","command":"pwd"}}"#,
        );
        assert_eq!(started_events.len(), 1);
        assert_eq!(started_events[0].0, "tool_call");

        let completed_events = parser.parse_line(
            r#"{"type":"item.completed","item":{"id":"cmd_001","type":"command_execution","command":"pwd","output":"/workspace\n"}}"#,
        );
        // Only tool_result, not another tool_call.
        assert_eq!(event_types(&completed_events), &["tool_result"]);
        assert_eq!(completed_events[0].1["tool_call_id"], "cmd_001");
    }

    #[test]
    fn model_captured_from_turn_started_and_surfaced_in_model_usage() {
        let mut parser = CodexParser::new();
        let _ = parser.parse_line(r#"{"type":"turn.started","turn_id":"t1","model":"codex-4"}"#);
        let events = parser.parse_line(
            r#"{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":5,"reasoning_output_tokens":0,"cached_input_tokens":0}}"#,
        );
        let (_, payload) = events.iter().find(|(t, _)| t == "model_usage").unwrap();
        assert_eq!(payload["model"], "codex-4");
    }

    #[test]
    fn thread_started_emits_stdout_output() {
        let mut parser = CodexParser::new();
        let events = parser.parse_line(r#"{"type":"thread.started","thread_id":"t1"}"#);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "output");
        assert_eq!(events[0].1["stream"], "stdout");
    }

    #[test]
    fn unrecognised_event_type_emits_stdout_output() {
        let mut parser = CodexParser::new();
        let events = parser.parse_line(r#"{"type":"turn.failed","error":"something went wrong"}"#);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "output");
        assert_eq!(events[0].1["stream"], "stdout");
    }

    #[test]
    fn non_json_line_emits_stdout_output() {
        let mut parser = CodexParser::new();
        let events = parser.parse_line("codex 1.2.3 — banner text");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "output");
        assert_eq!(events[0].1["stream"], "stdout");
        assert!(events[0].1["text"].as_str().unwrap().contains("banner text"));
    }

    #[test]
    fn empty_line_produces_no_events() {
        let mut parser = CodexParser::new();
        assert!(parser.parse_line("").is_empty());
        assert!(parser.parse_line("   ").is_empty());
    }

    #[test]
    fn egress_endpoints_declared() {
        assert!(EGRESS_ENDPOINTS.contains(&"api.openai.com"));
    }
}
