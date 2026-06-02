#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde_json::{json, Value};

/// Declared egress endpoints required by the Claude Code adapter.
pub const EGRESS_ENDPOINTS: &[&str] = &["api.anthropic.com"];

pub struct ClaudeCodeParser {
    turn_counter: u32,
    last_model: Option<String>,
}

impl ClaudeCodeParser {
    pub fn new() -> Self {
        ClaudeCodeParser { turn_counter: 0, last_model: None }
    }

    /// Parse one line of claude-code stream-json output.
    /// Returns a list of (event_type, payload) pairs to emit via Encoder.
    pub fn parse_line(&mut self, line: &str) -> Vec<(String, Value)> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return vec![];
        }

        let v: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return vec![("output".into(), json!({"stream": "stdout", "text": line}))],
        };

        match v.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "assistant" => self.parse_assistant(&v),
            "user" => self.parse_user(&v),
            "result" => self.parse_result(&v),
            // All other well-formed protocol JSON (system, rate_limit_event, …)
            // is silently dropped. Only non-JSON lines become raw output events
            // so banner text and progress lines still surface.
            _ => vec![],
        }
    }

    fn parse_assistant(&mut self, v: &Value) -> Vec<(String, Value)> {
        let mut events = vec![];

        self.turn_counter += 1;
        let turn_id = self.turn_counter;

        events.push(("turn_start".into(), json!({"turn_id": turn_id})));

        let message = match v.get("message") {
            Some(m) => m,
            None => {
                events.push(("turn_end".into(), json!({"turn_id": turn_id})));
                return events;
            }
        };

        if let Some(model) = message.get("model").and_then(|m| m.as_str()) {
            self.last_model = Some(model.to_string());
        }

        if let Some(content) = message.get("content").and_then(|c| c.as_array()) {
            for block in content {
                if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    if let (Some(id), Some(name)) = (
                        block.get("id").and_then(|v| v.as_str()),
                        block.get("name").and_then(|v| v.as_str()),
                    ) {
                        let input = block.get("input").cloned().unwrap_or(Value::Null);
                        events.push(("tool_call".into(), json!({
                            "tool_call_id": id,
                            "name": name,
                            "input": input,
                        })));
                    }
                }
            }
        }

        let mut end_payload = json!({"turn_id": turn_id});
        if let Some(model) = message.get("model").and_then(|m| m.as_str()) {
            end_payload["model"] = json!(model);
        }
        if let Some(stop_reason) = message.get("stop_reason").and_then(|r| r.as_str()) {
            end_payload["stop_reason"] = json!(stop_reason);
        }
        events.push(("turn_end".into(), end_payload));

        events
    }

    fn parse_user(&self, v: &Value) -> Vec<(String, Value)> {
        let mut events = vec![];

        let content = v
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array());

        let content = match content {
            Some(c) => c,
            None => return events,
        };

        for block in content {
            if block.get("type").and_then(|t| t.as_str()) != Some("tool_result") {
                continue;
            }
            let tool_use_id = match block.get("tool_use_id").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => continue,
            };
            let content_str = extract_tool_result_content(block);
            let is_error = block.get("is_error").and_then(|v| v.as_bool()).unwrap_or(false);
            events.push(("tool_result".into(), json!({
                "tool_call_id": tool_use_id,
                "content": content_str,
                "is_error": is_error,
            })));
        }

        events
    }

    fn parse_result(&self, v: &Value) -> Vec<(String, Value)> {
        let usage = match v.get("usage") {
            Some(u) => u,
            None => return vec![],
        };

        let input_tokens = usage.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        let output_tokens = usage.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        let cache_read = usage.get("cache_read_input_tokens").and_then(|v| v.as_u64());
        let cache_write = usage.get("cache_creation_input_tokens").and_then(|v| v.as_u64());
        let cost_usd = v.get("total_cost_usd").and_then(|v| v.as_f64());

        let mut payload = json!({
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        });
        if let Some(model) = &self.last_model {
            payload["model"] = json!(model);
        }
        if let Some(cr) = cache_read {
            payload["cache_read_tokens"] = json!(cr);
        }
        if let Some(cw) = cache_write {
            payload["cache_write_tokens"] = json!(cw);
        }
        if let Some(cost) = cost_usd {
            payload["cost_usd"] = json!(cost);
        }

        vec![("model_usage".into(), payload)]
    }
}

fn extract_tool_result_content(block: &Value) -> String {
    match block.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fixture() -> Vec<(String, Value)> {
        let fixture = include_str!("testdata/claude_code_fixture.ndjson");
        let mut parser = ClaudeCodeParser::new();
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
            &["turn_start", "tool_call", "turn_end", "tool_result", "turn_start", "turn_end", "model_usage"]
        );
    }

    #[test]
    fn tool_call_has_correct_id_and_name() {
        let events = parse_fixture();
        let (_, payload) = events.iter().find(|(t, _)| t == "tool_call").unwrap();
        assert_eq!(payload["tool_call_id"], "toolu_001");
        assert_eq!(payload["name"], "Bash");
        assert_eq!(payload["input"]["command"], "ls /workspace");
    }

    #[test]
    fn tool_result_pairs_with_call() {
        let events = parse_fixture();
        let (_, payload) = events.iter().find(|(t, _)| t == "tool_result").unwrap();
        assert_eq!(payload["tool_call_id"], "toolu_001");
        assert!(payload["content"].as_str().unwrap().contains("file1.txt"));
        assert_eq!(payload["is_error"], false);
    }

    #[test]
    fn model_usage_has_token_counts() {
        let events = parse_fixture();
        let (_, payload) = events.iter().find(|(t, _)| t == "model_usage").unwrap();
        assert_eq!(payload["input_tokens"], 300);
        assert_eq!(payload["output_tokens"], 67);
        assert_eq!(payload["cache_read_tokens"], 60);
        assert_eq!(payload["cache_write_tokens"], 0);
        assert!((payload["cost_usd"].as_f64().unwrap() - 0.00215).abs() < 1e-9);
        assert_eq!(payload["model"], "claude-opus-4-5");
    }

    #[test]
    fn non_json_line_becomes_output_event() {
        let mut parser = ClaudeCodeParser::new();
        let events = parser.parse_line("Claude Code 1.2.3 — banner text");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "output");
        assert_eq!(events[0].1["stream"], "stdout");
        assert!(events[0].1["text"].as_str().unwrap().contains("banner text"));
    }

    #[test]
    fn system_init_line_is_ignored() {
        let mut parser = ClaudeCodeParser::new();
        let line = r#"{"type":"system","subtype":"init","session_id":"x","tools":[],"model":"claude-opus-4-5"}"#;
        let events = parser.parse_line(line);
        assert!(events.is_empty());
    }

    #[test]
    fn unknown_json_type_is_silently_ignored() {
        let mut parser = ClaudeCodeParser::new();
        let line = r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed"},"uuid":"abc","session_id":"s"}"#;
        let events = parser.parse_line(line);
        assert!(events.is_empty());
    }

    #[test]
    fn turn_end_carries_model_and_stop_reason() {
        let events = parse_fixture();
        let turn_ends: Vec<_> = events.iter().filter(|(t, _)| t == "turn_end").collect();
        // First turn ends with stop_reason "tool_use"
        assert_eq!(turn_ends[0].1["stop_reason"], "tool_use");
        assert_eq!(turn_ends[0].1["model"], "claude-opus-4-5");
        // Second turn ends with stop_reason "end_turn"
        assert_eq!(turn_ends[1].1["stop_reason"], "end_turn");
    }

    #[test]
    fn egress_endpoints_declared() {
        assert!(EGRESS_ENDPOINTS.contains(&"api.anthropic.com"));
    }

    #[test]
    fn empty_line_produces_no_events() {
        let mut parser = ClaudeCodeParser::new();
        assert!(parser.parse_line("").is_empty());
        assert!(parser.parse_line("   ").is_empty());
    }
}
