#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde_json::{json, Value};

/// Accumulated model_usage across all turns in a session.
#[derive(Default)]
struct SessionAccumulator {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    cost_usd: f64,
    model: Option<String>,
}

pub struct PiParser {
    turn_counter: u32,
    accumulator: SessionAccumulator,
}

impl PiParser {
    pub fn new() -> Self {
        PiParser {
            turn_counter: 0,
            accumulator: SessionAccumulator::default(),
        }
    }

    /// Parse one line of pi `--mode json` JSONL output.
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
            "turn_start" => {
                self.turn_counter += 1;
                vec![("turn_start".into(), json!({"turn_id": self.turn_counter}))]
            }
            "tool_execution_start" => self.parse_tool_execution_start(&v),
            "tool_execution_end" => self.parse_tool_execution_end(&v),
            "turn_end" => self.parse_turn_end(&v),
            "agent_end" => self.emit_session_usage(),
            // Silently dropped — internal session/message lifecycle events.
            "session" | "agent_start" | "message_start" | "message_update" | "message_end" => {
                vec![]
            }
            // Passthrough — operational events the user may want to inspect.
            "compaction_start"
            | "compaction_end"
            | "auto_retry_start"
            | "auto_retry_end"
            | "queue_update" => {
                vec![("output".into(), json!({"stream": "stdout", "text": trimmed}))]
            }
            // Unknown well-formed JSON: silently drop (not surfaced as output
            // so banner/progress text doesn't pollute the event stream — only
            // non-JSON lines become raw output events).
            _ => vec![],
        }
    }

    fn parse_tool_execution_start(&self, v: &Value) -> Vec<(String, Value)> {
        let tool_call_id = match v.get("toolCallId").and_then(|id| id.as_str()) {
            Some(id) => id,
            None => return vec![],
        };
        let name = match v.get("toolName").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => return vec![],
        };
        let input = v.get("args").cloned().unwrap_or(Value::Null);
        vec![("tool_call".into(), json!({
            "tool_call_id": tool_call_id,
            "name": name,
            "input": input,
        }))]
    }

    fn parse_tool_execution_end(&self, v: &Value) -> Vec<(String, Value)> {
        let tool_call_id = match v.get("toolCallId").and_then(|id| id.as_str()) {
            Some(id) => id,
            None => return vec![],
        };
        // result may be a string or a structured JSON value; contract requires string content.
        let content = match v.get("result") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => serde_json::to_string(other).unwrap_or_default(),
            None => String::new(),
        };
        let is_error = v.get("isError").and_then(|e| e.as_bool()).unwrap_or(false);
        vec![("tool_result".into(), json!({
            "tool_call_id": tool_call_id,
            "content": content,
            "is_error": is_error,
        }))]
    }

    fn parse_turn_end(&mut self, v: &Value) -> Vec<(String, Value)> {
        let turn_id = self.turn_counter;
        let mut events = vec![];

        let message = v.get("message");
        let model = message.and_then(|m| m.get("model")).and_then(|m| m.as_str());
        let stop_reason = message.and_then(|m| m.get("stopReason")).and_then(|r| r.as_str());

        let mut end_payload = json!({"turn_id": turn_id});
        if let Some(m) = model {
            end_payload["model"] = json!(m);
        }
        if let Some(r) = stop_reason {
            end_payload["stop_reason"] = json!(r);
        }
        events.push(("turn_end".into(), end_payload));

        if let Some(usage) = message.and_then(|m| m.get("usage")) {
            let input = usage.get("input").and_then(|n| n.as_u64()).unwrap_or(0);
            let output = usage.get("output").and_then(|n| n.as_u64()).unwrap_or(0);
            let cache_read = usage.get("cacheRead").and_then(|n| n.as_u64()).unwrap_or(0);
            let cache_write = usage.get("cacheWrite").and_then(|n| n.as_u64()).unwrap_or(0);
            let cost = usage.get("cost").and_then(|c| c.get("total")).and_then(|t| t.as_f64());

            // Accumulate into session totals for the agent_end event.
            self.accumulator.input_tokens += input;
            self.accumulator.output_tokens += output;
            self.accumulator.cache_read_tokens += cache_read;
            self.accumulator.cache_write_tokens += cache_write;
            if let Some(c) = cost {
                self.accumulator.cost_usd += c;
            }
            if let Some(m) = model {
                self.accumulator.model = Some(m.to_string());
            }

            let mut usage_payload = json!({
                "input_tokens": input,
                "output_tokens": output,
                "cache_read_tokens": cache_read,
                "cache_write_tokens": cache_write,
            });
            if let Some(m) = model {
                usage_payload["model"] = json!(m);
            }
            if let Some(c) = cost {
                usage_payload["cost_usd"] = json!(c);
            }
            events.push(("model_usage".into(), usage_payload));
        }

        events
    }

    fn emit_session_usage(&self) -> Vec<(String, Value)> {
        let acc = &self.accumulator;
        let mut payload = json!({
            "input_tokens": acc.input_tokens,
            "output_tokens": acc.output_tokens,
            "cache_read_tokens": acc.cache_read_tokens,
            "cache_write_tokens": acc.cache_write_tokens,
            "cost_usd": acc.cost_usd,
        });
        if let Some(ref m) = acc.model {
            payload["model"] = json!(m);
        }
        vec![("model_usage".into(), payload)]
    }
}

/// Infer the egress endpoint(s) required by pi from the command line.
///
/// Primary: `--model <provider>/<model>` — take the prefix before the first `/`.
/// Fallback: `--provider <name>` when `--model` has no slash.
/// Local/unrecognised providers return an empty slice.
pub fn egress_endpoints_for_cmd(cmd: &[String]) -> &'static [&'static str] {
    let model_val = extract_flag_value(cmd, "--model");
    let provider = if let Some(ref m) = model_val {
        if let Some((prefix, _)) = m.split_once('/') {
            Some(prefix.to_string())
        } else {
            // No slash in --model — fall back to --provider flag.
            extract_flag_value(cmd, "--provider")
        }
    } else {
        extract_flag_value(cmd, "--provider")
    };

    match provider.as_deref().map(|p| p.to_ascii_lowercase()).as_deref() {
        Some("anthropic") => &["api.anthropic.com"],
        Some("openai") | Some("openai-codex") | Some("azure-openai-responses") => {
            &["api.openai.com"]
        }
        Some("google") | Some("google-vertex") => &["generativelanguage.googleapis.com"],
        _ => &[],
    }
}

fn extract_flag_value(cmd: &[String], flag: &str) -> Option<String> {
    let mut iter = cmd.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().cloned();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fixture() -> Vec<(String, Value)> {
        let fixture = include_str!("testdata/pi_fixture.ndjson");
        let mut parser = PiParser::new();
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
                "turn_start",
                "tool_call",
                "tool_result",
                "turn_end",
                "model_usage", // per-turn: turn 1
                "turn_start",
                "turn_end",
                "model_usage", // per-turn: turn 2
                "output",      // compaction_start passthrough
                "model_usage", // session total at agent_end
            ]
        );
    }

    #[test]
    fn session_and_agent_start_are_dropped() {
        let fixture = include_str!("testdata/pi_fixture.ndjson");
        let mut parser = PiParser::new();
        // Count events; session and agent_start must not produce any.
        let mut session_line_events = vec![];
        let mut agent_start_events = vec![];
        for line in fixture.lines() {
            let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_default();
            let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let evts = parser.parse_line(line);
            if ty == "session" {
                session_line_events.extend(evts);
            } else if ty == "agent_start" {
                agent_start_events.extend(evts);
            }
        }
        assert!(session_line_events.is_empty(), "session must produce no events");
        assert!(agent_start_events.is_empty(), "agent_start must produce no events");
    }

    #[test]
    fn turn_id_from_internal_counter_not_json_field() {
        let events = parse_fixture();
        let turn_starts: Vec<_> = events.iter().filter(|(t, _)| t == "turn_start").collect();
        assert_eq!(turn_starts.len(), 2);
        assert_eq!(turn_starts[0].1["turn_id"], 1);
        assert_eq!(turn_starts[1].1["turn_id"], 2);
    }

    #[test]
    fn per_turn_model_usage_fields() {
        let events = parse_fixture();
        let usages: Vec<_> = events.iter().filter(|(t, _)| t == "model_usage").collect();
        // First model_usage is per-turn for turn 1.
        let u1 = &usages[0].1;
        assert_eq!(u1["input_tokens"], 100);
        assert_eq!(u1["output_tokens"], 50);
        assert_eq!(u1["cache_read_tokens"], 20);
        assert_eq!(u1["cache_write_tokens"], 10);
        assert!((u1["cost_usd"].as_f64().unwrap() - 0.0015).abs() < 1e-9);
        assert_eq!(u1["model"], "claude-sonnet-4-6");
    }

    #[test]
    fn session_level_model_usage_sums_across_turns() {
        let events = parse_fixture();
        let usages: Vec<_> = events.iter().filter(|(t, _)| t == "model_usage").collect();
        // Last model_usage is the session total emitted at agent_end.
        let session = &usages[usages.len() - 1].1;
        // Turn 1: (100, 50, 20, 10, 0.0015) + Turn 2: (150, 30, 10, 5, 0.001)
        assert_eq!(session["input_tokens"], 250);
        assert_eq!(session["output_tokens"], 80);
        assert_eq!(session["cache_read_tokens"], 30);
        assert_eq!(session["cache_write_tokens"], 15);
        assert!((session["cost_usd"].as_f64().unwrap() - 0.0025).abs() < 1e-9);
        assert_eq!(session["model"], "claude-sonnet-4-6");
    }

    #[test]
    fn tool_call_and_result_paired_by_tool_call_id() {
        let events = parse_fixture();
        let (_, call) = events.iter().find(|(t, _)| t == "tool_call").unwrap();
        let (_, result) = events.iter().find(|(t, _)| t == "tool_result").unwrap();
        assert_eq!(call["tool_call_id"], "call_001");
        assert_eq!(result["tool_call_id"], "call_001");
        assert_eq!(call["name"], "bash");
        assert_eq!(call["input"]["command"], "ls /workspace");
        assert!(result["content"].as_str().unwrap().contains("file1.txt"));
        assert_eq!(result["is_error"], false);
    }

    #[test]
    fn compaction_start_passes_through_as_stdout_output() {
        let events = parse_fixture();
        let outputs: Vec<_> = events.iter().filter(|(t, _)| t == "output").collect();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].1["stream"], "stdout");
        assert!(outputs[0].1["text"].as_str().unwrap().contains("compaction_start"));
    }

    #[test]
    fn tool_result_content_serialised_when_result_is_json_object() {
        let mut parser = PiParser::new();
        let line = r#"{"type":"tool_execution_end","toolCallId":"c1","result":{"files":["a.txt"]},"isError":false}"#;
        let events = parser.parse_line(line);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "tool_result");
        // content must be a string (not a nested object)
        let content = events[0].1["content"].as_str().unwrap();
        assert!(content.contains("a.txt"), "structured result serialised to string");
    }

    #[test]
    fn empty_line_produces_no_events() {
        let mut parser = PiParser::new();
        assert!(parser.parse_line("").is_empty());
        assert!(parser.parse_line("   ").is_empty());
    }

    #[test]
    fn egress_endpoints_model_with_slash_anthropic() {
        let cmd: Vec<String> =
            ["pi", "--mode", "json", "--model", "anthropic/claude-sonnet-4-6", "-p", "task"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(egress_endpoints_for_cmd(&cmd), &["api.anthropic.com"]);
    }

    #[test]
    fn egress_endpoints_provider_flag_openai() {
        let cmd: Vec<String> =
            ["pi", "--mode", "json", "--provider", "openai", "--model", "gpt-4o", "-p", "task"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(egress_endpoints_for_cmd(&cmd), &["api.openai.com"]);
    }

    #[test]
    fn egress_endpoints_model_slash_ollama_is_empty() {
        let cmd: Vec<String> =
            ["pi", "--mode", "json", "--model", "ollama/llama3", "-p", "task"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert!(egress_endpoints_for_cmd(&cmd).is_empty());
    }

    #[test]
    fn egress_endpoints_google_vertex() {
        let cmd: Vec<String> =
            ["pi", "--model", "google-vertex/gemini-pro", "-p", "task"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(egress_endpoints_for_cmd(&cmd), &["generativelanguage.googleapis.com"]);
    }

    #[test]
    fn egress_endpoints_openai_codex_provider() {
        let cmd: Vec<String> =
            ["pi", "--provider", "openai-codex", "-p", "task"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(egress_endpoints_for_cmd(&cmd), &["api.openai.com"]);
    }

    #[test]
    fn egress_endpoints_no_model_or_provider_is_empty() {
        let cmd: Vec<String> = ["pi", "-p", "task"].iter().map(|s| s.to_string()).collect();
        assert!(egress_endpoints_for_cmd(&cmd).is_empty());
    }

    #[test]
    fn egress_endpoints_provider_lookup_is_case_insensitive() {
        let cmd: Vec<String> =
            ["pi", "--model", "Anthropic/claude-sonnet-4-6", "-p", "task"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(egress_endpoints_for_cmd(&cmd), &["api.anthropic.com"]);
    }
}
