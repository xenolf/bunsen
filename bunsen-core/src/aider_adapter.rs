//! Aider adapter — parses aider's plain-text stdout into the same typed
//! event vocabulary the Claude Code adapter produces (`turn_start`,
//! `turn_end`, `model_usage`, `output`).
//!
//! Aider has no structured stream-json mode, so the parser is line-shape
//! driven. We recognise:
//!
//! - `Main model: <name> with ...` — captures the current model so the
//!   eventual `model_usage` event can carry it.
//! - `> <text>` — user prompt echo. Marks the start of a model response;
//!   emits `turn_start` (plus an `output` event so the raw line is still
//!   in the transcript for human readers).
//! - `Tokens: X sent, Y received.` — captures token counts; held as
//!   pending state because aider 0.6x prints `Cost:` on the next line.
//! - `Cost: $A message, $B session.` — completes the pending usage;
//!   emits `turn_end` + `model_usage`. If there is no pending Tokens
//!   line (cost only), the cost is dropped and the line becomes a
//!   regular `output` event.
//! - Anything else — passes through as an `output` event so the raw
//!   transcript is preserved.
//!
//! A turn that ends without seeing a `Cost:` line (e.g. `--no-stream`
//! aborted, or a model that doesn't surface cost) gets a `turn_end` +
//! `model_usage` flush triggered by the next `> prompt` or by
//! [`AiderParser::flush`] at end-of-stream.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde_json::{json, Value};

/// Endpoints aider needs based on the configured model name. The empty
/// slice means "no opinion — let the user script supply the allowlist."
///
/// Patterns are matched case-insensitively against the model name; the
/// list of providers is intentionally narrow for v1 (the three biggest
/// hosted-model destinations). Adding a provider is a one-line patch.
pub fn egress_endpoints_for_model(model: &str) -> &'static [&'static str] {
    let m = model.to_ascii_lowercase();
    if m.starts_with("claude-") || m.starts_with("anthropic/") {
        &["api.anthropic.com"]
    } else if m.starts_with("gpt-")
        || m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("openai/")
    {
        &["api.openai.com"]
    } else if m.starts_with("gemini-") || m.starts_with("gemini/") {
        &["generativelanguage.googleapis.com"]
    } else {
        &[]
    }
}

/// Pull the `--model X` / `--model=X` value out of an aider command line.
/// Returns `None` if no `--model` flag is present (aider would then use
/// its built-in default, which we don't try to second-guess here).
pub fn extract_model_from_cmd(cmd: &[String]) -> Option<String> {
    let mut iter = cmd.iter();
    while let Some(arg) = iter.next() {
        if let Some(rest) = arg.strip_prefix("--model=") {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        } else if arg == "--model" {
            if let Some(next) = iter.next() {
                return Some(next.clone());
            }
        }
    }
    None
}

#[derive(Default)]
struct PendingUsage {
    input_tokens: u64,
    output_tokens: u64,
}

pub struct AiderParser {
    turn_counter: u32,
    in_turn: bool,
    last_model: Option<String>,
    pending_usage: Option<PendingUsage>,
}

impl AiderParser {
    pub fn new() -> Self {
        AiderParser {
            turn_counter: 0,
            in_turn: false,
            last_model: None,
            pending_usage: None,
        }
    }

    pub fn parse_line(&mut self, line: &str) -> Vec<(String, Value)> {
        let trimmed_nl = line.trim_end_matches(['\n', '\r']);
        let trimmed = trimmed_nl.trim();

        if trimmed.is_empty() {
            return vec![];
        }

        // Aider 0.6x splits `Tokens:` and `Cost:` across two lines, so
        // any line that ISN'T a Cost: completion must flush any pending
        // usage as a cost-less model_usage before being processed.
        let is_cost = trimmed.starts_with("Cost:");
        let mut events: Vec<(String, Value)> = Vec::new();

        if !is_cost {
            if let Some(flushed) = self.flush_pending_usage() {
                events.extend(flushed);
            }
        }

        // `Main model: <name> with ...` — capture the model. Emit as
        // output too so the raw transcript still carries it.
        if let Some(rest) = trimmed.strip_prefix("Main model:") {
            if let Some(model) = rest.split_whitespace().next() {
                self.last_model = Some(model.to_string());
            }
            events.push(output_event(trimmed_nl));
            return events;
        }

        // `> <text>` — prompt marker. Open a new turn (flushing any
        // open one without cost data).
        if trimmed.starts_with('>') && !trimmed.starts_with(">>") {
            if self.in_turn {
                events.push(turn_end_event(self.turn_counter, self.last_model.as_deref()));
                self.in_turn = false;
            }
            self.turn_counter += 1;
            self.in_turn = true;
            events.push(("turn_start".into(), json!({"turn_id": self.turn_counter})));
            events.push(output_event(trimmed_nl));
            return events;
        }

        // `Tokens: 1.5k sent, 32 received.` — capture; emit nothing
        // until the Cost: line lands.
        if let Some(usage) = parse_tokens_line(trimmed) {
            self.pending_usage = Some(usage);
            return events;
        }

        // `Cost: $0.012 message, $0.024 session.` — complete the
        // model_usage and close the open turn. A Cost: line with no
        // pending Tokens: state is unusual (aider always prints them
        // together); treat it as raw output rather than emit a
        // synthetic zero-token usage event.
        if is_cost {
            if let (Some(cost), Some(pending)) = (parse_cost_line(trimmed), self.pending_usage.take()) {
                if self.in_turn {
                    events.push(turn_end_event(self.turn_counter, self.last_model.as_deref()));
                    self.in_turn = false;
                }
                events.push((
                    "model_usage".into(),
                    build_model_usage(Some(&pending), Some(cost), self.last_model.as_deref()),
                ));
                return events;
            }
        }

        events.push(output_event(trimmed_nl));
        events
    }

    /// Flush any pending usage as a cost-less model_usage; emit a
    /// `turn_end` for the open turn. Call at end-of-stream so a Run
    /// whose final line was a Tokens: still surfaces in the transcript.
    pub fn flush(&mut self) -> Vec<(String, Value)> {
        let mut events = Vec::new();
        if let Some(flushed) = self.flush_pending_usage() {
            events.extend(flushed);
        }
        if self.in_turn {
            events.push(turn_end_event(self.turn_counter, self.last_model.as_deref()));
            self.in_turn = false;
        }
        events
    }

    /// If a Tokens: line is pending, emit it as a cost-less model_usage
    /// and close the open turn. Used both as a per-line precondition and
    /// by [`AiderParser::flush`] at end-of-stream.
    fn flush_pending_usage(&mut self) -> Option<Vec<(String, Value)>> {
        let pending = self.pending_usage.take()?;
        let mut events = Vec::new();
        if self.in_turn {
            events.push(turn_end_event(self.turn_counter, self.last_model.as_deref()));
            self.in_turn = false;
        }
        events.push((
            "model_usage".into(),
            build_model_usage(Some(&pending), None, self.last_model.as_deref()),
        ));
        Some(events)
    }
}

fn output_event(text: &str) -> (String, Value) {
    ("output".into(), json!({"stream": "stdout", "text": text}))
}

fn turn_end_event(turn_id: u32, model: Option<&str>) -> (String, Value) {
    let mut payload = json!({"turn_id": turn_id});
    if let Some(m) = model {
        payload["model"] = json!(m);
    }
    ("turn_end".into(), payload)
}

fn build_model_usage(pending: Option<&PendingUsage>, cost_usd: Option<f64>, model: Option<&str>) -> Value {
    let (input, output) = pending.map_or((0, 0), |p| (p.input_tokens, p.output_tokens));
    let mut payload = json!({
        "input_tokens": input,
        "output_tokens": output,
    });
    if let Some(m) = model {
        payload["model"] = json!(m);
    }
    if let Some(c) = cost_usd {
        payload["cost_usd"] = json!(c);
    }
    payload
}

/// Parse `Tokens: 1.5k sent, 32 received.` (trailing punctuation /
/// whitespace tolerated). Returns `None` on any unexpected shape.
fn parse_tokens_line(line: &str) -> Option<PendingUsage> {
    let rest = line.strip_prefix("Tokens:")?.trim();
    // Expect: `<num> sent, <num> received.` (the trailing `.` is
    // optional because some aider versions omit it).
    let (sent_part, recv_part) = rest.split_once(',')?;
    let sent_num = sent_part.trim().strip_suffix("sent")?.trim();
    let recv_num = recv_part
        .trim()
        .trim_end_matches('.')
        .strip_suffix("received")?
        .trim();
    Some(PendingUsage {
        input_tokens: parse_token_count(sent_num)?,
        output_tokens: parse_token_count(recv_num)?,
    })
}

/// `1.5k` → 1500, `2.1M` → 2_100_000, `567` → 567, `1,234` → 1234.
fn parse_token_count(s: &str) -> Option<u64> {
    let cleaned: String = s.chars().filter(|c| *c != ',').collect();
    let (num_str, mult) = match cleaned.chars().last()? {
        'k' | 'K' => (&cleaned[..cleaned.len() - 1], 1_000_f64),
        'm' | 'M' => (&cleaned[..cleaned.len() - 1], 1_000_000_f64),
        _ => (cleaned.as_str(), 1_f64),
    };
    let value: f64 = num_str.parse().ok()?;
    Some((value * mult).round() as u64)
}

/// Parse `Cost: $0.012 message, $0.024 session.` Returns the per-message
/// cost (the session field is cumulative; per-message is the value tied
/// to the turn we're closing).
fn parse_cost_line(line: &str) -> Option<f64> {
    let rest = line.strip_prefix("Cost:")?.trim();
    let dollar = rest.strip_prefix('$')?;
    let (amount, _tail) = dollar.split_once(' ')?;
    amount.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_fixture() -> Vec<(String, Value)> {
        let fixture = include_str!("testdata/aider_fixture.txt");
        let mut parser = AiderParser::new();
        let mut events: Vec<(String, Value)> = fixture
            .lines()
            .flat_map(|line| parser.parse_line(line))
            .collect();
        events.extend(parser.flush());
        events
    }

    fn event_types(events: &[(String, Value)]) -> Vec<&str> {
        events.iter().map(|(t, _)| t.as_str()).collect()
    }

    #[test]
    fn fixture_yields_expected_event_sequence() {
        let events = parse_fixture();
        let types = event_types(&events);
        // Banner/model/repo lines → output. Then turn_start + the prompt
        // output. Model response + diff + Applied + Commit → output.
        // Cost line completes model_usage; turn_end fires first.
        assert_eq!(
            types,
            &[
                "output", // Aider v0.65.0
                "output", // Main model: gpt-4o ...
                "output", // Weak model: ...
                "output", // Git repo: ...
                "output", // Repo-map: ...
                "turn_start",
                "output", // > prompt
                "output", // model response text
                "output", // math_utils.py
                "output", // ```python
                "output", // <<<<<<< SEARCH
                "output", // =======
                "output", // def square...
                "output", // return ...
                "output", // >>>>>>> REPLACE
                "output", // ```
                "output", // Applied edit ...
                "output", // Commit ...
                "turn_end",
                "model_usage",
            ]
        );
    }

    #[test]
    fn model_usage_carries_tokens_cost_and_model() {
        let events = parse_fixture();
        let (_, payload) = events.iter().find(|(t, _)| t == "model_usage").unwrap();
        assert_eq!(payload["input_tokens"], 1500);
        assert_eq!(payload["output_tokens"], 32);
        assert!((payload["cost_usd"].as_f64().unwrap() - 0.0048).abs() < 1e-9);
        assert_eq!(payload["model"], "gpt-4o");
    }

    #[test]
    fn turn_end_carries_model() {
        let events = parse_fixture();
        let (_, payload) = events.iter().find(|(t, _)| t == "turn_end").unwrap();
        assert_eq!(payload["turn_id"], 1);
        assert_eq!(payload["model"], "gpt-4o");
    }

    #[test]
    fn prompt_line_emits_turn_start_and_output() {
        let mut parser = AiderParser::new();
        let events = parser.parse_line("> hello world\n");
        assert_eq!(event_types(&events), &["turn_start", "output"]);
        assert_eq!(events[0].1["turn_id"], 1);
        assert_eq!(events[1].1["text"], "> hello world");
    }

    #[test]
    fn second_prompt_closes_previous_turn() {
        let mut parser = AiderParser::new();
        let _ = parser.parse_line("> first\n");
        let events = parser.parse_line("> second\n");
        // First event must be the turn_end for turn 1.
        assert_eq!(events[0].0, "turn_end");
        assert_eq!(events[0].1["turn_id"], 1);
        // Followed by turn_start for turn 2 + output.
        assert_eq!(events[1].0, "turn_start");
        assert_eq!(events[1].1["turn_id"], 2);
        assert_eq!(events[2].0, "output");
    }

    #[test]
    fn empty_lines_emit_no_events() {
        let mut parser = AiderParser::new();
        assert!(parser.parse_line("").is_empty());
        assert!(parser.parse_line("   \n").is_empty());
    }

    #[test]
    fn tokens_line_emits_nothing_until_cost_lands() {
        let mut parser = AiderParser::new();
        let events = parser.parse_line("Tokens: 1.5k sent, 32 received.\n");
        assert!(events.is_empty(), "Tokens: alone should hold state, got {:?}", events);
    }

    #[test]
    fn cost_completes_pending_tokens_into_model_usage() {
        let mut parser = AiderParser::new();
        // Open a turn so we can verify turn_end fires.
        let _ = parser.parse_line("> demo\n");
        let _ = parser.parse_line("Tokens: 2k sent, 100 received.\n");
        let events = parser.parse_line("Cost: $0.01 message, $0.02 session.\n");
        assert_eq!(event_types(&events), &["turn_end", "model_usage"]);
        assert_eq!(events[1].1["input_tokens"], 2000);
        assert_eq!(events[1].1["output_tokens"], 100);
        assert!((events[1].1["cost_usd"].as_f64().unwrap() - 0.01).abs() < 1e-9);
    }

    #[test]
    fn cost_alone_with_no_pending_tokens_becomes_output() {
        let mut parser = AiderParser::new();
        let events = parser.parse_line("Cost: $0.99 message, $1.00 session.\n");
        assert_eq!(event_types(&events), &["output"]);
    }

    #[test]
    fn tokens_followed_by_unrelated_line_flushes_costless_usage() {
        let mut parser = AiderParser::new();
        let _ = parser.parse_line("> demo\n");
        let _ = parser.parse_line("Tokens: 500 sent, 50 received.\n");
        let events = parser.parse_line("Some unrelated output line\n");
        // turn_end then a cost-less model_usage then the unrelated line.
        assert_eq!(event_types(&events), &["turn_end", "model_usage", "output"]);
        assert_eq!(events[1].1["input_tokens"], 500);
        assert!(events[1].1.get("cost_usd").is_none());
    }

    #[test]
    fn flush_at_end_of_stream_closes_open_turn() {
        let mut parser = AiderParser::new();
        let _ = parser.parse_line("> demo\n");
        let events = parser.flush();
        assert_eq!(event_types(&events), &["turn_end"]);
    }

    #[test]
    fn main_model_line_captured_for_subsequent_usage() {
        let mut parser = AiderParser::new();
        let _ = parser.parse_line("Main model: claude-3-5-sonnet-20241022 with diff edit format\n");
        let _ = parser.parse_line("> task\n");
        let _ = parser.parse_line("Tokens: 1k sent, 50 received.\n");
        let events = parser.parse_line("Cost: $0.01 message, $0.01 session.\n");
        let (_, payload) = events.iter().find(|(t, _)| t == "model_usage").unwrap();
        assert_eq!(payload["model"], "claude-3-5-sonnet-20241022");
    }

    #[test]
    fn parse_token_count_handles_k_m_suffix_and_commas() {
        assert_eq!(parse_token_count("567").unwrap(), 567);
        assert_eq!(parse_token_count("1.5k").unwrap(), 1500);
        assert_eq!(parse_token_count("2K").unwrap(), 2000);
        assert_eq!(parse_token_count("1.2m").unwrap(), 1_200_000);
        assert_eq!(parse_token_count("3M").unwrap(), 3_000_000);
        assert_eq!(parse_token_count("1,234").unwrap(), 1234);
    }

    #[test]
    fn parse_cost_line_extracts_message_dollar_amount() {
        assert!((parse_cost_line("Cost: $0.012 message, $0.024 session.").unwrap() - 0.012).abs() < 1e-9);
        assert!((parse_cost_line("Cost: $0.5 message, $1.0 session.").unwrap() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn parse_cost_line_rejects_malformed() {
        assert!(parse_cost_line("Cost: free").is_none());
        assert!(parse_cost_line("Not a cost line").is_none());
    }

    #[test]
    fn parse_tokens_line_rejects_malformed() {
        assert!(parse_tokens_line("Tokens: foo").is_none());
        assert!(parse_tokens_line("Tokens: 1k sent only").is_none());
        assert!(parse_tokens_line("Not a tokens line").is_none());
    }

    #[test]
    fn double_prompt_marker_is_not_a_turn_start() {
        // Aider sometimes shows `>>>` as a continuation marker; only a
        // single `>` opens a new turn.
        let mut parser = AiderParser::new();
        let events = parser.parse_line(">>> continuation\n");
        assert_eq!(event_types(&events), &["output"]);
    }

    #[test]
    fn egress_endpoints_for_claude_model() {
        assert_eq!(
            egress_endpoints_for_model("claude-3-5-sonnet-20241022"),
            &["api.anthropic.com"]
        );
        assert_eq!(
            egress_endpoints_for_model("anthropic/claude-opus-4"),
            &["api.anthropic.com"]
        );
    }

    #[test]
    fn egress_endpoints_for_openai_model() {
        assert_eq!(egress_endpoints_for_model("gpt-4o"), &["api.openai.com"]);
        assert_eq!(egress_endpoints_for_model("o1-preview"), &["api.openai.com"]);
        assert_eq!(egress_endpoints_for_model("o3-mini"), &["api.openai.com"]);
        assert_eq!(egress_endpoints_for_model("openai/gpt-4o"), &["api.openai.com"]);
    }

    #[test]
    fn egress_endpoints_for_gemini_model() {
        assert_eq!(
            egress_endpoints_for_model("gemini-1.5-pro"),
            &["generativelanguage.googleapis.com"]
        );
    }

    #[test]
    fn egress_endpoints_for_unknown_model_is_empty() {
        assert!(egress_endpoints_for_model("mistral-large").is_empty());
        assert!(egress_endpoints_for_model("").is_empty());
    }

    #[test]
    fn egress_endpoints_lookup_is_case_insensitive() {
        assert_eq!(egress_endpoints_for_model("GPT-4o"), &["api.openai.com"]);
        assert_eq!(
            egress_endpoints_for_model("Claude-3-5-sonnet"),
            &["api.anthropic.com"]
        );
    }

    #[test]
    fn extract_model_from_separate_flag() {
        let cmd: Vec<String> = ["aider", "--model", "gpt-4o", "--message", "hi"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(extract_model_from_cmd(&cmd), Some("gpt-4o".to_string()));
    }

    #[test]
    fn extract_model_from_equals_flag() {
        let cmd: Vec<String> = ["aider", "--model=claude-3-5-sonnet", "--yes"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            extract_model_from_cmd(&cmd),
            Some("claude-3-5-sonnet".to_string())
        );
    }

    #[test]
    fn extract_model_returns_none_when_absent() {
        let cmd: Vec<String> = ["aider", "--message", "hi"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(extract_model_from_cmd(&cmd).is_none());
    }

    #[test]
    fn extract_model_returns_none_when_flag_has_no_value() {
        let cmd: Vec<String> = ["aider", "--model"].iter().map(|s| s.to_string()).collect();
        assert!(extract_model_from_cmd(&cmd).is_none());
    }

    #[test]
    fn extract_model_ignores_empty_equals_form() {
        let cmd: Vec<String> = ["aider", "--model=", "--yes"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(extract_model_from_cmd(&cmd).is_none());
    }
}
