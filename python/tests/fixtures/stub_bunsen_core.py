#!/usr/bin/env python3
"""Stub bunsen-core for testing. Reads --spec, emits scripted NDJSON to stdout."""
import json
import sys
import time

RUN_ID = "01HWTEST00000000000000000A"
WORKSPACE = f"/tmp/bunsen-test-runs/{RUN_ID}/workspace"
TRANSCRIPT = f"/tmp/bunsen-test-runs/{RUN_ID}/transcript.ndjson"

# Parse --mode, --spec, and --session from args
mode = "normal"
spec_dict: dict = {}
has_session = False
i = 1
while i < len(sys.argv):
    arg = sys.argv[i]
    if arg == "--mode" and i + 1 < len(sys.argv):
        mode = sys.argv[i + 1]
        i += 2
    elif arg.startswith("--mode="):
        mode = arg.split("=", 1)[1]
        i += 1
    elif arg == "--spec" and i + 1 < len(sys.argv):
        try:
            spec_dict = json.loads(sys.argv[i + 1])
        except Exception:
            pass
        i += 2
    elif arg.startswith("--spec="):
        try:
            spec_dict = json.loads(arg.split("=", 1)[1])
        except Exception:
            pass
        i += 1
    elif arg == "--session" and i + 1 < len(sys.argv):
        has_session = True
        i += 2
    elif arg.startswith("--session="):
        has_session = True
        i += 1
    else:
        i += 1

wall_clock_seconds: float = float(spec_dict.get("wall-clock-seconds", 1800))

def emit(event: dict) -> None:
    print(json.dumps(event), flush=True)

base = {
    "schema_version": 1,
    "run_id": RUN_ID,
}

if mode == "schema_too_high":
    emit({**base, "schema_version": 999, "seq": 0, "ts": "2026-01-01T00:00:00.000Z",
          "type": "run_started", "adapter": "black-box", "workspace_path": WORKSPACE,
          "transcript_path": TRANSCRIPT})
    sys.exit(0)

if mode == "unknown_event":
    emit({**base, "seq": 0, "ts": "2026-01-01T00:00:00.000Z",
          "type": "run_started", "adapter": "black-box", "workspace_path": WORKSPACE,
          "transcript_path": TRANSCRIPT})
    emit({**base, "seq": 1, "ts": "2026-01-01T00:00:01.000Z",
          "type": "future_event", "some_field": "some_value"})
    emit({**base, "seq": 2, "ts": "2026-01-01T00:00:02.000Z",
          "type": "run_ended", "reason": "agent_exit", "exit_code": 0})
    sys.exit(0)

if mode == "egress_denied":
    emit({**base, "seq": 0, "ts": "2026-01-01T00:00:00.000Z",
          "type": "run_started", "adapter": "claude-code", "workspace_path": WORKSPACE,
          "transcript_path": TRANSCRIPT})
    emit({**base, "seq": 1, "ts": "2026-01-01T00:00:01.000Z",
          "type": "egress_denied", "destination": "github.com",
          "protocol": "https", "reason": "not in allowlist"})
    emit({**base, "seq": 2, "ts": "2026-01-01T00:00:02.000Z",
          "type": "run_ended", "reason": "agent_exit", "exit_code": 0})
    sys.exit(0)

if mode == "redact":
    emit({**base, "seq": 0, "ts": "2026-01-01T00:00:00.000Z",
          "type": "run_started", "adapter": "black-box", "workspace_path": WORKSPACE,
          "transcript_path": TRANSCRIPT})
    emit({**base, "seq": 1, "ts": "2026-01-01T00:00:01.000Z",
          "type": "output", "stream": "stdout", "text": "sk-abc123\n"})
    emit({**base, "seq": 2, "ts": "2026-01-01T00:00:02.000Z",
          "type": "run_ended", "reason": "agent_exit", "exit_code": 0})
    sys.exit(0)

if mode == "hang":
    # Emits run_started, then reads stdin for control commands.
    # Exits with the appropriate reason when stop/kill is received.
    emit({**base, "seq": 0, "ts": "2026-01-01T00:00:00.000Z",
          "type": "run_started", "adapter": "black-box", "workspace_path": WORKSPACE,
          "transcript_path": TRANSCRIPT})
    seq = 1
    for line in sys.stdin:
        try:
            cmd = json.loads(line.strip())
        except Exception:
            continue
        op = cmd.get("op")
        if op == "kill":
            emit({**base, "seq": seq, "ts": "2026-01-01T00:00:01.000Z",
                  "type": "run_ended", "reason": "killed"})
            sys.exit(0)
        elif op == "stop":
            emit({**base, "seq": seq, "ts": "2026-01-01T00:00:01.000Z",
                  "type": "run_ended", "reason": "stopped", "exit_code": 0})
            sys.exit(0)
    sys.exit(1)

if mode == "stop_graceful":
    # Like hang but handles SIGTERM by exiting cleanly (reason=stopped)
    emit({**base, "seq": 0, "ts": "2026-01-01T00:00:00.000Z",
          "type": "run_started", "adapter": "black-box", "workspace_path": WORKSPACE,
          "transcript_path": TRANSCRIPT})
    seq = 1
    for line in sys.stdin:
        try:
            cmd = json.loads(line.strip())
        except Exception:
            continue
        op = cmd.get("op")
        if op == "kill":
            emit({**base, "seq": seq, "ts": "2026-01-01T00:00:01.000Z",
                  "type": "run_ended", "reason": "killed"})
            sys.exit(0)
        elif op == "stop":
            emit({**base, "seq": seq, "ts": "2026-01-01T00:00:01.000Z",
                  "type": "run_ended", "reason": "stopped", "exit_code": 0})
            sys.exit(0)
    sys.exit(1)

if mode == "timeout":
    # Emits run_started, waits wall_clock_seconds, then emits timeout RunEnded.
    emit({**base, "seq": 0, "ts": "2026-01-01T00:00:00.000Z",
          "type": "run_started", "adapter": "black-box", "workspace_path": WORKSPACE,
          "transcript_path": TRANSCRIPT})
    time.sleep(wall_clock_seconds)
    emit({**base, "seq": 1, "ts": "2026-01-01T00:00:01.000Z",
          "type": "run_ended", "reason": "timeout"})
    sys.exit(0)

# Normal mode: run_started + 2 outputs + run_ended
emit({**base, "seq": 0, "ts": "2026-01-01T00:00:00.000Z",
      "type": "run_started", "adapter": "black-box", "workspace_path": WORKSPACE,
      "transcript_path": TRANSCRIPT})
emit({**base, "seq": 1, "ts": "2026-01-01T00:00:01.000Z",
      "type": "output", "stream": "stdout", "text": "hello\n"})
emit({**base, "seq": 2, "ts": "2026-01-01T00:00:02.000Z",
      "type": "output", "stream": "stdout", "text": "world\n"})
emit({**base, "seq": 3, "ts": "2026-01-01T00:00:03.000Z",
      "type": "run_ended", "reason": "agent_exit", "exit_code": 0})

# Session path: bunsen-core prints a trailing summary line (no "type"/"seq")
# after run_ended. Mirror that so the streaming handle can capture the Pool
# outcome.
if has_session:
    emit({"run_id": RUN_ID, "pool_sha": "deadbeefcafe",
          "output_branch_pushed": "feature/x", "uncommitted_paths": []})
