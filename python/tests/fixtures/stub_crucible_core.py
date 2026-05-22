#!/usr/bin/env python3
"""Stub crucible-core for testing. Reads --spec, emits scripted NDJSON to stdout."""
import json
import sys
import os
import time

RUN_ID = "01HWTEST00000000000000000A"
WORKSPACE = f"/tmp/crucible-test-runs/{RUN_ID}/workspace"
TRANSCRIPT = f"/tmp/crucible-test-runs/{RUN_ID}/transcript.ndjson"

# Parse --mode from args (default: normal)
mode = "normal"
for i, arg in enumerate(sys.argv):
    if arg == "--mode" and i + 1 < len(sys.argv):
        mode = sys.argv[i + 1]
    elif arg.startswith("--mode="):
        mode = arg.split("=", 1)[1]

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
