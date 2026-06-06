"""Tests for the bunsen.harness framework (render / runner / scheduler).

`run_dag` is exercised end-to-end against the stub bunsen-core (see
`tests/fixtures/stub_bunsen_core.py` and the pattern in
`test_session_run_stream.py`): in `normal` mode each Run emits a trailing Pool
summary line (`pool_sha="deadbeefcafe"`), so a task lands `ok`; in `fail` mode
the core exits non-zero with no events, surfacing a `RunError`. The stub's mode
is fixed per Session, so mixed-outcome tests rely on the scheduler skipping a
task before it ever runs.
"""
import sys
from pathlib import Path

import bunsen
from bunsen import RunSpec
from bunsen._events import decode_event
from bunsen.harness import SpecContext, Task, format_event, run_dag
from bunsen.harness.render import PlainRenderer

STUB = Path(__file__).parent / "fixtures" / "stub_bunsen_core.py"


def stub_bin(mode: str = "normal") -> str:
    return f"{sys.executable} {STUB} --mode={mode}"


def make_session(mode: str = "normal"):
    return bunsen.Session(
        {
            "id": "fake",
            "state": "open",
            "host_repo": "x",
            "path": "/tmp",
            "mirror_refs": [],
            "labels": [],
        },
        _core_bin=stub_bin(mode),
    )


class RecordingRenderer:
    """A no-output Renderer that records every call, for assertions."""

    def __init__(self):
        self.calls: list[tuple] = []

    def start(self, rid, title):
        self.calls.append(("start", rid, title))

    def line(self, rid, text):
        self.calls.append(("line", rid, text))

    def note(self, text):
        self.calls.append(("note", text))

    def ok(self, rid, summary):
        self.calls.append(("ok", rid, summary))

    def fail(self, rid, summary, *, detail=None, keep=200):
        self.calls.append(("fail", rid, summary, detail))

    def close(self):
        self.calls.append(("close",))


def _recording_build_spec(record: dict):
    """A build_spec that records the SpecContext it receives, keyed by task id."""

    def build_spec(ctx: SpecContext) -> RunSpec:
        record[ctx.task.id] = ctx
        return RunSpec(adapter="black-box", cmd=["echo", "hi"])

    return build_spec


# ── run_dag scheduling ──────────────────────────────────────────────────────


async def test_run_dag_all_ok():
    record: dict = {}
    bs = _recording_build_spec(record)
    tasks = [Task(id="a", build_spec=bs), Task(id="b", build_spec=bs)]

    results = await run_dag(
        make_session("normal"),
        tasks,
        base_ref="host/main",
        renderer=RecordingRenderer(),
    )

    assert results["a"].status == "ok"
    assert results["a"].pool_sha == "deadbeefcafe"
    assert results["a"].output_branch == "feature/x"  # echoed by the stub summary
    assert results["b"].status == "ok"


async def test_run_dag_fail_then_skip():
    record: dict = {}
    bs = _recording_build_spec(record)
    rr = RecordingRenderer()
    tasks = [Task(id="a", build_spec=bs), Task(id="b", deps=["a"], build_spec=bs)]

    results = await run_dag(
        make_session("fail"), tasks, base_ref="host/main", renderer=rr
    )

    assert results["a"].status == "failed"
    assert "invalid spec" in (results["a"].error or "")
    assert results["b"].status == "skipped"
    # b was gated by a's failure — its spec was never built or run.
    assert "a" in record and "b" not in record
    assert any(c[0] == "fail" and c[1] == "a" for c in rr.calls)
    assert any(c[0] == "note" for c in rr.calls)


async def test_run_dag_unrunnable_cycle():
    record: dict = {}
    bs = _recording_build_spec(record)
    tasks = [
        Task(id="a", deps=["b"], build_spec=bs),
        Task(id="b", deps=["a"], build_spec=bs),
    ]

    results = await run_dag(
        make_session("normal"),
        tasks,
        base_ref="host/main",
        renderer=RecordingRenderer(),
    )

    assert results["a"].status == "unrunnable"
    assert results["b"].status == "unrunnable"
    assert record == {}  # nothing ever ran


async def test_run_dag_ref_resolution():
    record: dict = {}
    bs = _recording_build_spec(record)
    tasks = [
        Task(id="a", build_spec=bs),
        Task(id="b", deps=["a"], build_spec=bs),
        Task(id="c", deps=["a", "b"], build_spec=bs),
    ]

    results = await run_dag(
        make_session("normal"),
        tasks,
        base_ref="host/main",
        renderer=RecordingRenderer(),
    )

    assert all(results[t].status == "ok" for t in ("a", "b", "c"))
    # Root task materialises from the run_dag base_ref, no imports.
    assert record["a"].base_ref == "host/main"
    assert record["a"].import_refs == []
    # output_branch defaults to runs/<id>.
    assert record["a"].output_branch == "runs/a"
    # Single dep → base is the dep's branch, no imports.
    assert record["b"].base_ref == "runs/a"
    assert record["b"].import_refs == []
    # Multiple deps → first is the base, the rest are imported for merge.
    assert record["c"].base_ref == "runs/a"
    assert record["c"].import_refs == ["runs/b"]


async def test_run_dag_custom_output_branch_used_as_base():
    """An explicit output_branch (not the runs/<id> default) is what a dependent
    materialises from."""
    record: dict = {}
    bs = _recording_build_spec(record)
    tasks = [
        Task(id="a", output_branch="issue/a", build_spec=bs),
        Task(id="b", deps=["a"], build_spec=bs),
    ]

    await run_dag(
        make_session("normal"),
        tasks,
        base_ref="host/main",
        renderer=RecordingRenderer(),
    )

    assert record["a"].output_branch == "issue/a"
    assert record["b"].base_ref == "issue/a"


# ── format_event ────────────────────────────────────────────────────────────


def _ev(**kw):
    return decode_event(kw)


def test_format_event_per_type():
    assert (
        format_event(
            _ev(type="run_started", adapter="x", workspace_path="w", transcript_path="t")
        )
        == "▶ started (transcript=t)"
    )
    assert format_event(_ev(type="turn_start", turn_id=3)) == "┌ turn 3"
    assert (
        format_event(_ev(type="tool_call", name="Bash", input={"a": 1}))
        == "│ 🔧 Bash({'a': 1})"
    )
    assert format_event(_ev(type="tool_result", content="ok", is_error=False)) == "│ ✓ ok"
    assert format_event(_ev(type="tool_result", content="bad", is_error=True)) == "│ ✗ bad"
    assert (
        format_event(_ev(type="turn_end", turn_id=2, model="m", stop_reason="end"))
        == "└ turn 2 end · m · end"
    )
    assert (
        format_event(_ev(type="model_usage", input_tokens=10, output_tokens=20, cost_usd=0.0123))
        == "Σ in=10 out=20 $0.0123"
    )
    assert format_event(_ev(type="output", stream="stdout", text="hi")) == "· [stdout] hi"
    assert format_event(_ev(type="output", stream="stdout", text="")) is None
    assert (
        format_event(
            _ev(type="egress_denied", destination="github.com", protocol="https", reason="not in allowlist")
        )
        == "⛔ egress github.com (https: not in allowlist)"
    )
    assert (
        format_event(_ev(type="run_ended", reason="agent_exit", exit_code=0))
        == "■ ended: agent_exit exit=0"
    )
    # Unknown/future events render nothing.
    assert format_event(_ev(type="future_thing")) is None


# ── PlainRenderer ─────────────────────────────────────────────────────────────


def test_plain_renderer_output(capsys):
    r = PlainRenderer()
    r.start("x", "My Title")
    r.line("x", "hello")
    r.ok("x", "done")
    r.fail("y", "boom", detail="line1\nline2")
    r.close()

    out = capsys.readouterr().out
    assert "My Title" in out
    assert "[x] hello" in out
    assert "done" in out
    assert "boom" in out
    assert "line1" in out and "line2" in out
