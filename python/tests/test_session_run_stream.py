"""Tests for the async streaming `Session.run` against a stub bunsen-core.

`Session.run` is an async context manager yielding a live event stream plus
run control; `Session.run_sync` (covered by test_session_cli.py against the
real binary) is the blocking variant. The stub ignores `--session`, so we
construct a Session directly with a fake summary rather than shelling out to
`session open`.
"""
import asyncio
import sys
import pytest
from pathlib import Path

STUB = Path(__file__).parent / "fixtures" / "stub_bunsen_core.py"


def stub_bin(mode: str = "normal") -> str:
    return f"{sys.executable} {STUB} --mode={mode}"


def make_session(mode: str = "normal"):
    import bunsen

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


@pytest.mark.asyncio
async def test_events_yielded_in_order():
    from bunsen._events import RunStarted, Output, RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    events = []
    async with make_session().run(spec) as run:
        async for event in run.events:
            events.append(event)

    # The trailing summary line is swallowed by the drain, not yielded.
    assert len(events) == 4
    assert isinstance(events[0], RunStarted)
    assert isinstance(events[1], Output)
    assert events[1].stream == "stdout"
    assert events[1].text == "hello\n"
    assert isinstance(events[2], Output)
    assert events[2].text == "world\n"
    assert isinstance(events[3], RunEnded)
    assert events[3].reason == "agent_exit"
    assert events[3].exit_code == 0


@pytest.mark.asyncio
async def test_run_ended_is_terminal():
    from bunsen._events import RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    ended_count = 0
    async with make_session().run(spec) as run:
        async for event in run.events:
            if isinstance(event, RunEnded):
                ended_count += 1

    assert ended_count == 1


@pytest.mark.asyncio
async def test_unknown_event_type_becomes_unknown_event():
    from bunsen._events import UnknownEvent

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    unknown_events = []
    async with make_session("unknown_event").run(spec) as run:
        async for event in run.events:
            if isinstance(event, UnknownEvent):
                unknown_events.append(event)

    assert len(unknown_events) == 1
    assert unknown_events[0].type == "future_event"
    assert unknown_events[0].raw["some_field"] == "some_value"


@pytest.mark.asyncio
async def test_egress_denied_event_decoded_with_typed_fields():
    from bunsen._events import EgressDenied

    spec = {"adapter": "claude-code", "cmd": ["claude"]}
    denials = []
    async with make_session("egress_denied").run(spec) as run:
        async for event in run.events:
            if isinstance(event, EgressDenied):
                denials.append(event)

    assert len(denials) == 1
    assert denials[0].destination == "github.com"
    assert denials[0].protocol == "https"
    assert denials[0].reason == "not in allowlist"


@pytest.mark.asyncio
async def test_schema_version_too_high_raises():
    from bunsen._events import SchemaVersionError

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    with pytest.raises(SchemaVersionError):
        async with make_session("schema_too_high").run(spec) as run:
            async for _ in run.events:
                pass


@pytest.mark.asyncio
async def test_nonzero_exit_without_events_raises_run_error():
    """A run that fails before emitting any event surfaces a RunError carrying
    stderr and the exit code, instead of a silent empty stream."""
    from bunsen import RunError

    spec = {"adapter": "claude-code", "cmd": ["claude"]}
    with pytest.raises(RunError) as ei:
        async with make_session("fail").run(spec) as run:
            async for _ in run.events:
                pass

    assert ei.value.returncode == 2
    assert "invalid spec" in ei.value.stderr
    assert "invalid spec" in str(ei.value)


@pytest.mark.asyncio
async def test_secret_values_not_in_run_repr():
    """Run handle must not expose secret values via repr or public attributes."""
    spec = {
        "adapter": "black-box",
        "cmd": ["echo", "hi"],
        "secrets": {"API_KEY": "sk-abc123"},
    }
    async with make_session("redact").run(spec) as run:
        async for _ in run.events:
            pass

    run_repr = repr(run)
    assert "sk-abc123" not in run_repr, f"Secret value leaked in repr: {run_repr}"
    for attr in ("id", "workspace_path", "transcript_path"):
        val = str(getattr(run, attr, ""))
        assert "sk-abc123" not in val, f"Secret value in run.{attr}: {val!r}"


@pytest.mark.asyncio
async def test_run_id_and_paths_available():
    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    async with make_session().run(spec) as run:
        async for _ in run.events:
            break  # consume first event to resolve

    assert run.id == "01HWTEST00000000000000000A"
    assert run.workspace_path is not None
    assert "workspace" in run.workspace_path
    assert run.transcript_path is not None


@pytest.mark.asyncio
async def test_pool_summary_available_after_stream():
    """The trailing summary line populates the Pool fields by the time the
    `async for` loop finishes — guaranteed by the drain ordering."""
    spec = {"adapter": "black-box", "cmd": ["echo", "hi"], "env": {}}
    async with make_session().run(spec) as run:
        async for _ in run.events:
            pass
        assert run.pool_sha == "deadbeefcafe"
        assert run.output_branch_pushed == "feature/x"
        assert run.uncommitted_paths == ()
        assert run.run_id == "01HWTEST00000000000000000A"


@pytest.mark.asyncio
async def test_pool_summary_none_when_no_summary_line():
    """A killed run emits no summary line; the handle drains EOF cleanly and
    the Pool fields stay None."""
    import bunsen
    from bunsen._events import RunStarted

    spec = {"adapter": "black-box", "cmd": ["echo", "hi"], "env": {}}
    async with make_session("hang").run(spec) as run:
        async for event in run.events:
            if isinstance(event, RunStarted):
                await run.kill()

    assert run.pool_sha is None


@pytest.mark.asyncio
async def test_kill_ends_run():
    """kill() command causes the hanging stub to emit RunEnded(reason='killed')."""
    from bunsen._events import RunStarted, RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hi"], "env": {}}
    events = []
    async with make_session("hang").run(spec) as run:
        async for event in run.events:
            events.append(event)
            if isinstance(event, RunStarted):
                await run.kill()

    run_ended = next((e for e in events if isinstance(e, RunEnded)), None)
    assert run_ended is not None
    assert run_ended.reason == "killed"


@pytest.mark.asyncio
async def test_stop_ends_run():
    """stop() command causes the stub to emit RunEnded(reason='stopped')."""
    from bunsen._events import RunStarted, RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hi"], "env": {}}
    events = []
    async with make_session("hang").run(spec) as run:
        async for event in run.events:
            events.append(event)
            if isinstance(event, RunStarted):
                await run.stop()

    run_ended = next((e for e in events if isinstance(e, RunEnded)), None)
    assert run_ended is not None
    assert run_ended.reason == "stopped"


@pytest.mark.asyncio
async def test_wall_clock_timeout_fires():
    """wall_clock_seconds=2 stub emits RunEnded(reason='timeout') within a few seconds."""
    from bunsen._events import RunEnded
    import time

    spec = {"adapter": "black-box", "cmd": ["sleep", "60"], "wall-clock-seconds": 2}
    t0 = time.monotonic()
    events = []
    async with make_session("timeout").run(spec) as run:
        async for event in run.events:
            events.append(event)
    elapsed = time.monotonic() - t0

    run_ended = next((e for e in events if isinstance(e, RunEnded)), None)
    assert run_ended is not None
    assert run_ended.reason == "timeout"
    assert 1.5 <= elapsed < 5.0, f"Expected timeout in 1.5–5s, got {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_kill_before_wall_clock_beats_timeout():
    """Explicit kill() before the wall clock produces killed, not timeout."""
    from bunsen._events import RunStarted, RunEnded

    spec = {"adapter": "black-box", "cmd": ["sleep", "60"], "wall-clock-seconds": 30}
    events = []
    async with make_session("hang").run(spec) as run:
        async for event in run.events:
            events.append(event)
            if isinstance(event, RunStarted):
                await run.kill()

    run_ended = next((e for e in events if isinstance(e, RunEnded)), None)
    assert run_ended is not None
    assert run_ended.reason == "killed"


@pytest.mark.asyncio
async def test_cancel_kills_subprocess():
    """Cancelling the context manager kills the subprocess cleanly."""
    spec = {"adapter": "black-box", "cmd": ["echo", "hi"], "env": {}}
    proc_ref = []

    async def run_and_cancel():
        async with make_session("hang").run(spec) as run:
            proc_ref.append(run._proc)
            async for _ in run.events:
                raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_and_cancel()

    if proc_ref:
        proc = proc_ref[0]
        await asyncio.sleep(0.1)
        assert proc.returncode is not None, "Subprocess must have exited after cancellation"


def test_manage_firewall_kwarg_appends_cli_flag():
    """manage_firewall=True injects --manage-firewall into the run argv."""
    s = make_session()
    spec = {"adapter": "black-box"}

    ctx_on = s.run(spec, manage_firewall=True)
    assert "--manage-firewall" in ctx_on._argv
    assert "--session" in ctx_on._argv and "fake" in ctx_on._argv

    ctx_off = s.run(spec, manage_firewall=False)
    assert "--manage-firewall" not in ctx_off._argv

    ctx_default = s.run(spec)
    assert "--manage-firewall" not in ctx_default._argv


def test_run_argv_suffix_includes_all_flags():
    from bunsen._session import _run_argv_suffix

    argv = _run_argv_suffix(
        "sid", {"adapter": "x"},
        kernel="k", rootfs="rf", firecracker="fc", manage_firewall=True,
    )
    assert argv[:4] == ["--session", "sid", "--spec", '{"adapter": "x"}']
    assert argv[argv.index("--kernel") + 1] == "k"
    assert argv[argv.index("--rootfs") + 1] == "rf"
    assert argv[argv.index("--firecracker") + 1] == "fc"
    assert "--manage-firewall" in argv
