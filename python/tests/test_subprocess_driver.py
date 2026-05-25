"""Tests for the Python subprocess driver against a stub crucible-core."""
import asyncio
import os
import sys
import pytest
import pytest_asyncio
from pathlib import Path

STUB = Path(__file__).parent / "fixtures" / "stub_crucible_core.py"

def stub_bin(mode: str = "normal") -> str:
    return f"{sys.executable} {STUB} --mode={mode}"


@pytest.mark.asyncio
async def test_events_yielded_in_order():
    import crucible
    from crucible._events import RunStarted, Output, RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    events = []
    async with crucible.run(spec, _core_bin=stub_bin()) as run:
        async for event in run.events:
            events.append(event)

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
    import crucible
    from crucible._events import RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    ended_count = 0
    async with crucible.run(spec, _core_bin=stub_bin()) as run:
        async for event in run.events:
            if isinstance(event, RunEnded):
                ended_count += 1

    # Iterator must have stopped cleanly after RunEnded
    assert ended_count == 1


@pytest.mark.asyncio
async def test_unknown_event_type_becomes_unknown_event():
    import crucible
    from crucible._events import UnknownEvent

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    unknown_events = []
    async with crucible.run(spec, _core_bin=stub_bin("unknown_event")) as run:
        async for event in run.events:
            if isinstance(event, UnknownEvent):
                unknown_events.append(event)

    assert len(unknown_events) == 1
    assert unknown_events[0].type == "future_event"
    assert unknown_events[0].raw["some_field"] == "some_value"


@pytest.mark.asyncio
async def test_egress_denied_event_decoded_with_typed_fields():
    import crucible
    from crucible._events import EgressDenied

    spec = {"adapter": "claude-code", "cmd": ["claude"]}
    denials = []
    async with crucible.run(spec, _core_bin=stub_bin("egress_denied")) as run:
        async for event in run.events:
            if isinstance(event, EgressDenied):
                denials.append(event)

    assert len(denials) == 1
    assert denials[0].destination == "github.com"
    assert denials[0].protocol == "https"
    assert denials[0].reason == "not in allowlist"


@pytest.mark.asyncio
async def test_schema_version_too_high_raises():
    import crucible
    from crucible._events import SchemaVersionError

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    with pytest.raises(SchemaVersionError):
        async with crucible.run(spec, _core_bin=stub_bin("schema_too_high")) as run:
            async for _ in run.events:
                pass


def test_sync_facade_works():
    import crucible
    from crucible._events import RunStarted, Output, RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    events = []
    with crucible.run_sync(spec, _core_bin=stub_bin()) as run:
        for event in run.events:
            events.append(event)

    assert isinstance(events[0], RunStarted)
    assert any(isinstance(e, Output) and "hello" in e.text for e in events)
    assert isinstance(events[-1], RunEnded)
    assert events[-1].reason == "agent_exit"


@pytest.mark.asyncio
async def test_secret_values_not_in_run_repr():
    """Run handle must not expose secret values via repr or public attributes."""
    import crucible

    spec = {
        "adapter": "black-box",
        "cmd": ["echo", "hi"],
        "secrets": {"API_KEY": "sk-abc123"},
    }
    async with crucible.run(spec, _core_bin=stub_bin("redact")) as run:
        async for _ in run.events:
            pass

    run_repr = repr(run)
    assert "sk-abc123" not in run_repr, f"Secret value leaked in repr: {run_repr}"
    # Public attributes should not expose secret values
    for attr in ("id", "workspace_path", "transcript_path"):
        val = str(getattr(run, attr, ""))
        assert "sk-abc123" not in val, f"Secret value in run.{attr}: {val!r}"


@pytest.mark.asyncio
async def test_run_id_and_paths_available():
    import crucible

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "env": {}}
    async with crucible.run(spec, _core_bin=stub_bin()) as run:
        async for _ in run.events:
            break  # consume first event to resolve

    assert run.id == "01HWTEST00000000000000000A"
    assert run.workspace_path is not None
    assert "workspace" in run.workspace_path
    assert run.transcript_path is not None


@pytest.mark.asyncio
async def test_kill_ends_run():
    """kill() command causes the hanging stub to emit RunEnded(reason='killed')."""
    import crucible
    from crucible._events import RunStarted, RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hi"], "env": {}}
    events = []
    async with crucible.run(spec, _core_bin=stub_bin("hang")) as run:
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
    import crucible
    from crucible._events import RunStarted, RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hi"], "env": {}}
    events = []
    async with crucible.run(spec, _core_bin=stub_bin("hang")) as run:
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
    import crucible
    from crucible._events import RunEnded
    import time

    spec = {"adapter": "black-box", "cmd": ["sleep", "60"], "wall-clock-seconds": 2}
    t0 = time.monotonic()
    events = []
    async with crucible.run(spec, _core_bin=stub_bin("timeout")) as run:
        async for event in run.events:
            events.append(event)
    elapsed = time.monotonic() - t0

    run_ended = next((e for e in events if isinstance(e, RunEnded)), None)
    assert run_ended is not None
    assert run_ended.reason == "timeout"
    assert 1.5 <= elapsed < 5.0, f"Expected timeout in 1.5–5s, got {elapsed:.2f}s"


@pytest.mark.asyncio
async def test_agent_exits_before_wall_clock():
    """Agent that exits quickly produces agent_exit, not timeout."""
    import crucible
    from crucible._events import RunEnded

    spec = {"adapter": "black-box", "cmd": ["echo", "hello"], "wall-clock-seconds": 30}
    events = []
    async with crucible.run(spec, _core_bin=stub_bin()) as run:
        async for event in run.events:
            events.append(event)

    run_ended = next((e for e in events if isinstance(e, RunEnded)), None)
    assert run_ended is not None
    assert run_ended.reason == "agent_exit"


@pytest.mark.asyncio
async def test_kill_before_wall_clock_beats_timeout():
    """Explicit kill() before the wall clock produces killed, not timeout."""
    import crucible
    from crucible._events import RunStarted, RunEnded

    spec = {"adapter": "black-box", "cmd": ["sleep", "60"], "wall-clock-seconds": 30}
    events = []
    async with crucible.run(spec, _core_bin=stub_bin("hang")) as run:
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
    import crucible

    spec = {"adapter": "black-box", "cmd": ["echo", "hi"], "env": {}}
    proc_ref = []

    async def run_and_cancel():
        async with crucible.run(spec, _core_bin=stub_bin("hang")) as run:
            proc_ref.append(run._proc)
            # Cancel immediately after getting the first event
            async for _ in run.events:
                raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_and_cancel()

    # After context exit the process must be gone
    if proc_ref:
        proc = proc_ref[0]
        # Give it a moment to clean up
        await asyncio.sleep(0.1)
        assert proc.returncode is not None, "Subprocess must have exited after cancellation"


def test_manage_firewall_kwarg_appends_cli_flag():
    """Slice 10k: manage_firewall=True must inject --manage-firewall into argv."""
    import crucible

    spec = {"adapter": "black-box"}

    ctx_on = crucible.run(spec, manage_firewall=True, _core_bin="dummy-core")
    assert "--manage-firewall" in ctx_on._core_argv

    ctx_off = crucible.run(spec, manage_firewall=False, _core_bin="dummy-core")
    assert "--manage-firewall" not in ctx_off._core_argv

    ctx_default = crucible.run(spec, _core_bin="dummy-core")
    assert "--manage-firewall" not in ctx_default._core_argv


def test_manage_firewall_kwarg_works_for_run_sync():
    """Slice 10k: same kwarg behavior in run_sync."""
    import crucible

    spec = {"adapter": "black-box"}

    ctx_on = crucible.run_sync(spec, manage_firewall=True, _core_bin="dummy-core")
    assert "--manage-firewall" in ctx_on._core_argv

    ctx_off = crucible.run_sync(spec, _core_bin="dummy-core")
    assert "--manage-firewall" not in ctx_off._core_argv
