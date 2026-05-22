"""Tests for the Python subprocess driver against a stub crucible-core."""
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
