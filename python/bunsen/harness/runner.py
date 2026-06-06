"""Drive one Run, streaming its events to a `Renderer`.

`format_event` turns a typed bunsen event into one concise display line;
`run_spec` opens a streaming Run, feeds those lines to a renderer, and returns
the finished `RunHandle` (with its Pool summary populated). A core failure
propagates as `bunsen.RunError` through the event stream — `run_spec` lets it
surface so the caller (e.g. `run_dag`) can record it per-item.
"""
from __future__ import annotations

from typing import Callable, Optional

from .._events import (
    EgressDenied,
    ModelUsage,
    Output,
    RunEnded,
    RunStarted,
    ToolCall,
    ToolResult,
    TurnEnd,
    TurnStart,
)
from .._run import RunHandle
from .render import Renderer, _short


# ── Event rendering ────────────────────────────────────────────────────────


def format_event(ev) -> str | None:
    """One concise line per event (no run prefix — the panel header carries the
    item id). Returns None for events not worth a line."""
    if isinstance(ev, RunStarted):
        return f"▶ started (transcript={ev.transcript_path})"
    if isinstance(ev, TurnStart):
        return f"┌ turn {ev.turn_id}"
    if isinstance(ev, ToolCall):
        return f"│ 🔧 {ev.name}({_short(ev.input)})"
    if isinstance(ev, ToolResult):
        return f"│ {'✗' if ev.is_error else '✓'} {_short(ev.content)}"
    if isinstance(ev, TurnEnd):
        bits = [f"turn {ev.turn_id} end"] + [b for b in (ev.model, ev.stop_reason) if b]
        return "└ " + " · ".join(bits)
    if isinstance(ev, ModelUsage):
        cost = f" ${ev.cost_usd:.4f}" if ev.cost_usd is not None else ""
        return f"Σ in={ev.input_tokens} out={ev.output_tokens}{cost}"
    if isinstance(ev, Output):
        text = ev.text.rstrip("\n")
        return f"· [{ev.stream}] {_short(text, 200)}" if text else None
    if isinstance(ev, EgressDenied):
        return f"⛔ egress {ev.destination} ({ev.protocol}: {ev.reason})"
    if isinstance(ev, RunEnded):
        code = "" if ev.exit_code is None else f" exit={ev.exit_code}"
        return f"■ ended: {ev.reason}{code}"
    return None


# ── Running one Run ────────────────────────────────────────────────────────


async def run_spec(
    session,
    spec,
    *,
    rid: str,
    title: str,
    renderer: Renderer,
    run_kwargs: Optional[dict] = None,
    first_line: Optional[str] = None,
    on_event: Optional[Callable[[object], None]] = None,
) -> RunHandle:
    """Stream one Run to `renderer` and return its finished `RunHandle`.

    `rid` is the renderer's stable id for this Run (its panel key); `title` is
    the panel header. `run_kwargs` is forwarded to `Session.run` (kernel /
    rootfs / firecracker / manage_firewall). `first_line`, if given, is shown
    before the first event; `on_event` is called for every raw event (e.g. to
    accumulate usage) before it is formatted.

    The Pool summary (`handle.pool_sha`, `handle.output_branch_pushed`) is
    populated on return. A `bunsen.RunError` from a failed core run propagates
    out of this call; the caller decides how to record it.
    """
    renderer.start(rid, title)
    if first_line is not None:
        renderer.line(rid, first_line)
    async with session.run(spec, **(run_kwargs or {})) as run:
        async for ev in run.events:
            if on_event is not None:
                on_event(ev)
            body = format_event(ev)
            if body is not None:
                renderer.line(rid, body)
            if isinstance(ev, RunEnded):
                break
        await run.wait_for_summary()
    return run


__all__ = ["format_event", "run_spec"]
