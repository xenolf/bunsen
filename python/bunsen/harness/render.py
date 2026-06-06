"""Terminal renderers for line-oriented progress output.

A `Renderer` turns a set of concurrently-running, identified work items into
live terminal output. `LiveRenderer` is a docker-compose-style view (one bounded
panel per running item, repainted in place) for interactive TTYs; `PlainRenderer`
streams prefixed lines for pipes/CI. `make_renderer` picks between them.

This module is deliberately free of any `bunsen` import — it knows nothing about
Runs or events, only `(rid, title)` work items and the lines you feed them — so
it is reusable for any line-oriented orchestration, not just agent Runs.
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from typing import Protocol, runtime_checkable


def _short(value, limit: int = 100) -> str:
    s = value if isinstance(value, str) else str(value)
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _detail_lines(detail: str | None) -> list[str]:
    """Split a multi-line blob (e.g. a Run's stderr) into individual lines,
    preserving line breaks (unlike `_short`, which collapses them) and dropping
    trailing blank lines."""
    if not detail:
        return []
    lines = detail.replace("\r", "").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


@runtime_checkable
class Renderer(Protocol):
    """The surface both renderers implement, and what `run_dag` / `run_spec`
    drive. Implement this to plug in a custom view (e.g. a GUI or a logger)."""

    def start(self, rid: str, title: str) -> None: ...
    def line(self, rid: str, text: str) -> None: ...
    def note(self, text: str) -> None: ...
    def ok(self, rid: str, summary: str) -> None: ...
    def fail(
        self, rid: str, summary: str, *, detail: str | None = None, keep: int = 200
    ) -> None: ...
    def close(self) -> None: ...


# ── Docker-style live renderer ──────────────────────────────────────────────

CSI = "\x1b["


class _Style:
    def __init__(self, enabled: bool):
        self.e = enabled

    def _w(self, s: str, code: str) -> str:
        return f"{CSI}{code}m{s}{CSI}0m" if self.e else s

    def bold(self, s):
        return self._w(s, "1")

    def dim(self, s):
        return self._w(s, "2")

    def red(self, s):
        return self._w(s, "31")

    def green(self, s):
        return self._w(s, "32")

    def yellow(self, s):
        return self._w(s, "33")

    def cyan(self, s):
        return self._w(s, "36")


class _Panel:
    def __init__(self, title: str):
        self.title = title
        self.lines: list[str] = []

    def push(self, text: str) -> None:
        for t in str(text).split("\n"):
            self.lines.append(t)


class LiveRenderer:
    """A docker-compose-style live view. Each active work item is a bounded panel
    showing its last lines; the whole set is repainted in place each update.
    On success a panel collapses to a single ✓ line (the space is reclaimed for
    the next item); on failure the panel's tail is committed to scrollback and
    kept. TTY only — use `make_renderer` for the non-TTY fallback.

    `total_lines` is the live-region budget shared across concurrent panels, so
    two parallel items each get ~half the rows and the region stays bounded.
    """

    def __init__(self, total_lines: int = 50, *, throttle: float = 0.06):
        self.total = max(8, total_lines)
        self.throttle = throttle
        self.panels: "dict[str, _Panel]" = {}
        self._drawn = 0  # rows the live region occupied at last paint
        self._last = 0.0
        self._cursor_hidden = False
        self.st = _Style(sys.stdout.isatty() and os.environ.get("NO_COLOR") is None)
        self._out = sys.stdout

    # ── public API (mirrors PlainRenderer) ──
    def start(self, rid: str, title: str) -> None:
        self.panels[rid] = _Panel(title)
        self._repaint(force=True)

    def line(self, rid: str, text: str) -> None:
        p = self.panels.get(rid)
        if p is None:
            return
        p.push(text)
        self._repaint()

    def note(self, text: str) -> None:
        self._commit([self.st.dim(self._fit(text))])
        self._repaint(force=True)

    def ok(self, rid: str, summary: str) -> None:
        self.panels.pop(rid, None)
        self._commit([self.st.green("✓ ") + self._fit(summary)])
        self._repaint(force=True)

    def fail(
        self, rid: str, summary: str, *, detail: str | None = None, keep: int = 200
    ) -> None:
        p = self.panels.pop(rid, None)
        block = [self.st.red("✗ ") + self._fit(summary)]
        dl = _detail_lines(detail)
        if dl:
            block.append(self.st.dim("   ┄ stderr ┄"))
            block += ["   " + self._fit(d, indent=3) for d in dl[-keep:]]
        if p is not None and p.lines:
            tail = p.lines[-keep:]
            block.append(self.st.dim(f"   ┄ last {len(tail)} line(s) of {rid} ┄"))
            block += ["   " + self._fit(t, indent=3) for t in tail]
        self._commit(block)
        self._repaint(force=True)

    def close(self) -> None:
        self._repaint(force=True)  # panels now empty → region clears
        if self._cursor_hidden:
            self._out.write(CSI + "?25h")
            self._cursor_hidden = False
        self._out.flush()

    # ── internals ──
    def _size(self):
        return shutil.get_terminal_size((100, 30))

    def _fit(self, s: str, indent: int = 0) -> str:
        width = max(8, self._size().columns - indent)
        s = str(s).rstrip("\n")
        return s if len(s) <= width else s[: width - 1] + "…"

    def _compose(self) -> list[str]:
        if not self.panels:
            return []
        _cols, rows = self._size()
        budget = min(self.total, max(6, rows - 1))
        per = max(4, budget // len(self.panels))  # rows per panel incl. header
        out: list[str] = []
        for p in self.panels.values():
            out.append(
                self.st.cyan(self.st.bold(self._fit(f"┄┄ {p.title}  (running) ┄┄")))
            )
            for b in p.lines[-(per - 1) :] if per > 1 else []:
                out.append(self._fit("  " + b))
        maxrows = max(4, rows - 1)
        return out[-maxrows:] if len(out) > maxrows else out

    def _repaint(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last) < self.throttle:
            return
        self._last = now
        if not self._cursor_hidden:
            self._out.write(CSI + "?25l")
            self._cursor_hidden = True
        lines = self._compose()
        buf: list[str] = []
        if self._drawn:
            buf.append(f"{CSI}{self._drawn}A")  # up to top of old region
        buf.append("\r")
        for ln in lines:
            buf.append(CSI + "2K")  # clear whole line, then draw
            buf.append(ln)
            buf.append("\n")
        extra = self._drawn - len(lines)
        if extra > 0:  # old region was taller — wipe the leftover rows
            buf.append((CSI + "2K\n") * extra)
            buf.append(f"{CSI}{extra}A")
        self._drawn = len(lines)
        self._out.write("".join(buf))
        self._out.flush()

    def _commit(self, plines: list[str]) -> None:
        """Print lines into the scrollback ABOVE the live region (permanent)."""
        buf: list[str] = []
        if self._drawn:
            buf.append(f"{CSI}{self._drawn}A")  # to top of live region
            buf.append(CSI + "0J")  # clear region (cursor → end of screen)
        self._drawn = 0
        for ln in plines:
            buf.append(ln + "\n")
        self._out.write("".join(buf))
        self._out.flush()


class PlainRenderer:
    """Non-TTY fallback: stream every line with a run prefix; never clear."""

    def __init__(self):
        self.st = _Style(sys.stdout.isatty() and os.environ.get("NO_COLOR") is None)

    def start(self, rid, title):
        print(self.st.bold(f"== {title}"), flush=True)

    def line(self, rid, text):
        print(f"[{rid}] {text}", flush=True)

    def note(self, text):
        print(text, flush=True)

    def ok(self, rid, summary):
        print(self.st.green("✓ ") + summary, flush=True)

    def fail(self, rid, summary, *, detail: str | None = None, keep: int = 200):
        print(self.st.red("✗ ") + summary, flush=True)
        for d in _detail_lines(detail)[-keep:]:
            print("   " + d, flush=True)

    def close(self):
        pass


def make_renderer(ui_lines: int = 50, force_plain: bool = False) -> Renderer:
    """LiveRenderer on an interactive TTY; PlainRenderer otherwise (pipes, CI)."""
    if force_plain or not sys.stdout.isatty():
        return PlainRenderer()
    return LiveRenderer(total_lines=ui_lines)


__all__ = [
    "Renderer",
    "LiveRenderer",
    "PlainRenderer",
    "make_renderer",
]
