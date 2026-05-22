"""crucible — Python library for orchestrating coding agent Runs."""
from __future__ import annotations
from typing import Optional
from ._core_path import find_core_bin
from ._run import _AsyncRunContext, _SyncRunContext
from ._events import (
    RunStarted, RunEnded, Output, UnknownEvent,
    SchemaVersionError, SCHEMA_VERSION,
)

__all__ = [
    "run", "run_sync",
    "RunStarted", "RunEnded", "Output", "UnknownEvent",
    "SchemaVersionError", "SCHEMA_VERSION",
]


def run(spec: dict, *, _core_bin: Optional[str] = None) -> _AsyncRunContext:
    """Async context manager. Usage: async with crucible.run(spec) as r: ..."""
    argv = _core_bin.split() if _core_bin else find_core_bin()
    return _AsyncRunContext(spec, argv)


def run_sync(spec: dict, *, _core_bin: Optional[str] = None) -> _SyncRunContext:
    """Sync context manager. Usage: with crucible.run_sync(spec) as r: ..."""
    argv = _core_bin.split() if _core_bin else find_core_bin()
    return _SyncRunContext(spec, argv)
