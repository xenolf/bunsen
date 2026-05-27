"""bunsen — Python library for orchestrating coding agent Runs."""
from __future__ import annotations
from typing import Optional
from ._core_path import find_core_bin
from ._run import _AsyncRunContext, _SyncRunContext
from ._events import (
    RunStarted, RunEnded, Output, EgressDenied, UnknownEvent,
    SchemaVersionError, SCHEMA_VERSION,
)

__all__ = [
    "run", "run_sync",
    "RunStarted", "RunEnded", "Output", "EgressDenied", "UnknownEvent",
    "SchemaVersionError", "SCHEMA_VERSION",
]


def run(
    spec: dict,
    *,
    manage_firewall: bool = False,
    _core_bin: Optional[str] = None,
) -> _AsyncRunContext:
    """Async context manager. Usage: async with bunsen.run(spec) as r: ...

    manage_firewall: when True, bunsen-core is allowed to add a per-TAP
    iptables ACCEPT rule on the host for the lifetime of this Run, to work
    around a default-DROP INPUT chain (e.g. UFW on Ubuntu). The rule is
    scoped to the Run's TAP device and removed on Run end. Default False
    so that bunsen never touches the host firewall unless told to this
    invocation.
    """
    argv = _core_bin.split() if _core_bin else find_core_bin()
    if manage_firewall:
        argv = argv + ["--manage-firewall"]
    return _AsyncRunContext(spec, argv)


def run_sync(
    spec: dict,
    *,
    manage_firewall: bool = False,
    _core_bin: Optional[str] = None,
) -> _SyncRunContext:
    """Sync context manager. Usage: with bunsen.run_sync(spec) as r: ...

    See `run` for the meaning of `manage_firewall`.
    """
    argv = _core_bin.split() if _core_bin else find_core_bin()
    if manage_firewall:
        argv = argv + ["--manage-firewall"]
    return _SyncRunContext(spec, argv)
