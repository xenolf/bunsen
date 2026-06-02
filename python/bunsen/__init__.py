"""bunsen — Python library for orchestrating coding agent Runs."""
from __future__ import annotations
from ._run import RunHandle, RunError
from ._events import (
    RunStarted, RunEnded, Output, EgressDenied,
    TurnStart, TurnEnd, ToolCall, ToolResult, ModelUsage,
    UnknownEvent, SchemaVersionError, SCHEMA_VERSION,
)
from ._session import (
    BranchingStrategy,
    NoneStrategy,
    PoolClone,
    RunSpec,
    ManifestPair,
    Run,
    Session,
    SessionError,
    open_session,
    attach_session,
    list_sessions,
)

__all__ = [
    "RunHandle", "RunError",
    "RunStarted", "RunEnded", "Output", "EgressDenied",
    "TurnStart", "TurnEnd", "ToolCall", "ToolResult", "ModelUsage",
    "UnknownEvent", "SchemaVersionError", "SCHEMA_VERSION",
    # Slice 11: Session/Pool/Run surface
    "BranchingStrategy", "NoneStrategy", "PoolClone", "RunSpec",
    "ManifestPair", "Run", "Session", "SessionError",
    "open_session", "attach_session", "list_sessions",
]
