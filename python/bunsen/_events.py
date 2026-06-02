"""Typed event dataclasses for bunsen's NDJSON event stream."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

SCHEMA_VERSION = 1


class SchemaVersionError(Exception):
    """Raised when bunsen-core emits a schema_version the library can't handle."""


@dataclass
class _Base:
    schema_version: int
    run_id: str
    seq: int
    ts: str
    extra: dict = field(default_factory=dict, repr=False)


@dataclass
class RunStarted(_Base):
    adapter: str = ""
    workspace_path: str = ""
    transcript_path: str = ""


@dataclass
class RunEnded(_Base):
    reason: str = ""
    exit_code: Optional[int] = None
    signal: Optional[int] = None
    error: Optional[str] = None


@dataclass
class Output(_Base):
    stream: str = ""
    text: str = ""


@dataclass
class EgressDenied(_Base):
    destination: str = ""
    protocol: str = ""  # "http" | "https" | "raw_tcp" | "dns"
    reason: str = ""


@dataclass
class TurnStart(_Base):
    turn_id: int = 0


@dataclass
class TurnEnd(_Base):
    turn_id: int = 0
    model: Optional[str] = None
    stop_reason: Optional[str] = None


@dataclass
class ToolCall(_Base):
    tool_call_id: str = ""
    name: str = ""
    input: dict = field(default_factory=dict)


@dataclass
class ToolResult(_Base):
    tool_call_id: str = ""
    content: str = ""
    is_error: bool = False


@dataclass
class ModelUsage(_Base):
    input_tokens: int = 0
    output_tokens: int = 0
    model: Optional[str] = None
    cache_read_tokens: Optional[int] = None
    cache_write_tokens: Optional[int] = None
    cost_usd: Optional[float] = None


@dataclass
class UnknownEvent(_Base):
    type: str = ""
    raw: dict = field(default_factory=dict)


_KNOWN_ENVELOPE = {"schema_version", "run_id", "seq", "ts", "type"}

_KNOWN_FIELDS: dict[str, set[str]] = {
    "run_started": {"adapter", "workspace_path", "transcript_path"},
    "run_ended": {"reason", "exit_code", "signal", "error"},
    "output": {"stream", "text"},
    "egress_denied": {"destination", "protocol", "reason"},
    "turn_start": {"turn_id"},
    "turn_end": {"turn_id", "model", "stop_reason"},
    "tool_call": {"tool_call_id", "name", "input"},
    "tool_result": {"tool_call_id", "content", "is_error"},
    "model_usage": {"input_tokens", "output_tokens", "model", "cache_read_tokens", "cache_write_tokens", "cost_usd"},
}


def decode_event(raw: dict) -> _Base:
    sv = raw.get("schema_version", 1)
    if sv > SCHEMA_VERSION:
        raise SchemaVersionError(
            f"schema_version {sv} > library maximum {SCHEMA_VERSION}"
        )

    base_kwargs = {
        "schema_version": sv,
        "run_id": raw.get("run_id", ""),
        "seq": raw.get("seq", 0),
        "ts": raw.get("ts", ""),
    }
    etype = raw.get("type", "")
    known = _KNOWN_FIELDS.get(etype)

    if known is not None:
        extra = {k: v for k, v in raw.items() if k not in _KNOWN_ENVELOPE and k not in known}
        variant_kwargs = {k: raw[k] for k in known if k in raw}
        cls = {
            "run_started": RunStarted,
            "run_ended": RunEnded,
            "output": Output,
            "egress_denied": EgressDenied,
            "turn_start": TurnStart,
            "turn_end": TurnEnd,
            "tool_call": ToolCall,
            "tool_result": ToolResult,
            "model_usage": ModelUsage,
        }[etype]
        return cls(**base_kwargs, extra=extra, **variant_kwargs)  # type: ignore[call-arg]
    else:
        extra_fields = {k: v for k, v in raw.items() if k not in _KNOWN_ENVELOPE}
        return UnknownEvent(**base_kwargs, extra={}, type=etype, raw=extra_fields)
