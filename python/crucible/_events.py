"""Typed event dataclasses for crucible's NDJSON event stream."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional

SCHEMA_VERSION = 1


class SchemaVersionError(Exception):
    """Raised when crucible-core emits a schema_version the library can't handle."""


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
class UnknownEvent(_Base):
    type: str = ""
    raw: dict = field(default_factory=dict)


_KNOWN_ENVELOPE = {"schema_version", "run_id", "seq", "ts", "type"}

_KNOWN_FIELDS: dict[str, set[str]] = {
    "run_started": {"adapter", "workspace_path", "transcript_path"},
    "run_ended": {"reason", "exit_code", "signal", "error"},
    "output": {"stream", "text"},
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
        cls = {"run_started": RunStarted, "run_ended": RunEnded, "output": Output}[etype]
        return cls(**base_kwargs, extra=extra, **variant_kwargs)  # type: ignore[call-arg]
    else:
        extra_fields = {k: v for k, v in raw.items() if k not in _KNOWN_ENVELOPE}
        return UnknownEvent(**base_kwargs, extra={}, type=etype, raw=extra_fields)
