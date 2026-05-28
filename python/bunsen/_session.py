"""Session, BranchingStrategy, ManifestPair, and top-level functions.

Slice 11: Python surface for the Session/Pool/Run model from ADR-0010.
The Python wrappers shell out to `bunsen-core session ...` and parse the
JSON output. Each verb's success exits 0 with a single JSON document on
stdout; errors land on stderr and produce a non-zero exit code.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence, Union

from ._core_path import find_core_bin
from ._run import _SessionRunContext


# ── BranchingStrategy variants ────────────────────────────────────────────


@dataclass(frozen=True)
class NoneStrategy:
    """No materialisation — empty Workspace, no `.git`.

    Serializes to `{"kind": "none"}`. See [ADR-0010] for the typed
    BranchingStrategy contract.
    """


@dataclass(frozen=True)
class PoolClone:
    """Clone `base` from the Session's Pool and additionally fetch each
    name in `import_refs` as a local ref under the same name.

    The materialiser refuses to start if any referenced ref is not in
    the Pool — there is no fallback to the host repo at materialise time.
    """
    base: str
    import_refs: Sequence[str] = field(default_factory=tuple)


BranchingStrategy = Union[NoneStrategy, PoolClone]


def _strategy_to_json(s: BranchingStrategy) -> dict:
    if isinstance(s, NoneStrategy):
        return {"kind": "none"}
    if isinstance(s, PoolClone):
        return {"kind": "pool-clone", "base": s.base, "import": list(s.import_refs)}
    raise TypeError(f"unknown BranchingStrategy variant: {type(s).__name__}")


# ── RunSpec ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RunSpec:
    """Typed description of a Run, mirroring bunsen-core's `RunSpec`.

    `adapter` and `cmd` are required; every other field carries the same
    default as the Rust struct. Pass an instance to `Session.run` /
    `Session.run_sync`, or a plain dict in the kebab-case wire shape as an
    escape hatch. See [ADR-0010] and the Rust `RunSpec` for field semantics.

    `branching_strategy` takes a typed `NoneStrategy` / `PoolClone`.
    `output_branch` is validated server-side against legal git branch names
    and the reserved `host/*` and `runs/*` namespaces.
    """
    adapter: str
    cmd: Sequence[str]
    env: Mapping[str, str] = field(default_factory=dict)
    secrets: Mapping[str, str] = field(default_factory=dict)
    branching_strategy: BranchingStrategy = field(default_factory=NoneStrategy)
    output_branch: Optional[str] = None
    stop_grace_seconds: int = 10
    wall_clock_seconds: int = 1800
    memory_mb: int = 4096
    vcpus: int = 2
    workspace_disk_mb: int = 10240
    oci_image: Optional[str] = None
    egress_endpoints: Sequence[str] = ()

    def _to_wire(self) -> dict:
        """Serialise to the kebab-case JSON shape `RunSpec::from_json` accepts."""
        return {
            "adapter": self.adapter,
            "cmd": list(self.cmd),
            "env": dict(self.env),
            "secrets": dict(self.secrets),
            "branching-strategy": _strategy_to_json(self.branching_strategy),
            "output-branch": self.output_branch,
            "stop-grace-seconds": self.stop_grace_seconds,
            "wall-clock-seconds": self.wall_clock_seconds,
            "memory-mb": self.memory_mb,
            "vcpus": self.vcpus,
            "workspace-disk-mb": self.workspace_disk_mb,
            "oci-image": self.oci_image,
            "egress-endpoints": list(self.egress_endpoints),
        }


def _spec_to_json(
    spec: Union["RunSpec", dict],
) -> str:
    """Serialise a `RunSpec` or a raw spec dict to the JSON shape
    bunsen-core's `RunSpec::from_json` accepts.

    A `RunSpec` is serialised field-by-field to the kebab-case wire form. A
    dict is treated as already being in that shape and passed through as-is;
    the one exception is `branching_strategy`/`branching-strategy`, which is
    normalised when supplied as a typed `NoneStrategy` / `PoolClone`.
    """
    if isinstance(spec, RunSpec):
        return json.dumps(spec._to_wire())
    out = dict(spec)
    bs = out.get("branching_strategy") or out.get("branching-strategy")
    if isinstance(bs, (NoneStrategy, PoolClone)):
        # Normalise to the kebab-case form the Rust deserialiser expects.
        out.pop("branching_strategy", None)
        out["branching-strategy"] = _strategy_to_json(bs)
    return json.dumps(out)


# ── ManifestPair ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ManifestPair:
    """One line of a close-time manifest.

    `force=True` opts this pair into a non-fast-forward push. Default
    `False` keeps the FF safety net (the Pool layer aborts the whole
    close on the first non-FF pair).
    """
    pool_ref: str
    host_ref: str
    force: bool = False

    def to_flag(self) -> str:
        suffix = ":force" if self.force else ""
        return f"{self.pool_ref}:{self.host_ref}{suffix}"


# ── Session error ─────────────────────────────────────────────────────────


class SessionError(RuntimeError):
    """Raised when `bunsen-core session ...` exits non-zero. `stderr` is
    the captured error text and `returncode` is the process exit code.
    """

    def __init__(self, message: str, *, stderr: str = "", returncode: int = 1):
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode


# ── Run result ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Run:
    """Outcome of a `Session.run(spec)` call.

    `pool_sha` is `None` when the agent produced zero commits (a successful
    but warning-annotated Run). `output_branch_pushed` echoes back the
    spec's `output-branch` when commits landed, otherwise `None`.
    """
    run_id: str
    pool_sha: Optional[str]
    output_branch_pushed: Optional[str]
    uncommitted_paths: Sequence[str]


# ── Subprocess helpers ────────────────────────────────────────────────────


def _core_argv(_core_bin: Optional[str] = None) -> list[str]:
    return _core_bin.split() if _core_bin else find_core_bin()


def _run_core(
    argv_extra: Sequence[str],
    *,
    _core_bin: Optional[str] = None,
    extra_env: Optional[dict] = None,
) -> dict:
    """Run `bunsen-core ...` and parse the trailing JSON summary from stdout.

    Some invocations (notably `--session <id> --spec ...`) interleave NDJSON
    event lines on stdout from the transcript encoder before the final
    summary line. We pick the LAST non-empty JSON line as the authoritative
    summary; event lines carry a `seq` field and a `type` field which the
    summary does not, so the parse is unambiguous.

    Raises `SessionError` on non-zero exit.
    """
    import os

    argv = _core_argv(_core_bin) + list(argv_extra)
    env = None
    if extra_env:
        env = os.environ.copy()
        env.update(extra_env)
    proc = subprocess.run(argv, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise SessionError(
            f"bunsen-core {' '.join(argv_extra)!r} exited {proc.returncode}",
            stderr=proc.stderr,
            returncode=proc.returncode,
        )
    out = proc.stdout.strip()
    if not out:
        return {}
    lines = [ln for ln in out.splitlines() if ln.strip()]
    last = lines[-1]
    return json.loads(last)


def _run_argv_suffix(
    session_id: str,
    spec: Union["RunSpec", dict],
    *,
    kernel: Optional[str],
    rootfs: Optional[str],
    firecracker: Optional[str],
    manage_firewall: bool,
) -> list[str]:
    """Build the `--session <id> --spec <json> [flags]` argv tail shared by
    `Session.run` (async streaming) and `Session.run_sync` (blocking).
    """
    argv: list[str] = ["--session", session_id, "--spec", _spec_to_json(spec)]
    if kernel is not None:
        argv.extend(["--kernel", kernel])
    if rootfs is not None:
        argv.extend(["--rootfs", rootfs])
    if firecracker is not None:
        argv.extend(["--firecracker", firecracker])
    if manage_firewall:
        argv.append("--manage-firewall")
    return argv


# ── Session class ─────────────────────────────────────────────────────────


class Session:
    """A bounded orchestration context owning a Pool of git refs.

    Created via `open_session(...)` or `attach_session(id)`. Use
    `Session.run(spec)` to drive a Run end-to-end, `Session.close(manifest)`
    to push selected Pool refs to the host repo, `Session.discard()` to
    tombstone, and `Session.purge()` (only from `closed`) to wipe.

    Context-manager form:

        with bunsen.open_session(host_repo) as s:
            r = s.run(spec)
            s.close([ManifestPair(...)])

    Important: leaving the `with` block WITHOUT calling `close` leaves
    the Session in its current state on disk (typically `open`). The
    context manager exists for binding ergonomics, not for auto-close.
    Per ADR-0010 user story 13, close is never implicit — the Rust
    `Session` has no `Drop` impl, and the Python `__exit__` mirrors
    that invariant.
    """

    def __init__(self, summary: dict, *, _core_bin: Optional[str] = None):
        self._summary = summary
        self._core_bin = _core_bin

    @property
    def id(self) -> str:
        return self._summary["id"]

    @property
    def state(self) -> str:
        return self._summary["state"]

    @property
    def host_repo(self) -> str:
        return self._summary["host_repo"]

    @property
    def mirror_refs(self) -> Sequence[str]:
        return tuple(self._summary.get("mirror_refs", ()))

    @property
    def labels(self) -> Sequence[str]:
        return tuple(self._summary.get("labels", ()))

    @property
    def path(self) -> str:
        return self._summary["path"]

    @property
    def last_close_failure(self) -> Optional[str]:
        return self._summary.get("last_close_failure")

    def __repr__(self) -> str:
        return (
            f"Session(id={self.id!r}, state={self.state!r}, "
            f"host_repo={self.host_repo!r}, labels={list(self.labels)!r})"
        )

    # Context manager — does NOT call close on exit (ADR-0010 us. 13).
    def __enter__(self) -> "Session":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # Deliberately no-op. Close is never implicit.
        return None

    def _refresh(self) -> None:
        """Re-read the Session's on-disk metadata via `session show`."""
        self._summary = _run_core(
            ["session", "show", self.id],
            _core_bin=self._core_bin,
        )

    def label(self, label: str) -> None:
        result = _run_core(
            ["session", "label", self.id, label],
            _core_bin=self._core_bin,
        )
        self._summary["labels"] = list(result.get("labels", ()))

    def discard(self) -> None:
        _run_core(
            ["session", "discard", self.id],
            _core_bin=self._core_bin,
        )
        self._summary["state"] = "discarded"

    def purge(self) -> None:
        _run_core(
            ["session", "purge", self.id],
            _core_bin=self._core_bin,
        )
        self._summary["state"] = "purged"

    def close(self, manifest: Sequence[ManifestPair]) -> None:
        if not manifest:
            raise SessionError("close requires at least one ManifestPair")
        argv: list[str] = ["session", "close", self.id]
        for p in manifest:
            argv.extend(["--pair", p.to_flag()])
        try:
            _run_core(argv, _core_bin=self._core_bin)
        finally:
            # On failure the Session lands in failed_to_close on disk;
            # mirror that into the handle's view.
            try:
                self._refresh()
            except Exception:
                pass

    def run(
        self,
        spec: Union["RunSpec", dict],
        *,
        kernel: Optional[str] = None,
        rootfs: Optional[str] = None,
        firecracker: Optional[str] = None,
        manage_firewall: bool = False,
    ) -> _SessionRunContext:
        """Drive a streaming Run inside this Session.

        Async context manager yielding a live event stream plus run control:

            async with s.run(spec) as r:
                async for event in r.events:
                    ...
                # After the loop the Pool summary is on the handle:
                print(r.pool_sha, r.output_branch_pushed, r.uncommitted_paths)

        `spec`, `kernel`, `rootfs`, `firecracker`, and `manage_firewall` carry
        the same meaning as `run_sync`. Use `run_sync` when you only need the
        final outcome and not the live event stream.
        """
        suffix = _run_argv_suffix(
            self.id, spec,
            kernel=kernel, rootfs=rootfs,
            firecracker=firecracker, manage_firewall=manage_firewall,
        )
        argv = _core_argv(self._core_bin) + suffix
        return _SessionRunContext(argv)

    def run_sync(
        self,
        spec: Union["RunSpec", dict],
        *,
        kernel: Optional[str] = None,
        rootfs: Optional[str] = None,
        firecracker: Optional[str] = None,
        manage_firewall: bool = False,
    ) -> Run:
        """Drive a Run inside this Session, blocking until it completes.

        `spec` is a typed `RunSpec` or a dict matching it (no `host_repo_path`;
        the Session provides it). In dict form, `branching_strategy` may be
        either a dict (the JSON shape) or a typed `NoneStrategy` / `PoolClone`
        instance. `output_branch` is optional.

        Pass `kernel` (and optionally `rootfs`, `firecracker`,
        `manage_firewall`) to route the Run through the Firecracker sandbox
        on Linux. With no `kernel`, the Run uses the host-subprocess
        supervisor — the cross-platform default. See [ADR-0001] and the
        Rust [`RunBackend`] type for the full dispatch rules. On non-Linux
        hosts, supplying `kernel` raises `SessionError`
        ("sandbox backend requires Linux + KVM").
        """
        argv = _run_argv_suffix(
            self.id, spec,
            kernel=kernel, rootfs=rootfs,
            firecracker=firecracker, manage_firewall=manage_firewall,
        )
        result = _run_core(argv, _core_bin=self._core_bin)
        return Run(
            run_id=result["run_id"],
            pool_sha=result.get("pool_sha"),
            output_branch_pushed=result.get("output_branch_pushed"),
            uncommitted_paths=tuple(result.get("uncommitted_paths", ())),
        )


# ── Top-level constructors ────────────────────────────────────────────────


def open_session(
    host_repo: str,
    *,
    mirror_refs: Optional[Sequence[str]] = None,
    label: Optional[str] = None,
    _core_bin: Optional[str] = None,
) -> Session:
    """Open a new Session backed by `host_repo`.

    Default `mirror_refs` is the host repo's default branch (resolved
    server-side via `git symbolic-ref --short HEAD`). See [ADR-0010].
    """
    argv: list[str] = ["session", "open", host_repo]
    if mirror_refs:
        for r in mirror_refs:
            argv.extend(["--mirror", r])
    if label is not None:
        argv.extend(["--label", label])
    opened = _run_core(argv, _core_bin=_core_bin)
    # `session open` prints only `id` + `path`; fill in the rest via show.
    return attach_session(opened["id"], _core_bin=_core_bin)


def attach_session(id: str, *, _core_bin: Optional[str] = None) -> Session:
    """Attach by ULID to an existing Session."""
    summary = _run_core(
        ["session", "show", id],
        _core_bin=_core_bin,
    )
    return Session(summary, _core_bin=_core_bin)


def list_sessions(
    *,
    all: bool = False,
    with_tombstones: bool = False,
    _core_bin: Optional[str] = None,
) -> list[Session]:
    """List Sessions on disk.

    Default returns only live Sessions (`open` and `failed_to_close`).
    Pass `all=True` to include `closed`; `with_tombstones=True` to
    include `discarded`.
    """
    argv: list[str] = ["session", "list"]
    if all:
        argv.append("--all")
    if with_tombstones:
        argv.append("--with-tombstones")


    proc = subprocess.run(
        _core_argv(_core_bin) + argv,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SessionError(
            f"bunsen-core session list exited {proc.returncode}",
            stderr=proc.stderr,
            returncode=proc.returncode,
        )
    raw = json.loads(proc.stdout)
    return [Session(item, _core_bin=_core_bin) for item in raw]


__all__ = [
    "BranchingStrategy",
    "NoneStrategy",
    "PoolClone",
    "RunSpec",
    "ManifestPair",
    "Run",
    "Session",
    "SessionError",
    "open_session",
    "attach_session",
    "list_sessions",
]
