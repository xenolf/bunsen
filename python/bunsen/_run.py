"""Streaming Run handle — async context manager wrapping a bunsen-core Run."""
from __future__ import annotations
import asyncio
import json
from typing import AsyncIterator, Optional, Sequence

from ._events import RunStarted, RunEnded, decode_event, _Base, SchemaVersionError


class RunError(RuntimeError):
    """Raised through the event stream when `bunsen-core` exits non-zero
    without emitting a terminal `run_ended` event or a Pool summary line.

    `stderr` is the captured error text and `returncode` is the process exit
    code, mirroring `SessionError` on the blocking `run_sync` path. Without
    this, an early core failure (bad spec, missing privileges) would surface
    as a silent empty event stream with an all-`None` summary.
    """

    def __init__(self, message: str, *, stderr: str = "", returncode: int = 1):
        super().__init__(message)
        self.stderr = stderr
        self.returncode = returncode


class RunHandle:
    """Live handle to a streaming Run, yielded by `async with Session.run(spec)`.

    `.events` async-iterates the typed NDJSON event stream until the run ends.
    `.stop()` / `.kill()` / `.pause()` / `.resume()` send control commands. Once
    the iterator is exhausted the Pool summary (`.pool_sha`,
    `.output_branch_pushed`, `.uncommitted_paths`, `.run_id`) is populated — the
    drain captures the trailing summary line before signalling end-of-stream, so
    these are guaranteed readable the moment the `async for` loop finishes.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[_Base | Exception | None] = asyncio.Queue(maxsize=1024)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._id: Optional[str] = None
        self._workspace_path: Optional[str] = None
        self._transcript_path: Optional[str] = None
        # Pool summary — set by _drain from the trailing summary line (the one
        # stdout line with neither "type" nor "seq"). None until a run produces
        # commits / a summary (e.g. a killed run may emit none).
        self._pool_sha: Optional[str] = None
        self._output_branch_pushed: Optional[str] = None
        self._uncommitted_paths: tuple[str, ...] = ()
        self._summary_run_id: Optional[str] = None
        # Accumulated stderr (bounded), surfaced via RunError if the run ends
        # non-zero without a terminal signal.
        self._stderr_buf = bytearray()

    @property
    def id(self) -> Optional[str]:
        return self._id

    @property
    def workspace_path(self) -> Optional[str]:
        return self._workspace_path

    @property
    def transcript_path(self) -> Optional[str]:
        return self._transcript_path

    @property
    def run_id(self) -> Optional[str]:
        return self._summary_run_id or self._id

    @property
    def pool_sha(self) -> Optional[str]:
        return self._pool_sha

    @property
    def output_branch_pushed(self) -> Optional[str]:
        return self._output_branch_pushed

    @property
    def uncommitted_paths(self) -> Sequence[str]:
        return self._uncommitted_paths

    async def _drain_stderr(self, proc: asyncio.subprocess.Process) -> None:
        if proc.stderr is None:
            return
        try:
            async for chunk in proc.stderr:
                # Bound the buffer; a runaway stderr should not grow unbounded.
                if len(self._stderr_buf) < 64 * 1024:
                    self._stderr_buf.extend(chunk)
        except Exception:
            pass

    async def _drain(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stdout is not None
        # A terminal signal is either a `run_ended` event or the trailing Pool
        # summary line. If we reach EOF without one and the process exited
        # non-zero, the run failed before producing any usable output — surface
        # it as a RunError instead of a silent empty stream.
        saw_terminal = False
        try:
            async for line in proc.stdout:
                raw_line = line.decode("utf-8", errors="replace").rstrip("\n")
                if not raw_line:
                    continue
                try:
                    obj = json.loads(raw_line)
                except Exception:
                    continue

                # The trailing summary line carries neither "type" nor "seq"
                # (every event has both). Capture it onto the handle and keep
                # reading to EOF; it is never yielded as an event. Setting the
                # fields here — before the `finally` enqueues the EOF sentinel —
                # is what lets callers read `.pool_sha` right after the loop.
                if "type" not in obj and "seq" not in obj:
                    self._summary_run_id = obj.get("run_id")
                    self._pool_sha = obj.get("pool_sha")
                    self._output_branch_pushed = obj.get("output_branch_pushed")
                    self._uncommitted_paths = tuple(obj.get("uncommitted_paths", ()))
                    saw_terminal = True
                    continue

                try:
                    event = decode_event(obj)
                except SchemaVersionError as e:
                    await self._queue.put(e)
                    return
                except Exception:
                    continue

                if self._id is None and getattr(event, "run_id", ""):
                    self._id = event.run_id
                if isinstance(event, RunStarted):
                    self._workspace_path = event.workspace_path
                    self._transcript_path = event.transcript_path
                if isinstance(event, RunEnded):
                    saw_terminal = True

                await self._queue.put(event)
        except asyncio.CancelledError:
            raise
        else:
            # Reached natural EOF (no early return / no cancellation). If the
            # run never produced a terminal signal and the process failed,
            # raise through the stream so the caller sees the error.
            if not saw_terminal:
                try:
                    rc = await asyncio.wait_for(proc.wait(), timeout=5.0)
                except Exception:
                    rc = proc.returncode
                if rc not in (0, None):
                    err = bytes(self._stderr_buf).decode("utf-8", errors="replace").strip()
                    msg = f"bunsen-core run exited {rc}"
                    if err:
                        msg += f": {err}"
                    await self._queue.put(RunError(msg, stderr=err, returncode=rc))
        finally:
            await self._queue.put(None)

    @property
    def events(self) -> AsyncIterator[_Base]:
        return self._event_iter()

    async def _event_iter(self) -> AsyncIterator[_Base]:
        while True:
            item = await self._queue.get()
            if item is None:
                return
            if isinstance(item, Exception):
                raise item
            yield item

    async def _send_cmd(self, op: str) -> None:
        if self._proc and self._proc.stdin and self._proc.returncode is None:
            try:
                self._proc.stdin.write((f'{{"op":"{op}"}}\n').encode())
                await self._proc.stdin.drain()
            except Exception:
                pass

    async def stop(self) -> None:
        await self._send_cmd("stop")

    async def kill(self) -> None:
        await self._send_cmd("kill")

    async def pause(self) -> None:
        await self._send_cmd("pause")

    async def resume(self) -> None:
        await self._send_cmd("resume")

    async def _terminate(self) -> None:
        if self._proc and self._proc.returncode is None:
            try:
                await self.kill()
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except Exception:
                pass


class _SessionRunContext:
    """Async context manager spawning `bunsen-core --session ...`. Built with the
    complete argv (core binary + `--session <id> --spec <json>` + any flags) and
    yields a `RunHandle` bound to the live subprocess.
    """

    def __init__(self, argv: list[str]) -> None:
        self._argv = argv
        self._run = RunHandle()
        self._drain_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None

    async def __aenter__(self) -> RunHandle:
        proc = await asyncio.create_subprocess_exec(
            *self._argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
        )
        self._run._proc = proc
        self._stderr_task = asyncio.ensure_future(self._run._drain_stderr(proc))
        self._drain_task = asyncio.ensure_future(self._run._drain(proc))
        return self._run

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._run._terminate()
        for task in (self._drain_task, self._stderr_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
