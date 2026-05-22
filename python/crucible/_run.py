"""Run handle — async context manager wrapping crucible-core subprocess."""
from __future__ import annotations
import asyncio
import json
import sys
import threading
from contextlib import contextmanager
from typing import AsyncIterator, Iterator, Optional

from ._core_path import find_core_bin
from ._events import RunStarted, RunEnded, decode_event, _Base, SchemaVersionError


class Run:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[_Base | Exception | None] = asyncio.Queue(maxsize=1024)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._id: Optional[str] = None
        self._workspace_path: Optional[str] = None
        self._transcript_path: Optional[str] = None

    @property
    def id(self) -> Optional[str]:
        return self._id

    @property
    def workspace_path(self) -> Optional[str]:
        return self._workspace_path

    @property
    def transcript_path(self) -> Optional[str]:
        return self._transcript_path

    async def _drain(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stdout is not None
        try:
            async for line in proc.stdout:
                raw_line = line.decode("utf-8", errors="replace").rstrip("\n")
                if not raw_line:
                    continue
                try:
                    obj = json.loads(raw_line)
                    event = decode_event(obj)
                except SchemaVersionError as e:
                    await self._queue.put(e)
                    return
                except Exception:
                    continue

                if self._id is None and hasattr(event, "run_id"):
                    self._id = event.run_id
                if isinstance(event, RunStarted):
                    self._workspace_path = event.workspace_path
                    self._transcript_path = event.transcript_path

                await self._queue.put(event)
                if isinstance(event, RunEnded):
                    return
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
            if isinstance(item, RunEnded):
                return

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


class _AsyncRunContext:
    def __init__(self, spec: dict, core_argv: list[str]) -> None:
        self._spec = spec
        self._core_argv = core_argv
        self._run = Run()
        self._drain_task: Optional[asyncio.Task] = None

    async def __aenter__(self) -> Run:
        import json as _json
        argv = self._core_argv + ["--spec", _json.dumps(self._spec)]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.PIPE,
        )
        self._run._proc = proc
        self._drain_task = asyncio.ensure_future(self._run._drain(proc))
        return self._run

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._run._terminate()
        if self._drain_task:
            self._drain_task.cancel()
            try:
                await self._drain_task
            except asyncio.CancelledError:
                pass


# ---- sync facade ----

class _SyncRun:
    def __init__(self, run: Run, loop: asyncio.AbstractEventLoop) -> None:
        self._run = run
        self._loop = loop

    @property
    def id(self) -> Optional[str]:
        return self._run.id

    @property
    def workspace_path(self) -> Optional[str]:
        return self._run.workspace_path

    @property
    def transcript_path(self) -> Optional[str]:
        return self._run.transcript_path

    @property
    def events(self) -> Iterator[_Base]:
        aiter = self._run.events
        while True:
            try:
                item = self._loop.run_until_complete(aiter.__anext__())
                yield item
            except StopAsyncIteration:
                return

    def stop(self) -> None:
        self._loop.run_until_complete(self._run.stop())

    def kill(self) -> None:
        self._loop.run_until_complete(self._run.kill())

    def pause(self) -> None:
        self._loop.run_until_complete(self._run.pause())

    def resume(self) -> None:
        self._loop.run_until_complete(self._run.resume())


class _SyncRunContext:
    def __init__(self, spec: dict, core_argv: list[str]) -> None:
        self._spec = spec
        self._core_argv = core_argv
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._async_ctx: Optional[_AsyncRunContext] = None
        self._run: Optional[_SyncRun] = None

    def __enter__(self) -> _SyncRun:
        self._loop = asyncio.new_event_loop()
        self._async_ctx = _AsyncRunContext(self._spec, self._core_argv)
        async_run = self._loop.run_until_complete(self._async_ctx.__aenter__())
        self._run = _SyncRun(async_run, self._loop)
        return self._run

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        assert self._async_ctx is not None and self._loop is not None
        self._loop.run_until_complete(self._async_ctx.__aexit__(exc_type, exc_val, exc_tb))
        self._loop.close()
