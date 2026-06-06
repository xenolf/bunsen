"""A generic DAG scheduler over agent Runs.

Define a list of `Task`s, each declaring its `deps` (other task ids) and a
`build_spec` callback that returns a `RunSpec` given the resolved refs. `run_dag`
runs every task whose deps are satisfied — in parallel, capped by `max_parallel`
— gating each blocked task until its blockers succeed and materialising it from
the blockers' output branches in the Session's Pool.

This is the `Issue`-agnostic generalisation of the original `implement.py`
scheduler: the markdown/issue model lives in the user script; this module only
knows ids, deps, and `RunSpec` builders.
"""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from .._run import RunError, RunHandle
from .._session import RunSpec
from .render import Renderer, make_renderer
from .runner import run_spec


@dataclass
class SpecContext:
    """The resolved refs handed to a `Task.build_spec` callback.

    `base_ref` is the Pool ref to clone from (the `run_dag` `base_ref` for a
    root task, else the first dep's `output_branch`); `import_refs` are the
    remaining deps' branches, fetched alongside so the spec can merge them;
    `output_branch` is where this task's commits publish.
    """

    task: "Task"
    base_ref: str
    import_refs: list[str]
    output_branch: str


@dataclass
class Task:
    """One node in the Run DAG.

    `build_spec(ctx)` returns the `RunSpec` to run, using the resolved refs in
    `ctx` (typically `PoolClone(base=ctx.base_ref, import_refs=ctx.import_refs)`
    and `output_branch=ctx.output_branch`). `deps` are other task ids that must
    finish `ok` first. `output_branch` defaults to `runs/<id>`; `title` is the
    panel header and defaults to `id`.
    """

    id: str
    build_spec: Callable[[SpecContext], RunSpec]
    deps: Sequence[str] = field(default_factory=tuple)
    output_branch: Optional[str] = None
    title: Optional[str] = None

    def resolved_output_branch(self) -> str:
        return self.output_branch or f"runs/{self.id}"


@dataclass
class TaskResult:
    """Outcome of one task in a `run_dag`.

    `status` is one of `ok` / `failed` / `skipped` / `unrunnable`. `pool_sha`
    and `output_branch` are populated on `ok`; `error` carries the failure
    text; `handle` is the finished `RunHandle` when the task actually ran.
    """

    id: str
    status: str
    pool_sha: Optional[str] = None
    output_branch: Optional[str] = None
    error: Optional[str] = None
    handle: Optional[RunHandle] = None


async def run_dag(
    session,
    tasks: Sequence[Task],
    *,
    base_ref: str,
    renderer: Optional[Renderer] = None,
    max_parallel: int = 0,
    run_kwargs: Optional[dict] = None,
) -> dict[str, TaskResult]:
    """Run `tasks` honouring deps; parallelise everything ready.

    `base_ref` is the Pool ref root (dependency-free) tasks materialise from
    (e.g. `host/main`). `max_parallel` caps concurrent Runs (0 = unlimited).
    `run_kwargs` is forwarded to `Session.run` (kernel / rootfs / firecracker /
    manage_firewall). Returns `{id: TaskResult}`.
    """
    if renderer is None:
        renderer = make_renderer()
    by_id: dict[str, Task] = {t.id: t for t in tasks}
    branch_of = {t.id: t.resolved_output_branch() for t in tasks}

    results: dict[str, TaskResult] = {}
    pending = dict(by_id)
    running: dict[asyncio.Task, str] = {}
    sem = asyncio.Semaphore(max_parallel) if max_parallel > 0 else None

    def resolve_base(task: Task) -> tuple[str, list[str]]:
        branches = [branch_of[d] for d in task.deps]
        if not branches:
            return base_ref, []
        return branches[0], branches[1:]  # extra deps imported for merge

    async def guarded(task: Task, base: str, imports: list[str]) -> RunHandle:
        cm = sem if sem is not None else contextlib.nullcontext()
        async with cm:
            out_branch = branch_of[task.id]
            ctx = SpecContext(
                task=task, base_ref=base, import_refs=imports, output_branch=out_branch
            )
            spec = task.build_spec(ctx)
            src = base + (f" + import {imports}" if imports else "")
            title = f"{task.id}   {src} → {out_branch}"
            return await run_spec(
                session,
                spec,
                rid=task.id,
                title=title,
                renderer=renderer,
                run_kwargs=run_kwargs,
                first_line=f"launching: {task.title or task.id}",
            )

    try:
        while pending or running:
            # Launch every task whose deps are all resolved.
            for tid in [
                t for t, task in pending.items() if all(d in results for d in task.deps)
            ]:
                task = pending.pop(tid)
                if all(results[d].status == "ok" for d in task.deps):
                    base, imports = resolve_base(task)
                    job = asyncio.create_task(guarded(task, base, imports))
                    running[job] = tid
                else:
                    failed = [d for d in task.deps if results[d].status != "ok"]
                    results[tid] = TaskResult(
                        id=tid, status="skipped", error=f"blocker(s) not ok: {failed}"
                    )
                    renderer.note(f"⤬ {tid} skipped — blocker(s) not ok: {failed}")

            if not running:
                for tid in list(pending):
                    results[tid] = TaskResult(
                        id=tid,
                        status="unrunnable",
                        error="unsatisfiable/cyclic deps",
                    )
                    renderer.note(f"⤬ {tid} unrunnable — unsatisfiable/cyclic deps")
                    pending.pop(tid)
                break

            done, _ = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
            for job in done:
                tid = running.pop(job)
                try:
                    handle = job.result()
                except RunError as e:
                    results[tid] = TaskResult(
                        id=tid, status="failed", error=e.stderr or str(e)
                    )
                    renderer.fail(
                        tid, f"{tid} run error (exit {e.returncode})", detail=e.stderr
                    )
                    continue
                except Exception as e:  # noqa: BLE001
                    results[tid] = TaskResult(id=tid, status="failed", error=repr(e))
                    renderer.fail(tid, f"{tid} unexpected error: {e!r}")
                    continue
                if handle.pool_sha:
                    results[tid] = TaskResult(
                        id=tid,
                        status="ok",
                        pool_sha=handle.pool_sha,
                        output_branch=handle.output_branch_pushed,
                        handle=handle,
                    )
                    renderer.ok(
                        tid,
                        f"{tid} committed {handle.pool_sha[:12]} → {handle.output_branch_pushed}",
                    )
                else:
                    results[tid] = TaskResult(
                        id=tid,
                        status="failed",
                        error="produced no commits",
                        handle=handle,
                    )
                    renderer.fail(tid, f"{tid} produced no commits")
    finally:
        renderer.close()

    return results


__all__ = ["Task", "SpecContext", "TaskResult", "run_dag"]
