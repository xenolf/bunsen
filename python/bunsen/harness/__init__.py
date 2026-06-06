"""bunsen.harness — a small framework for orchestrating coding-agent Runs.

Opt-in layer on top of the core `bunsen` SDK. It gives you a docker-compose-style
live terminal view, a single-Run streamer, a dependency-aware DAG scheduler, and
the CLI/session boilerplate — so a user script reduces to: describe tasks, then
`run_dag`.

    import asyncio, bunsen
    from bunsen import RunSpec, PoolClone
    from bunsen.harness import Task, run_dag

    def spec_for(name):
        return lambda ctx: RunSpec(
            adapter="claude-code",
            cmd=["claude", "-p", f"do {name}"],
            branching_strategy=PoolClone(base=ctx.base_ref, import_refs=ctx.import_refs),
            output_branch=ctx.output_branch,
        )

    tasks = [
        Task(id="a", build_spec=spec_for("a")),
        Task(id="b", deps=["a"], build_spec=spec_for("b")),
    ]
    session = bunsen.open_session("/repo", mirror_refs=["main"])
    results = asyncio.run(run_dag(session, tasks, base_ref="host/main"))
"""
from __future__ import annotations

from .bootstrap import (
    add_sandbox_args,
    claude_code_secrets,
    detect_default_branch,
    run_kwargs_from_args,
)
from .render import LiveRenderer, PlainRenderer, Renderer, make_renderer
from .runner import format_event, run_spec
from .scheduler import SpecContext, Task, TaskResult, run_dag

__all__ = [
    # rendering
    "Renderer",
    "LiveRenderer",
    "PlainRenderer",
    "make_renderer",
    "format_event",
    # running one Run
    "run_spec",
    # DAG scheduling
    "Task",
    "SpecContext",
    "TaskResult",
    "run_dag",
    # CLI / session bootstrap
    "detect_default_branch",
    "claude_code_secrets",
    "add_sandbox_args",
    "run_kwargs_from_args",
]
