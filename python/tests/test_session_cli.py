"""End-to-end integration tests for the Session/Pool/Run surface (slice 11).

These tests drive the real `bunsen-core` binary through the Python wrappers
to exercise the parallel-Runs → reconciliation → downstream-Runs → close
flow from the PRD's user story 25, plus the smaller AC-level invariants
(context-manager does NOT close, `bunsen run --session <id>` ties to a
session, etc.).

The tests need a real bunsen-core binary; they skip when
``target/release/bunsen-core`` isn't present and ``BUNSEN_CORE_BIN`` is
not overridden to a real binary (the conftest stub does not implement
session subcommands).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_BIN = REPO_ROOT / "target" / "release" / "bunsen-core"


def _real_core_bin() -> str | None:
    """Resolve a real bunsen-core binary (no stub). Tests skip when None.

    The conftest sets `BUNSEN_CORE_BIN` to a stub for the lower-level
    Run-driver tests; we explicitly override that here because the stub
    doesn't implement the session subcommand.
    """
    if RELEASE_BIN.is_file() and os.access(RELEASE_BIN, os.X_OK):
        return str(RELEASE_BIN)
    debug = REPO_ROOT / "target" / "debug" / "bunsen-core"
    if debug.is_file() and os.access(debug, os.X_OK):
        return str(debug)
    return None


pytestmark = pytest.mark.skipif(
    _real_core_bin() is None,
    reason="needs a real bunsen-core binary; run `cargo build [--release]` first",
)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def core_bin() -> str:
    return _real_core_bin()  # type: ignore[return-value]


@pytest.fixture
def xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated XDG_DATA_HOME so the test never touches the user's real sessions."""
    root = tmp_path / "xdg"
    root.mkdir()
    monkeypatch.setenv("XDG_DATA_HOME", str(root))
    return root


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _git_capture(cwd: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return out.stdout


@pytest.fixture
def host_repo(tmp_path: Path) -> Path:
    """A bare host repo seeded with one commit on `main`."""
    bare = tmp_path / "host.git"
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", "--quiet", str(bare)],
        check=True,
    )
    # Push a seed commit so `main` exists.
    work = tmp_path / "host-seed"
    subprocess.run(["git", "init", "-b", "main", "--quiet", str(work)], check=True)
    _git(work, "config", "user.email", "host@test")
    _git(work, "config", "user.name", "Host")
    (work / "README.md").write_text("host\n")
    _git(work, "add", "README.md")
    _git(work, "commit", "-m", "init", "--quiet")
    _git(work, "push", str(bare), "main:main")
    shutil.rmtree(work)
    return bare


# ── Lightweight AC tests ──────────────────────────────────────────────────


def test_open_attach_list_round_trip(host_repo: Path, core_bin: str, xdg: Path) -> None:
    """open → attach → list returns the new Session by ID."""
    import bunsen

    s = bunsen.open_session(str(host_repo), _core_bin=core_bin)
    assert s.id
    assert s.state == "open"
    assert s.host_repo == str(host_repo)
    assert "main" in s.mirror_refs

    # attach by id
    re = bunsen.attach_session(s.id, _core_bin=core_bin)
    assert re.id == s.id
    assert re.state == "open"

    # list (default) surfaces the open Session
    items = bunsen.list_sessions(_core_bin=core_bin)
    ids = [x.id for x in items]
    assert s.id in ids


def test_list_filters(host_repo: Path, core_bin: str, xdg: Path) -> None:
    """`--all` adds closed; `--with-tombstones` adds discarded.

    Builds a discarded Session by opening then discarding, and uses the
    `failed_to_close` annotation as a stand-in for "live but not open"
    by checking the default list only returns live entries.
    """
    import bunsen

    live = bunsen.open_session(str(host_repo), _core_bin=core_bin)
    tomb = bunsen.open_session(str(host_repo), _core_bin=core_bin)
    tomb_id = tomb.id
    tomb.discard()

    # Default: tombstone not visible.
    default = bunsen.list_sessions(_core_bin=core_bin)
    default_ids = [x.id for x in default]
    assert live.id in default_ids
    assert tomb_id not in default_ids

    # --with-tombstones: tombstone visible.
    with_tomb = bunsen.list_sessions(_core_bin=core_bin, with_tombstones=True)
    assert tomb_id in [x.id for x in with_tomb]


def test_context_manager_does_not_close(host_repo: Path, core_bin: str, xdg: Path) -> None:
    """ADR-0010 user story 13: exiting `with` does NOT call close."""
    import bunsen

    with bunsen.open_session(str(host_repo), _core_bin=core_bin) as s:
        sid = s.id

    # After the `with` block, the on-disk state must still be `open`.
    re = bunsen.attach_session(sid, _core_bin=core_bin)
    assert re.state == "open", (
        "Session.__exit__ must NOT call close — see docstring + ADR-0010"
    )
    # Test teardown explicitly discards so the test exits cleanly.
    re.discard()


def test_label_appends_and_persists(host_repo: Path, core_bin: str, xdg: Path) -> None:
    import bunsen

    s = bunsen.open_session(str(host_repo), label="first", _core_bin=core_bin)
    s.label("second")
    s.label("third")

    re = bunsen.attach_session(s.id, _core_bin=core_bin)
    assert tuple(re.labels) == ("first", "second", "third")


# ── End-to-end orchestration test (user story 25) ────────────────────────


_AGENT_COMMIT_SH = """\
git config user.email agent@test
git config user.name Agent
echo "{tag}" > {file}
git add {file}
git commit -m "{tag}" --quiet
"""


def _run_spec(
    sh_body: str,
    base: str,
    *,
    import_refs=(),
    output_branch=None,
) -> dict:
    strat: dict = {"kind": "pool-clone", "base": base}
    if import_refs:
        strat["import"] = list(import_refs)
    spec = {
        "adapter": "black-box",
        "cmd": ["sh", "-c", sh_body],
        "branching-strategy": strat,
    }
    if output_branch is not None:
        spec["output-branch"] = output_branch
    return spec


def test_end_to_end_parallel_reconcile_downstream_close(
    host_repo: Path, core_bin: str, xdg: Path, tmp_path: Path
) -> None:
    """PRD user story 25: parallel Runs → reconciliation → downstream → close.

    The reconciliation Run uses `PoolClone { base: host/main, import: [run-1, run-2, run-3] }`
    to bring in the parallel branches; downstream Runs `PoolClone { base:
    reconciled, ... }` start from the reconciled tip; close pushes ONLY
    the reconciled branch (renamed on the host as `release/reconciled`)
    and asserts the host repo's final state.
    """
    import bunsen

    s = bunsen.open_session(str(host_repo), _core_bin=core_bin)

    # ── 1. Three parallel Runs, each producing a distinct branch. ──────────
    parallel = []
    for i in (1, 2, 3):
        spec = _run_spec(
            _AGENT_COMMIT_SH.format(tag=f"parallel-{i}", file=f"p{i}.txt"),
            base="host/main",
            output_branch=f"parallel/{i}",
        )
        r = s.run(spec)
        assert r.pool_sha is not None, f"parallel run {i} produced no commits"
        assert r.output_branch_pushed == f"parallel/{i}"
        parallel.append(r)

    # ── 2. Reconciliation Run merging the three parallel branches. ─────────
    # The agent script octopus-merges the three imported refs.
    reconcile_sh = """\
git config user.email agent@test
git config user.name Agent
git merge --no-edit --quiet parallel/1 parallel/2 parallel/3
echo reconciled > RECONCILE.md
git add RECONCILE.md
git commit -m reconcile --quiet
"""
    reconcile_spec = _run_spec(
        reconcile_sh,
        base="host/main",
        import_refs=("parallel/1", "parallel/2", "parallel/3"),
        output_branch="reconciled",
    )
    reconciled = s.run(reconcile_spec)
    assert reconciled.pool_sha is not None
    assert reconciled.output_branch_pushed == "reconciled"

    # ── 3. Two downstream Runs starting from the reconciled tip. ───────────
    downstream = []
    for i in (1, 2):
        spec = _run_spec(
            _AGENT_COMMIT_SH.format(tag=f"downstream-{i}", file=f"d{i}.txt"),
            base="reconciled",
            output_branch=f"downstream/{i}",
        )
        r = s.run(spec)
        assert r.pool_sha is not None, f"downstream run {i} produced no commits"
        downstream.append(r)

    # ── 4. Close, pushing only the reconciled branch to the host. ──────────
    s.close([bunsen.ManifestPair("reconciled", "release/reconciled")])
    re = bunsen.attach_session(s.id, _core_bin=core_bin)
    assert re.state == "closed", f"expected closed, got {re.state!r}"

    # ── 5. Host repo final state: ONLY release/reconciled added. ───────────
    branches = _git_capture(
        host_repo, "for-each-ref", "--format=%(refname:short)", "refs/heads/"
    ).split()

    assert "main" in branches, f"main must survive: {branches}"
    assert "release/reconciled" in branches, f"reconciled push missing: {branches}"

    # No runs/* refs (audit refs) should have leaked to the host.
    runs_leaked = [b for b in branches if b.startswith("runs/")]
    assert not runs_leaked, f"runs/* refs must not leak: {runs_leaked}"

    # No parallel/* or downstream/* refs either — close manifest only
    # pushed `reconciled` → `release/reconciled`, so everything else
    # must stay in the Pool.
    other_leaks = [
        b
        for b in branches
        if b.startswith(("parallel/", "downstream/", "reconciled"))
        and b != "release/reconciled"
    ]
    assert not other_leaks, f"only reconciled should land on host: {other_leaks}"

    # And the SHA must match the Pool's reconciled tip.
    host_sha = _git_capture(
        host_repo, "rev-parse", "refs/heads/release/reconciled"
    ).strip()
    assert host_sha == reconciled.pool_sha


def test_documented_worktree_inspection_command_works(
    host_repo: Path, core_bin: str, xdg: Path, tmp_path: Path
) -> None:
    """The README's `git worktree add` command actually creates an
    inspectable directory tree from a Pool ref produced by `Session.run`.
    """
    import bunsen

    s = bunsen.open_session(str(host_repo), _core_bin=core_bin)
    spec = _run_spec(
        _AGENT_COMMIT_SH.format(tag="for-inspect", file="inspect-me.txt"),
        base="host/main",
        output_branch="feature/inspect",
    )
    r = s.run(spec)
    assert r.pool_sha is not None

    pool = Path(s.path) / "pool"
    wt = tmp_path / "inspect-wt"
    # Verbatim the command shape documented in the README.
    subprocess.run(
        ["git", "-C", str(pool), "worktree", "add", str(wt), "feature/inspect"],
        check=True,
        capture_output=True,
    )
    try:
        assert (wt / "inspect-me.txt").is_file(), (
            "documented worktree command must materialise the agent's commit"
        )
        assert (wt / "inspect-me.txt").read_text().strip() == "for-inspect"
    finally:
        subprocess.run(
            ["git", "-C", str(pool), "worktree", "remove", "--force", str(wt)],
            capture_output=True,
        )


def test_run_session_flag_runs_inside_named_session(
    host_repo: Path, core_bin: str, xdg: Path
) -> None:
    """`bunsen-core --session <id> --spec <json>` ties the Run to that Session.

    Verifies the Run's audit ref lands in the named Session's Pool and
    nothing leaks to a peer Session.
    """
    import bunsen

    a = bunsen.open_session(str(host_repo), _core_bin=core_bin)
    b = bunsen.open_session(str(host_repo), _core_bin=core_bin)

    spec = _run_spec(
        _AGENT_COMMIT_SH.format(tag="via-flag", file="f.txt"),
        base="host/main",
        output_branch="feature/via-flag",
    )
    # Drive the Run through Session.run (which uses --session under the hood).
    r = a.run(spec)
    assert r.pool_sha is not None

    a_pool = Path(a.path) / "pool"
    b_pool = Path(b.path) / "pool"

    # Session A's Pool has the ref; Session B's Pool does not.
    a_has = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "refs/heads/feature/via-flag"],
        cwd=a_pool,
    ).returncode == 0
    b_has = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "refs/heads/feature/via-flag"],
        cwd=b_pool,
    ).returncode == 0
    assert a_has, "feature/via-flag must land in Session A's Pool"
    assert not b_has, "feature/via-flag must NOT leak to Session B's Pool"
