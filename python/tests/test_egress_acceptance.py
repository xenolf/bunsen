"""Acceptance tests for issue 10 (egress enforcer). Requires Linux + KVM.

Run with:
    BUNSEN_KERNEL=/path/vmlinux \\
    BUNSEN_ROOTFS=/path/rootfs.ext4 \\
    pytest python/tests/test_egress_acceptance.py -v -s

Can be run from any directory — no pytest plugin required beyond pytest itself.

Optional env vars:
    BUNSEN_ALPINE_ROOTFS=/path  also run every AC against an alpine-derived
                                  rootfs (see adapters/_alpine-test/). When
                                  set, each test runs twice — once per rootfs
                                  — with pytest ids `[smoke]` and `[alpine]`.
    BUNSEN_MANAGE_FIREWALL=0    disable --manage-firewall (default: enabled)
    BUNSEN_FIRECRACKER=/path    path to firecracker binary (default: "firecracker")

Assumes busybox is available inside the guest (wget, nc, nslookup, sh).
The rootfs must have git for AC7 (User Story 21 demo); that test is skipped
if `git` is absent from the rootfs.
"""
import asyncio
import os
import sys
import pytest
from pathlib import Path
from typing import Optional

# ── Skip guards ─────────────────────────────────────────────────────────────

_LINUX_KVM = sys.platform == "linux" and Path("/dev/kvm").exists()

pytestmark = pytest.mark.skipif(
    not _LINUX_KVM,
    reason="acceptance tests require Linux + /dev/kvm",
)

_KERNEL = os.environ.get("BUNSEN_KERNEL", "")
_ROOTFS = os.environ.get("BUNSEN_ROOTFS", "")
_ALPINE_ROOTFS = os.environ.get("BUNSEN_ALPINE_ROOTFS", "")
_FIRECRACKER = os.environ.get("BUNSEN_FIRECRACKER", "")
_MANAGE_FIREWALL = os.environ.get("BUNSEN_MANAGE_FIREWALL", "1") != "0"


def _rootfs_params() -> list:
    """Discover all rootfs sources from env and produce pytest params.

    Each set env var contributes one parametrization. If neither is set, a
    single "no-rootfs" param is emitted with a skip marker so the suite
    collects (and reports a clean skip) instead of erroring at collection.
    """
    specs = []
    if _ROOTFS:
        specs.append(pytest.param(_ROOTFS, id="smoke"))
    if _ALPINE_ROOTFS:
        specs.append(pytest.param(_ALPINE_ROOTFS, id="alpine"))
    if not specs:
        specs.append(pytest.param(
            None,
            id="no-rootfs",
            marks=pytest.mark.skip(
                reason="set BUNSEN_ROOTFS and/or BUNSEN_ALPINE_ROOTFS to run acceptance tests"
            ),
        ))
    return specs


@pytest.fixture(params=_rootfs_params())
def rootfs(request) -> str:
    """Yield each rootfs path the suite should exercise.

    Skips when BUNSEN_KERNEL is missing — the rootfs alone isn't enough.
    """
    if not _KERNEL:
        pytest.skip("set BUNSEN_KERNEL to run acceptance tests")
    return request.param


def _kvm_core_bin(rootfs_path: str) -> str:
    """Build the _core_bin string with --kernel/--rootfs flags.

    Intentionally bypasses BUNSEN_CORE_BIN — conftest.py sets that to the
    stub for unit tests; acceptance tests always need the real binary.
    """
    import shutil
    # Mirror find_core_bin()'s workspace search but skip the env-var step.
    here = Path(__file__).resolve()
    binary: Optional[str] = None
    for parent in here.parents:
        candidate = parent / "target" / "release" / "bunsen-core"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            binary = str(candidate)
            break
    if binary is None:
        found = shutil.which("bunsen-core")
        if found:
            binary = found
    if binary is None:
        pytest.skip(
            "real bunsen-core binary not found; build with `cargo build --release`"
        )
    parts = [binary, "--kernel", _KERNEL, "--rootfs", rootfs_path]
    if _FIRECRACKER:
        parts += ["--firecracker", _FIRECRACKER]
    return " ".join(parts)


async def _collect(spec: dict, timeout: float, rootfs_path: str) -> tuple:
    """Spawn bunsen-core, collect events until RunEnded, capture stderr via temp file.

    Returns (events, stderr).

    bunsen-core hangs after emitting run_ended (workspace extraction + nftables
    cleanup keep stdout open). We break on RunEnded and kill the process rather
    than waiting for EOF.

    stderr=PIPE deadlocks when journalctl -k -f is orphaned and keeps the pipe open.
    A temp file avoids the deadlock: all children write to the same file; we read it
    once after proc.wait() with no pipe to block on.
    """
    import json as _json
    import os
    import tempfile
    import time
    from bunsen._events import decode_event, RunEnded as _RunEnded

    cmd = _kvm_core_bin(rootfs_path).split()
    cmd.insert(1, "run")
    if _MANAGE_FIREWALL:
        cmd += ["--manage-firewall"]
    cmd += ["--spec", _json.dumps(spec)]

    # Open a temp file for stderr and pass the raw FD to the subprocess.
    stderr_fd, stderr_path = tempfile.mkstemp(suffix=".bunsen-stderr")
    os.close(stderr_fd)
    stderr_fd = os.open(stderr_path, os.O_WRONLY)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=stderr_fd,
            stdin=asyncio.subprocess.PIPE,
        )
        os.close(stderr_fd)  # parent doesn't need the write end
        assert proc.stdout is not None

        events: list = []
        t0 = time.monotonic()
        timed_out = False
        try:
            async with asyncio.timeout(timeout):
                async for raw_line in proc.stdout:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = decode_event(_json.loads(line))
                        events.append(event)
                        if isinstance(event, _RunEnded):
                            break  # bunsen-core hangs after RunEnded; don't wait for EOF
                    except Exception:
                        pass
        except TimeoutError:
            timed_out = True

        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        elapsed = time.monotonic() - t0
        await proc.wait()

        with open(stderr_path) as fh:
            stderr = fh.read().strip()
    finally:
        try:
            os.unlink(stderr_path)
        except OSError:
            pass

    if timed_out:
        pytest.fail(
            f"sandbox run timed out after {elapsed:.1f}s\n"
            f"events so far: {events}\n"
            f"bunsen-core stderr:\n{stderr or '(empty)'}"
        )

    if not events:
        pytest.fail(
            f"bunsen-core emitted no events "
            f"(exit {proc.returncode}, elapsed {elapsed:.1f}s)\n"
            f"bunsen-core stderr:\n{stderr or '(empty)'}"
        )

    return events, stderr


def _run_and_collect(spec: dict, rootfs_path: str, timeout: float = 90.0) -> list:
    """Run a sandbox synchronously and return all events. No pytest-asyncio needed."""
    events, stderr = asyncio.run(_collect(spec, timeout, rootfs_path))
    if stderr:
        # Printed to pytest's captured output — visible with -s and in failure reports.
        print(f"\n[bunsen-core stderr]\n{stderr}\n", flush=True)
    return events


def _denials(events) -> list:
    from bunsen._events import EgressDenied
    return [e for e in events if isinstance(e, EgressDenied)]


def _run_ended(events):
    from bunsen._events import RunEnded
    return next((e for e in events if isinstance(e, RunEnded)), None)


# ── Helpers for building specs ───────────────────────────────────────────────

def _spec(cmd: str, egress_endpoints: Optional[list] = None) -> dict:
    spec: dict = {
        "adapter": "black-box",
        "cmd": ["sh", "-c", cmd],
        "env": {},
        "workspace-disk-mb": 128,
    }
    if egress_endpoints is not None:
        spec["egress-endpoints"] = egress_endpoints
    return spec


# ── Tests ────────────────────────────────────────────────────────────────────

def test_ac1_allowed_domain_produces_no_egress_denied(rootfs):
    """AC1: a domain in the egress allowlist produces no EgressDenied.

    wget connects via HTTPS_PROXY (injected by bunsen). The proxy allows
    the CONNECT to api.anthropic.com because it is in egress-endpoints.
    The underlying request may fail (no API key) — that is irrelevant; we
    only care that no EgressDenied event is emitted.
    """
    spec = _spec(
        "wget -q --timeout=10 -O /dev/null https://api.anthropic.com/ 2>&1 || true; echo DONE",
        egress_endpoints=["api.anthropic.com"],
    )
    events = _run_and_collect(spec, rootfs)

    denials = _denials(events)
    assert denials == [], f"unexpected EgressDenied events: {denials}"

    ended = _run_ended(events)
    assert ended is not None, f"RunEnded missing; collected events: {events}"
    assert ended.reason == "agent_exit"


def test_ac2_blocked_https_produces_egress_denied(rootfs):
    """AC2: HTTPS to a domain not in the allowlist produces EgressDenied(https).

    With an empty egress-endpoints list, the proxy denies the CONNECT to
    github.com:443 and emits EgressDenied(destination='github.com', protocol='https').
    The agent receives a 403 from the proxy, so wget exits non-zero; the
    Run continues and exits normally (agent_exit).
    """
    spec = _spec(
        "wget -q --timeout=10 -O /dev/null https://github.com/ 2>&1 || true; echo DONE",
        egress_endpoints=[],
    )
    events = _run_and_collect(spec, rootfs)

    denials = _denials(events)
    assert len(denials) >= 1, f"expected at least one EgressDenied, got: {events}"

    d = denials[0]
    assert d.destination == "github.com", f"expected destination='github.com', got {d.destination!r}"
    assert d.protocol == "https", f"expected protocol='https', got {d.protocol!r}"

    ended = _run_ended(events)
    assert ended is not None
    assert ended.reason == "agent_exit"


def test_ac3_adding_domain_to_allowlist_lifts_block(rootfs):
    """AC3: adding 'github.com' to egress-endpoints allows the HTTPS CONNECT.

    Same command as AC2, but with github.com in egress-endpoints. The proxy
    allows the CONNECT; no EgressDenied is emitted.
    """
    spec = _spec(
        "wget -q --timeout=10 -O /dev/null https://github.com/ 2>&1 || true; echo DONE",
        egress_endpoints=["github.com"],
    )
    events = _run_and_collect(spec, rootfs)

    github_denials = [
        d for d in _denials(events) if d.destination == "github.com"
    ]
    assert github_denials == [], f"unexpected github.com EgressDenied: {github_denials}"

    ended = _run_ended(events)
    assert ended is not None
    assert ended.reason == "agent_exit"


def test_ac4_raw_tcp_bypass_produces_egress_denied_raw_tcp(rootfs):
    """AC4: a direct TCP connection that bypasses the proxy is dropped at L3.

    nc connects directly to 1.1.1.1:443 — not to the proxy. The nftables
    ruleset installed by bunsen drops the SYN; the kernel logs the drop;
    the journalctl tailer emits EgressDenied(protocol='raw_tcp').

    A 2-second sleep after nc gives the kernel log pipeline time to flush
    before the agent exits and the denial channel is drained.
    """
    spec = _spec(
        "nc -w 3 1.1.1.1 443 </dev/null 2>&1 || true; sleep 2; echo DONE",
        egress_endpoints=[],
    )
    events = _run_and_collect(spec, rootfs)

    raw_tcp_denials = [d for d in _denials(events) if d.protocol == "raw_tcp"]
    assert len(raw_tcp_denials) >= 1, (
        f"expected at least one EgressDenied(raw_tcp); got denials={_denials(events)}"
    )


def test_ac5_dns_for_non_allowed_domain_produces_egress_denied_dns(rootfs):
    """AC5: DNS lookup for a domain not in the allowlist produces EgressDenied(dns).

    bunsen-init wrote /etc/resolv.conf pointing at the host-side DNS
    listener (slice 10n). nslookup sends a UDP query to that listener;
    the listener evaluates the domain against the egress policy, returns
    REFUSED, and emits DenialEvent(protocol=dns).
    """
    spec = _spec(
        "nslookup github.com 2>&1 || true; echo DONE",
        egress_endpoints=[],
    )
    events = _run_and_collect(spec, rootfs)

    dns_denials = [d for d in _denials(events) if d.protocol == "dns"]
    assert len(dns_denials) >= 1, (
        f"expected at least one EgressDenied(dns); got denials={_denials(events)}\n"
        f"all events: {events}"
    )

    d = dns_denials[0]
    assert "github.com" in d.destination, (
        f"expected destination to contain 'github.com', got {d.destination!r}"
    )


def test_ac6_egress_denied_does_not_terminate_run(rootfs):
    """AC6: multiple EgressDenied events leave the Run running; it exits normally.

    Two blocked HTTPS requests produce two denial events. The agent exits
    with exit_code=0 — the Run reason must be 'agent_exit', not 'killed',
    'stopped', or anything triggered by a denial.
    """
    spec = _spec(
        (
            "wget -q --timeout=5 -O /dev/null https://github.com/ 2>&1 || true; "
            "wget -q --timeout=5 -O /dev/null https://evil.example.com/ 2>&1 || true; "
            "echo DONE"
        ),
        egress_endpoints=[],
    )
    events = _run_and_collect(spec, rootfs)

    denials = _denials(events)
    assert len(denials) >= 2, f"expected >= 2 EgressDenied events, got {denials}"

    ended = _run_ended(events)
    assert ended is not None, "Run must have ended"
    assert ended.reason == "agent_exit", (
        f"Run must end with reason='agent_exit', got {ended.reason!r}"
    )
    assert ended.exit_code in (None, 0), f"agent must exit 0, got {ended.exit_code}"

    # RunEnded comes after the denials in the event sequence
    denial_seqs = [d.seq for d in denials]
    assert all(s < ended.seq for s in denial_seqs), (
        "all EgressDenied events must precede RunEnded in sequence order"
    )


def test_ac7_user_story_21_clone_public_repo(rootfs):
    """AC7 / User Story 21: with github.com in the egress policy, git clone works.

    This test requires git in the rootfs. It is skipped at runtime if
    `command -v git` returns non-zero inside the guest.

    A successful clone prints CLONE_OK; the test asserts that string appears
    in the agent's stdout output and that no github.com EgressDenied was emitted.
    """
    from bunsen._events import Output

    # The command first checks for git; if absent it prints NO_GIT and exits 0
    # so we can skip cleanly without a test failure.
    check_then_clone = (
        "command -v git >/dev/null 2>&1 || { echo NO_GIT; exit 0; }; "
        "git clone --depth 1 https://github.com/octocat/Hello-World.git /tmp/hello"
        " && echo CLONE_OK || echo CLONE_FAIL"
    )
    spec = _spec(check_then_clone, egress_endpoints=["github.com"])

    events = _run_and_collect(spec, rootfs, timeout=120.0)

    stdout_text = "".join(
        e.text for e in events if isinstance(e, Output) and e.stream == "stdout"
    )

    if "NO_GIT" in stdout_text:
        pytest.skip("git not found in guest rootfs — install git or skip AC7")

    assert "CLONE_OK" in stdout_text, (
        f"expected CLONE_OK in stdout; got: {stdout_text!r}\n"
        f"denials: {_denials(events)}"
    )

    github_denials = [
        d for d in _denials(events) if d.destination == "github.com"
    ]
    assert github_denials == [], (
        f"unexpected github.com EgressDenied with github.com in allowlist: {github_denials}"
    )

    ended = _run_ended(events)
    assert ended is not None
    assert ended.reason == "agent_exit"
