"""CLI / session bootstrap helpers shared by harness user scripts.

These cover the boilerplate around a Run: discovering the host repo's branch to
mirror, resolving claude-code credentials into a secrets dict, declaring the
common sandbox/UI command-line flags, and turning parsed args into the kwargs
`Session.run` / `run_dag` expect.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


def detect_default_branch(host_repo: str) -> str:
    """The host repo's current branch name (e.g. 'master' or 'main').

    bunsen mirrors this branch into the Pool as `host/<branch>` at session
    open, and Runs materialise from that ref. We read it straight from git so
    the base ref always matches what was actually mirrored — `session show`
    does not round-trip `mirror_refs`, so we must not rely on reading it back.
    """
    for git_args in (
        ["symbolic-ref", "--short", "HEAD"],
        ["rev-parse", "--abbrev-ref", "HEAD"],
    ):
        try:
            out = subprocess.run(
                ["git", "-C", host_repo, *git_args],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        if out and out != "HEAD":
            return out
    raise RuntimeError(
        f"could not determine the default branch of {host_repo!r}; "
        "pass an explicit branch name."
    )


def claude_code_secrets(
    api_key_env: str = "ANTHROPIC_API_KEY",
    *,
    credentials_path: Path | None = None,
) -> dict[str, str]:
    """Resolve claude-code credentials into a `RunSpec.secrets` dict.

    Prefers the `api_key_env` environment variable (passed through under the
    same name). Falls back to the local Claude credentials file
    (`~/.claude/.credentials.json` by default), exporting its OAuth access token
    as `CLAUDE_CODE_OAUTH_TOKEN`. Raises `RuntimeError` if neither is available.
    """
    key = os.environ.get(api_key_env)
    if key:
        return {api_key_env: key}
    creds = credentials_path or (Path.home() / ".claude" / ".credentials.json")
    if creds.is_file():
        data = json.loads(creds.read_text(encoding="utf-8"))
        return {"CLAUDE_CODE_OAUTH_TOKEN": data["claudeAiOauth"]["accessToken"]}
    raise RuntimeError(
        f"no claude-code credentials: set ${api_key_env} or provide {creds}."
    )


def add_sandbox_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Add the common sandbox/UI flags (with the standard BUNSEN_* env defaults).

    Sandbox image / backend: --kernel --rootfs --oci-image --firecracker
    --manage-firewall. Scheduling/UI: --max-parallel --wall-clock --ui-lines
    --no-ui. Returns the same parser for chaining.
    """
    parser.add_argument("--kernel", default=os.environ.get("BUNSEN_KERNEL"))
    parser.add_argument(
        "--rootfs",
        default=os.environ.get("BUNSEN_ROOTFS"),
        help="prebuilt ext4 rootfs path; wins over --oci-image when both are set",
    )
    parser.add_argument(
        "--oci-image",
        default=os.environ.get("BUNSEN_OCI_IMAGE"),
        help="digest-pinned OCI ref (ghcr.io/...@sha256:<hex>) resolved via the OCI cache",
    )
    parser.add_argument("--firecracker", default=os.environ.get("BUNSEN_FIRECRACKER"))
    parser.add_argument("--manage-firewall", action="store_true")
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=int(os.environ.get("BUNSEN_MAX_PARALLEL", "0")),
        help="cap concurrent Runs (0 = unlimited)",
    )
    parser.add_argument(
        "--wall-clock",
        type=int,
        default=int(os.environ.get("BUNSEN_WALL_CLOCK", "3600")),
    )
    parser.add_argument(
        "--ui-lines",
        type=int,
        default=int(os.environ.get("BUNSEN_UI_LINES", "50")),
        help="live-view height (rows) shared across concurrent Runs (default: 50)",
    )
    parser.add_argument(
        "--no-ui",
        action="store_true",
        help="disable the live view; stream all lines plainly (auto when not a TTY)",
    )
    return parser


def run_kwargs_from_args(args: argparse.Namespace) -> dict:
    """Build the `Session.run` kwargs (kernel/rootfs/firecracker/manage_firewall)
    from parsed args, omitting unset values so bunsen applies its own defaults."""
    run_kwargs: dict = {}
    if getattr(args, "kernel", None):
        run_kwargs["kernel"] = args.kernel
    if getattr(args, "rootfs", None):
        run_kwargs["rootfs"] = args.rootfs
    if getattr(args, "firecracker", None):
        run_kwargs["firecracker"] = args.firecracker
    if getattr(args, "manage_firewall", False):
        run_kwargs["manage_firewall"] = True
    return run_kwargs


__all__ = [
    "detect_default_branch",
    "claude_code_secrets",
    "add_sandbox_args",
    "run_kwargs_from_args",
]
