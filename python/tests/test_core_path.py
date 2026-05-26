"""Tests for the four-tier crucible-core binary discovery in `_core_path`."""
from __future__ import annotations

import importlib
import os
import stat
import sys
from pathlib import Path

import pytest


@pytest.fixture
def core_path_module(monkeypatch):
    """Provide a fresh import of `crucible._core_path` with CRUCIBLE_CORE_BIN cleared.

    `conftest.py` sets `CRUCIBLE_CORE_BIN` for the rest of the suite (pointing at
    the stub). The discovery tiers below tier 1 only fire when that env var is
    unset, so each test starts from an empty environment and adds back what it
    needs.
    """
    monkeypatch.delenv("CRUCIBLE_CORE_BIN", raising=False)
    if "crucible._core_path" in sys.modules:
        importlib.reload(sys.modules["crucible._core_path"])
    import crucible._core_path as cp
    return cp


def _make_exec(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_env_var_overrides_everything(core_path_module, monkeypatch, tmp_path):
    """Tier 1: CRUCIBLE_CORE_BIN wins even if a package-relative binary exists."""
    pkg_dir = Path(core_path_module.__file__).parent
    pkg_bin = pkg_dir / "bin" / "crucible-core"
    _make_exec(pkg_bin)
    try:
        monkeypatch.setenv("CRUCIBLE_CORE_BIN", "/custom/path/crucible-core --flag")
        argv = core_path_module.find_core_bin()
        assert argv == ["/custom/path/crucible-core", "--flag"]
    finally:
        pkg_bin.unlink(missing_ok=True)
        try:
            pkg_bin.parent.rmdir()
        except OSError:
            pass


def test_package_relative_tier_returns_bundled_binary(core_path_module):
    """Tier 2 (new): `<crucible package>/bin/crucible-core` is returned when present."""
    pkg_dir = Path(core_path_module.__file__).parent
    pkg_bin = pkg_dir / "bin" / "crucible-core"
    _make_exec(pkg_bin)
    try:
        argv = core_path_module.find_core_bin()
        assert argv == [str(pkg_bin)]
    finally:
        pkg_bin.unlink(missing_ok=True)
        try:
            pkg_bin.parent.rmdir()
        except OSError:
            pass


def test_workspace_target_release_tier_returns_dev_build(core_path_module, tmp_path, monkeypatch):
    """Tier 3 (unchanged): walks up from the package and finds `target/release/crucible-core`.

    Verified end-to-end by the existing test suite + the `pip install -e ./python`
    developer workflow: with the env var unset and no package-relative binary, the
    parent-walk locates `target/release/crucible-core` after `cargo build --release`.
    """
    # Guard against PATH-tier interference; isolate the walk-up tier.
    monkeypatch.setenv("PATH", str(tmp_path))
    pkg_dir = Path(core_path_module.__file__).parent
    pkg_bin = pkg_dir / "bin" / "crucible-core"
    if pkg_bin.exists():
        pytest.skip("package-relative binary present from another test")

    repo_root = next(p for p in pkg_dir.parents if (p / "Cargo.toml").exists())
    target_bin = repo_root / "target" / "release" / "crucible-core"
    if not (target_bin.is_file() and os.access(target_bin, os.X_OK)):
        pytest.skip("target/release/crucible-core not built — covered by integration env")

    argv = core_path_module.find_core_bin()
    assert argv == [str(target_bin)]


def test_path_tier_used_when_no_other_match(core_path_module, tmp_path, monkeypatch):
    """Tier 4: `shutil.which` on PATH is the last fallback."""
    pkg_dir = Path(core_path_module.__file__).parent
    pkg_bin = pkg_dir / "bin" / "crucible-core"
    if pkg_bin.exists():
        pytest.skip("package-relative binary present from another test")

    # Build a fake PATH that contains only our stub.
    fake_bin = tmp_path / "crucible-core"
    _make_exec(fake_bin)
    monkeypatch.setenv("PATH", str(tmp_path))

    # Suppress tier 3 by making the parent-walk find nothing relevant.
    # We rely on `repo_root / target / release / crucible-core` not existing in
    # tmp_path's parents — true by construction.
    fake_module_root = tmp_path / "fakepkg" / "crucible"
    fake_module_root.mkdir(parents=True)
    fake_init = fake_module_root / "__init__.py"
    fake_init.write_text("")
    fake_core_path_src = (Path(core_path_module.__file__)).read_text()
    (fake_module_root / "_core_path.py").write_text(fake_core_path_src)

    # Load the copy from the isolated location so the parent walk sees no
    # Cargo workspace above it.
    monkeypatch.syspath_prepend(str(tmp_path / "fakepkg"))
    sys.modules.pop("crucible", None)
    sys.modules.pop("crucible._core_path", None)
    try:
        cp_iso = importlib.import_module("crucible._core_path")
        argv = cp_iso.find_core_bin()
        assert argv == [str(fake_bin)]
    finally:
        sys.modules.pop("crucible", None)
        sys.modules.pop("crucible._core_path", None)


def test_no_match_raises_filenotfound(core_path_module, tmp_path, monkeypatch):
    """When no tier matches, raise FileNotFoundError with a helpful message."""
    pkg_dir = Path(core_path_module.__file__).parent
    pkg_bin = pkg_dir / "bin" / "crucible-core"
    if pkg_bin.exists():
        pytest.skip("package-relative binary present from another test")

    # Empty PATH so the PATH tier finds nothing.
    monkeypatch.setenv("PATH", str(tmp_path))

    # Isolate the import so the parent walk for target/release also misses.
    fake_module_root = tmp_path / "fakepkg" / "crucible"
    fake_module_root.mkdir(parents=True)
    (fake_module_root / "__init__.py").write_text("")
    fake_core_path_src = (Path(core_path_module.__file__)).read_text()
    (fake_module_root / "_core_path.py").write_text(fake_core_path_src)
    monkeypatch.syspath_prepend(str(tmp_path / "fakepkg"))
    sys.modules.pop("crucible", None)
    sys.modules.pop("crucible._core_path", None)
    try:
        cp_iso = importlib.import_module("crucible._core_path")
        with pytest.raises(FileNotFoundError) as exc_info:
            cp_iso.find_core_bin()
        msg = str(exc_info.value)
        # Helpful message must name each tier the user can act on.
        assert "CRUCIBLE_CORE_BIN" in msg
        assert "pip install" in msg or "wheel" in msg or "crucible/bin" in msg
        assert "cargo build" in msg
        assert "PATH" in msg
    finally:
        sys.modules.pop("crucible", None)
        sys.modules.pop("crucible._core_path", None)
