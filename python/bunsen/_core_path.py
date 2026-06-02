"""Five-tier discovery of the bunsen-core binary.

Order of resolution:

1. ``BUNSEN_CORE_BIN`` env var — developer override, full argv string.
2. Package-relative ``<bunsen>/bin/bunsen-core`` — installed-wheel layout.
3. Sibling of ``sys.executable`` — maturin bin-binding installs here (works under sudo).
4. ``target/release/bunsen-core`` walking up from this file — local cargo build.
5. ``shutil.which("bunsen-core")`` — anything on ``PATH``.
"""
import os
import shutil
import sys
from pathlib import Path


def find_core_bin() -> list[str]:
    """Return argv prefix to invoke bunsen-core (may be [interpreter, script] or [path])."""
    env_val = os.environ.get("BUNSEN_CORE_BIN")
    if env_val:
        return env_val.split()

    here = Path(__file__).resolve()

    # Tier 2: package-relative path inside an installed wheel.
    pkg_bin = here.parent / "bin" / "bunsen-core"
    if pkg_bin.is_file() and os.access(pkg_bin, os.X_OK):
        return [str(pkg_bin)]

    # Tier 3: sibling of sys.executable — maturin `bindings = "bin"` installs the
    # binary next to the Python interpreter in the venv's bin/ directory.  This path
    # is absolute so it survives sudo's PATH reset.
    py_sibling = Path(sys.executable).resolve().parent / "bunsen-core"
    if py_sibling.is_file() and os.access(py_sibling, os.X_OK):
        return [str(py_sibling)]

    # Tier 4: workspace target/release (cargo dev build).
    for parent in here.parents:
        candidate = parent / "target" / "release" / "bunsen-core"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return [str(candidate)]

    # Tier 5: anything on PATH.
    found = shutil.which("bunsen-core")
    if found:
        return [found]

    raise FileNotFoundError(
        "bunsen-core not found. Either:\n"
        "  - set BUNSEN_CORE_BIN to the full argv string, or\n"
        "  - pip install a published bunsen wheel (binary at bunsen/bin/bunsen-core), or\n"
        "  - run `cargo build --release` from a workspace checkout, or\n"
        "  - add bunsen-core to $PATH."
    )
