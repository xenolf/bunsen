"""Four-tier discovery of the crucible-core binary.

Order of resolution:

1. ``CRUCIBLE_CORE_BIN`` env var — developer override, full argv string.
2. Package-relative ``<crucible>/bin/crucible-core`` — installed-wheel layout.
3. ``target/release/crucible-core`` walking up from this file — local cargo build.
4. ``shutil.which("crucible-core")`` — anything on ``PATH``.
"""
import os
import shutil
from pathlib import Path


def find_core_bin() -> list[str]:
    """Return argv prefix to invoke crucible-core (may be [interpreter, script] or [path])."""
    env_val = os.environ.get("CRUCIBLE_CORE_BIN")
    if env_val:
        return env_val.split()

    here = Path(__file__).resolve()

    # Tier 2: package-relative path inside an installed wheel.
    pkg_bin = here.parent / "bin" / "crucible-core"
    if pkg_bin.is_file() and os.access(pkg_bin, os.X_OK):
        return [str(pkg_bin)]

    # Tier 3: workspace target/release (cargo dev build).
    for parent in here.parents:
        candidate = parent / "target" / "release" / "crucible-core"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return [str(candidate)]

    # Tier 4: anything on PATH.
    found = shutil.which("crucible-core")
    if found:
        return [found]

    raise FileNotFoundError(
        "crucible-core not found. Either:\n"
        "  - set CRUCIBLE_CORE_BIN to the full argv string, or\n"
        "  - pip install a published crucible wheel (binary at crucible/bin/crucible-core), or\n"
        "  - run `cargo build --release` from a workspace checkout, or\n"
        "  - add crucible-core to $PATH."
    )
