"""Three-tier discovery of the crucible-core binary."""
import os
import shutil
from pathlib import Path


def find_core_bin() -> list[str]:
    """Return argv prefix to invoke crucible-core (may be [interpreter, script] or [path])."""
    env_val = os.environ.get("CRUCIBLE_CORE_BIN")
    if env_val:
        return env_val.split()

    # workspace target/release
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "target" / "release" / "crucible-core"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return [str(candidate)]

    found = shutil.which("crucible-core")
    if found:
        return [found]

    raise FileNotFoundError(
        "crucible-core not found. Set CRUCIBLE_CORE_BIN, build with `cargo build --release`, "
        "or add crucible-core to $PATH."
    )
