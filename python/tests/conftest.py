import os
import sys
from pathlib import Path

# Point CRUCIBLE_CORE_BIN at the stub for all tests
STUB = Path(__file__).parent / "fixtures" / "stub_crucible_core.py"

def pytest_configure(config):
    os.environ.setdefault("CRUCIBLE_CORE_BIN", f"{sys.executable} {STUB}")
