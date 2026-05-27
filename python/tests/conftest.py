import os
import sys
from pathlib import Path

# Point BUNSEN_CORE_BIN at the stub for all tests
STUB = Path(__file__).parent / "fixtures" / "stub_bunsen_core.py"

def pytest_configure(config):
    os.environ.setdefault("BUNSEN_CORE_BIN", f"{sys.executable} {STUB}")
