"""
Project-level pytest config.

- Makes `import droidnet...` work regardless of where pytest is invoked from,
  without requiring an installed package.
- Keeps the suite away from the operator's real data: logs go to a throwaway
  directory and every test gets its own history database.
"""

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

# Must run before anything imports droidnet: the logger reads
# DROIDNET_LOG_DIR at import time and opens its file on first use, so setting
# it here keeps every test log line out of the project's real logs/.
_TEST_LOG_DIR = tempfile.mkdtemp(prefix="droidnet-test-logs-")
os.environ["DROIDNET_LOG_DIR"] = _TEST_LOG_DIR

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TEST_LOG_DIR, ignore_errors=True)


@pytest.fixture(autouse=True)
def _isolated_history_db(tmp_path, monkeypatch):
    """Never let a test read or write the real history database.

    Every test gets a fresh, initialised SQLite file; tests that need their
    own path still override DB_PATH themselves.
    """
    from droidnet.core import database
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "isolated-history.db")
    database.init_db()
