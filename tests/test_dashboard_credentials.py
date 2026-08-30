"""Unit tests for dashboard credentials persistence (~/.sentinel/credentials)."""

import os
from pathlib import Path

import pytest

# Skip cleanly on environments where Flask is not installed.
pytest.importorskip("flask")

# Importing dashboard runs module-level credential init. Set SENTINEL_PASS
# beforehand so the auto-gen branch (which would touch ~/.sentinel) does not
# fire on import.
os.environ.setdefault("SENTINEL_PASS", "test-import-only")

from droidnet.web import dashboard as dash  # noqa: E402


@pytest.fixture
def cred_paths(tmp_path: Path, monkeypatch):
    """Redirect _CRED_DIR / _CRED_FILE to a tmp location for the test."""
    cred_dir  = tmp_path / ".sentinel"
    cred_file = cred_dir / "credentials"
    monkeypatch.setattr(dash, "_CRED_DIR", cred_dir)
    monkeypatch.setattr(dash, "_CRED_FILE", cred_file)
    return cred_dir, cred_file


def test_persist_writes_file_with_0600(cred_paths):
    _, cred_file = cred_paths
    ok = dash._persist_password("hunter2")
    assert ok is True
    assert cred_file.read_text() == "hunter2"
    mode = cred_file.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0600 got {oct(mode)}"


def test_persist_creates_dir_with_0700(cred_paths):
    cred_dir, _ = cred_paths
    dash._persist_password("x")
    mode = cred_dir.stat().st_mode & 0o777
    assert mode == 0o700, f"expected 0700 got {oct(mode)}"


def test_read_returns_none_when_missing(cred_paths):
    assert dash._read_persisted_password() is None


def test_read_round_trip(cred_paths):
    dash._persist_password("super-secret")
    assert dash._read_persisted_password() == "super-secret"


def test_read_rejects_world_readable_file(cred_paths):
    _, cred_file = cred_paths
    dash._persist_password("leaky")
    # Loosen perms — read must refuse.
    os.chmod(cred_file, 0o644)
    assert dash._read_persisted_password() is None


def test_read_rejects_group_readable_file(cred_paths):
    _, cred_file = cred_paths
    dash._persist_password("leaky")
    os.chmod(cred_file, 0o640)
    assert dash._read_persisted_password() is None


def test_persist_overwrites_existing(cred_paths):
    _, cred_file = cred_paths
    dash._persist_password("first")
    dash._persist_password("second")
    assert cred_file.read_text() == "second"
    assert (cred_file.stat().st_mode & 0o777) == 0o600


def test_read_strips_trailing_whitespace(cred_paths):
    _, cred_file = cred_paths
    cred_file.parent.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(cred_file, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, b"padded  \n")
    os.close(fd)
    assert dash._read_persisted_password() == "padded"
