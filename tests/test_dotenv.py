"""Secrets can live in a .env file at the project root.

VULNERS_API_KEY, TELEGRAM_TOKEN, SENTINEL_PASS, NVD_API_KEY and the rest are
read from the environment when their modules are imported, so the file is
loaded from the package's __init__, before any of them. A variable already
set in the environment wins: `VAR=... python main.py` still overrides the file
for one run. The suite itself runs with DROIDNET_DOTENV=0 (see conftest.py)
so a developer's own .env never changes a test result.
"""
import os

import pytest

from droidnet import load_dotenv

NAMES = ("DN_TEST_PLAIN", "DN_TEST_EXPORTED", "DN_TEST_DOUBLE", "DN_TEST_SINGLE",
         "DN_TEST_COMMENTED", "DN_TEST_HASH_IN_QUOTES", "DN_TEST_EMPTY", "DN_TEST_PRESET")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)


def write(tmp_path, text):
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return path


def test_supported_line_forms(tmp_path):
    path = write(tmp_path, "\n".join([
        "# a comment line",
        "",
        "DN_TEST_PLAIN=plain-value",
        "export DN_TEST_EXPORTED=exported",
        'DN_TEST_DOUBLE="double quoted"',
        "DN_TEST_SINGLE='single quoted'",
        "DN_TEST_COMMENTED=value   # trailing comment",
        'DN_TEST_HASH_IN_QUOTES="a#b"',
        "DN_TEST_EMPTY=",
    ]))
    loaded = load_dotenv(path)
    assert os.environ["DN_TEST_PLAIN"] == "plain-value"
    assert os.environ["DN_TEST_EXPORTED"] == "exported"
    assert os.environ["DN_TEST_DOUBLE"] == "double quoted"
    assert os.environ["DN_TEST_SINGLE"] == "single quoted"
    assert os.environ["DN_TEST_COMMENTED"] == "value"
    assert os.environ["DN_TEST_HASH_IN_QUOTES"] == "a#b"
    assert os.environ["DN_TEST_EMPTY"] == ""
    assert loaded == ["DN_TEST_PLAIN", "DN_TEST_EXPORTED", "DN_TEST_DOUBLE", "DN_TEST_SINGLE",
                      "DN_TEST_COMMENTED", "DN_TEST_HASH_IN_QUOTES", "DN_TEST_EMPTY"]


@pytest.mark.parametrize("line", [
    'X-Api-Key="0123456789abcdef"',     # an HTTP header name is not a variable name
    "just-a-bare-value",
    "1NAME=starts with a digit",
])
def test_lines_that_are_not_assignments_are_ignored(tmp_path, line):
    before = dict(os.environ)
    assert load_dotenv(write(tmp_path, line)) == []
    assert dict(os.environ) == before


def test_the_environment_wins_over_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DN_TEST_PRESET", "from-the-shell")
    assert load_dotenv(write(tmp_path, "DN_TEST_PRESET=from-the-file")) == []
    assert os.environ["DN_TEST_PRESET"] == "from-the-shell"


def test_missing_or_unreadable_file_is_not_an_error(tmp_path):
    assert load_dotenv(tmp_path / "absent.env") == []
    binary = tmp_path / "binary.env"
    binary.write_bytes(b"\xff\xfe\x00not utf-8")
    assert load_dotenv(binary) == []


def test_returns_names_never_values(tmp_path):
    loaded = load_dotenv(write(tmp_path, "DN_TEST_PLAIN=s3cr3t-value"))
    assert loaded == ["DN_TEST_PLAIN"]
    assert "s3cr3t-value" not in repr(loaded)
