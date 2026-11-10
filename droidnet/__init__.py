"""DroidNet Sentinel — Network Security Toolkit."""

import os
import re
from pathlib import Path

__version__ = "1.0.0"

_DOTENV_LINE = re.compile(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*")


def load_dotenv(path: Path) -> list[str]:
    """Copy the NAME=value lines of *path* into os.environ; return the names set.

    Secrets (VULNERS_API_KEY, TELEGRAM_TOKEN, SENTINEL_PASS, NVD_API_KEY...)
    can live in a .env file at the project root instead of a shell profile.
    Modules read their variables when imported, so this runs from the
    package's __init__, before any of them. A variable already set in the
    environment wins: `VAR=... python main.py` still overrides the file for
    one run. Accepts `export NAME=value`, single or double quotes and "#"
    comments; any other line is ignored. Values are never printed or logged.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    loaded = []
    for line in lines:
        match = _DOTENV_LINE.fullmatch(line)
        if not match or line.lstrip().startswith("#"):
            continue
        name, value = match.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            # Unquoted values may carry a trailing comment: "abc  # note" → "abc".
            value = re.sub(r"\s+#.*$", "", value)
        if name not in os.environ:
            os.environ[name] = value
            loaded.append(name)
    return loaded


# DROIDNET_DOTENV=0 skips the file; the test suite sets it so a developer's
# own .env never changes a test result.
if os.environ.get("DROIDNET_DOTENV", "1") != "0":
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
