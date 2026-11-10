"""`python main.py -h` shows argparse's help, not the startup banner.

main.py prints an ASCII banner and probes the environment before running a
command. For -h / --help that output is noise in front of the help text, so
the args are parsed first: argparse prints help and exits during parsing,
before the banner is reached. A normal run still shows the banner.
"""
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
# Unique to the banner box. "Network Security Toolkit" would be a poor marker:
# it is also the parser's description, which argparse prints in the help.
_BANNER_MARK = "Authorised use only"


def _run(*args):
    return subprocess.run([sys.executable, "main.py", *args], cwd=_ROOT,
                          capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_prints_usage_without_the_banner(flag):
    proc = _run(flag)
    assert proc.returncode == 0
    assert "usage: droidnet" in proc.stdout
    assert "show this help message and exit" in proc.stdout
    # The banner box and the environment probe must not precede the help.
    assert _BANNER_MARK not in proc.stdout
    assert "Probing operating environment" not in proc.stdout


def test_subcommand_help_also_skips_the_banner():
    proc = _run("cve", "--help")
    assert proc.returncode == 0
    assert "usage: droidnet cve" in proc.stdout
    assert _BANNER_MARK not in proc.stdout


def test_an_unknown_command_errors_without_the_banner():
    proc = _run("nope")
    assert proc.returncode != 0
    assert "invalid choice" in proc.stderr
    assert _BANNER_MARK not in proc.stdout
