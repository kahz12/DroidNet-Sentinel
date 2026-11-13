"""Command examples shown to users match the parser that runs them.

main.py's docstring and the menu's help panels list commands by hand. These
tests tie every example to the real argparse parser, so renaming a command or
flag cannot leave a stale example behind, and check that the panels render
each example readably.
"""
import argparse
import ast
import io
import re
from pathlib import Path

import pytest
from rich.console import Console

from droidnet.cli import args as cli_args
from droidnet.cli import menu

_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE = re.compile(r"python main\.py (.*)")
_WORD = re.compile(r"[a-z][\w-]*")


def _subcommands(parser):
    action = next((a for a in parser._actions if isinstance(a, argparse._SubParsersAction)), None)
    return action.choices if action else {}


def _resolve(example):
    """Follow an example's leading words down the subcommand tree.

    Returns (words, parser): the command words that were recognised and the
    parser that owns the flags written after them.
    """
    parser, words = cli_args._build_parser(), []
    for token in example.split():
        if not _WORD.fullmatch(token) or token not in _subcommands(parser):
            break
        parser = _subcommands(parser)[token]
        words.append(token)
    return words, parser


def _main_examples():
    doc = ast.get_docstring(ast.parse((_ROOT / "main.py").read_text(encoding="utf-8")))
    return [m.group(1).strip() for m in _EXAMPLE.finditer(doc)]


def _panel_examples(panel):
    rec = Console(file=io.StringIO(), record=True, width=120, color_system=None)
    rec.print(panel)
    lines = [line.strip().strip("│").strip() for line in rec.export_text().splitlines()]
    return [line for line in lines if line.startswith("python main.py")]


# ── main.py docstring ──────────────────────────────────────────────

def test_main_docstring_lists_every_subcommand():
    listed = {_resolve(example)[0][0] for example in _main_examples() if _resolve(example)[0]}
    commands = set(_subcommands(cli_args._build_parser())) - {"cve-watch"}   # alias of cve
    assert listed == commands


def test_main_docstring_shows_no_flat_legacy_flags():
    # The flat --scan / --hunt flags are still accepted for existing scripts,
    # but examples teach the subcommands.
    assert not [e for e in _main_examples() if e.startswith("--")]


@pytest.mark.parametrize("example", _main_examples())
def test_main_docstring_flags_exist(example):
    words, parser = _resolve(example)
    for flag in re.findall(r"--[a-z][a-z-]*", example):
        assert flag in parser._option_string_actions, (example, flag)
    assert words or example.split()[0] in ("-h", "<command>"), example


# ── menu help panels ───────────────────────────────────────────────

def test_cli_panel_examples_are_real_commands():
    for line in _panel_examples(menu._help_cli()):
        words, parser = _resolve(line.removeprefix("python main.py "))
        assert words, line
        for flag in re.findall(r"--[a-z][a-z-]*", line):
            assert flag in parser._option_string_actions, (line, flag)


def test_cli_panel_separates_each_command_from_its_description():
    # At least two spaces between the command column and the description,
    # whatever the command's length.
    for line in _panel_examples(menu._help_cli()):
        assert re.search(r"\S {2,}\S", line), line


def test_feature_table_does_not_claim_hunter_needs_searchsploit():
    rec = Console(file=io.StringIO(), record=True, width=120, color_system=None)
    rec.print(menu._help_features())
    text = rec.export_text()
    assert "Requires `searchsploit`" not in text
    assert "Vulners" in text


def test_build_parser_does_not_probe_default_interface(monkeypatch):
    monkeypatch.setattr(cli_args, "get_default_iface",
                        lambda: pytest.fail("_build_parser must not call get_default_iface"))
    parser = cli_args._build_parser()
    assert parser.prog == "droidnet"
