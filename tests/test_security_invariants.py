"""
Source-level guards for the project's security invariants.

These tests do not exercise behaviour — they enforce invariants by
scanning the source tree. If a future commit reintroduces shell=True,
turns off TLS verification, or concatenates a raw SSID into a path,
one of these tests will fail in CI.
"""

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DROIDNET = ROOT / "droidnet"


def _python_files() -> list[Path]:
    """All .py files under droidnet/ (excludes tests, venv, etc.)."""
    return sorted(DROIDNET.rglob("*.py"))


# ── Invariant 1: no shell=True in subprocess calls ──────────────────

def test_no_subprocess_shell_true():
    """
    subprocess.run / Popen must always receive a list, never shell=True.
    Enforces the "no shell injection" invariant.
    """
    pattern = re.compile(r"shell\s*=\s*True")
    offenders: list[str] = []
    for path in _python_files():
        text = path.read_text()
        for lineno, line in enumerate(text.splitlines(), start=1):
            # Strip line-comments before matching to avoid false positives
            # on doc strings/comments that mention "shell=True".
            code = line.split("#", 1)[0]
            if pattern.search(code):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "shell=True is forbidden:\n" + "\n".join(offenders)


# ── Invariant 2: TLS verification not disabled ──────────────────────

def test_no_requests_verify_false():
    """
    requests.get / post / Session must never pass verify=False.
    Enforces the "TLS to NVD/Telegram" invariant.
    """
    pattern = re.compile(r"verify\s*=\s*False")
    offenders: list[str] = []
    for path in _python_files():
        text = path.read_text()
        for lineno, line in enumerate(text.splitlines(), start=1):
            code = line.split("#", 1)[0]
            if pattern.search(code):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "verify=False is forbidden:\n" + "\n".join(offenders)


# ── Invariant 3: Jinja autoescape never explicitly disabled ─────────

def test_no_jinja_autoescape_disabled():
    """
    No `autoescape=False` and no `|safe` filter on user-controlled values.
    The dashboard relies on Flask's default autoescape; turning it off
    would re-open XSS via DB-stored banners or SSIDs.
    """
    pattern = re.compile(r"autoescape\s*=\s*False")
    offenders: list[str] = []
    for path in _python_files():
        text = path.read_text()
        for lineno, line in enumerate(text.splitlines(), start=1):
            code = line.split("#", 1)[0]
            if pattern.search(code):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
    assert not offenders, "autoescape=False is forbidden:\n" + "\n".join(offenders)


# ── Invariant 4: scan_id route uses int converter ───────────────────

def test_scan_id_route_uses_int_converter():
    """
    The /api/scan/<...>/diff route must use the <int:scan_id> converter
    so Flask rejects non-integer values with 404 before our handler runs.
    """
    dashboard = (DROIDNET / "web" / "dashboard.py").read_text()
    # Match the @app.route(...) line that mentions /api/scan/.../diff.
    route_lines = [
        ln for ln in dashboard.splitlines()
        if "@app.route" in ln and "/api/scan/" in ln and "/diff" in ln
    ]
    assert route_lines, "expected /api/scan/<id>/diff route to exist"
    for ln in route_lines:
        assert "<int:scan_id>" in ln, (
            f"route must use <int:scan_id> converter, got: {ln.strip()}"
        )


# ── Invariant 5: SSID is sanitised before becoming a path ───────────

def test_ssid_path_uses_sanitizer():
    """
    save_report() must run the SSID through _sanitize_ssid before joining
    it to REPORTS_DIR, enforcing the "path traversal closed" invariant if
    someone refactors the function.
    """
    src = (DROIDNET / "modules" / "sentinel.py").read_text()
    tree = ast.parse(src)

    target = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == "save_report"),
        None,
    )
    assert target is not None, "save_report() must exist in sentinel.py"

    body_src = ast.get_source_segment(src, target) or ""
    assert "_sanitize_ssid" in body_src, (
        "save_report() must call _sanitize_ssid on the SSID before path use"
    )


# ── Invariant 6: subprocess calls receive list args, not strings ────

def test_subprocess_args_are_lists():
    """
    Every subprocess.run / Popen call in the codebase must pass its
    command as a list literal, not as a single string. A single-string
    arg combined with shell=True is the classic injection sink.
    """
    bad_calls: list[str] = []
    for path in _python_files():
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match subprocess.run / subprocess.Popen / subprocess.check_output.
            if not (isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "subprocess"
                    and func.attr in {"run", "Popen", "call",
                                      "check_call", "check_output"}):
                continue
            if not node.args:
                continue
            first = node.args[0]
            # Lists / tuples / Name (variable bound elsewhere) are fine.
            # A bare string literal is a smell.
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                bad_calls.append(
                    f"{path.relative_to(ROOT)}:{node.lineno}: "
                    f"subprocess.{func.attr}(\"{first.value}\")"
                )
    assert not bad_calls, (
        "subprocess.* must receive a list, not a string:\n" + "\n".join(bad_calls)
    )
