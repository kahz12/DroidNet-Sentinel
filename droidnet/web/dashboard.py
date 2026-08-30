"""
Flask Command Center — web dashboard for Sentinel audit reports.

Authentication:
    Session-based login (Flask sessions + HMAC credential check).
    Configure via environment variables:
        SENTINEL_USER   → username  (default: admin)
        SENTINEL_PASS   → password  (auto-generated if absent)
        SENTINEL_SECRET → Flask secret key (auto-generated if absent)

    Set credentials before exposing to a network:
        export SENTINEL_USER="myuser"
        export SENTINEL_PASS="mypassword"

Routes:
    GET  /login              → login form
    POST /login              → authenticate and start session
    GET  /logout             → end session
    GET  /                   → HTML dashboard          (auth required)
    GET  /help               → in-app help / user guide (auth required)
    GET  /api/reports        → raw JSON, all scans     (auth required)
    GET  /api/scan/<id>/diff → diff JSON for one scan  (auth required)

Data source:
    SQLite via droidnet.core.database (sentinel.db in project root).
    JSON flat files are still written by sentinel.py for portability.
"""

import hmac
import os
import secrets
import stat
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse

from flask import (
    Flask, render_template, jsonify,
    request, session, redirect, url_for, abort, Response,
)
from flask.typing import ResponseReturnValue

from droidnet.core.logger import get_logger
from droidnet.core.database import (
    init_db,
    get_all_scans,
    get_all_scans_with_diffs,
    get_scan_diff,
    count_scans,
)

log = get_logger(__name__)

# ── App setup ─────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SENTINEL_SECRET") or secrets.token_hex(32)

# Session cookie hardening + 8h timeout.
app.config.update(
    SESSION_COOKIE_HTTPONLY      = True,
    SESSION_COOKIE_SAMESITE      = "Lax",
    PERMANENT_SESSION_LIFETIME   = timedelta(hours=8),
)

# Content-Security-Policy and related hardening headers. The UI ships no
# JavaScript, so scripts are blocked outright; inline styles are allowed
# because the templates embed their CSS.
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'none'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy":        "same-origin",
    "X-Frame-Options":        "DENY",
}


@app.after_request
def _apply_security_headers(response: Response) -> Response:
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response

_USER = os.environ.get("SENTINEL_USER", "admin")

# Auto-generated credentials are persisted at ~/.sentinel/credentials with
# 0600 perms instead of being printed to stdout, where redirected logs or a
# shared tmux pane could leak them. The env var still wins when set.
_CRED_DIR  = Path.home() / ".sentinel"
_CRED_FILE = _CRED_DIR / "credentials"


def _read_persisted_password() -> str | None:
    """
    Return the password stored in ~/.sentinel/credentials (one line, plain
    text). Refuses world/group-readable files. Returns None on miss/error.
    """
    try:
        st = _CRED_FILE.stat()
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        log.warning("ignoring %s: not 0600 (mode=%o)", _CRED_FILE, st.st_mode & 0o777)
        return None
    try:
        text = _CRED_FILE.read_text().strip()
    except OSError:
        return None
    return text or None


def _persist_password(password: str) -> bool:
    """
    Atomically write *password* to ~/.sentinel/credentials with 0600 perms.
    Returns True on success.
    """
    try:
        _CRED_DIR.mkdir(mode=0o700, exist_ok=True)
        os.chmod(_CRED_DIR, 0o700)
        # Open with O_CREAT|O_WRONLY|O_TRUNC and explicit mode so we never
        # widen perms via umask races.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(_CRED_FILE, flags, 0o600)
        try:
            os.write(fd, password.encode())
        finally:
            os.close(fd)
        os.chmod(_CRED_FILE, 0o600)
        return True
    except OSError as exc:
        log.warning("could not persist credentials to %s: %s", _CRED_FILE, exc)
        return False


_PASS_FROM_ENV = os.environ.get("SENTINEL_PASS")
if _PASS_FROM_ENV:
    _PASS = _PASS_FROM_ENV
    _GENERATED_PASS = False
    _PASS_PERSISTED = False
else:
    _persisted = _read_persisted_password()
    if _persisted:
        _PASS = _persisted
        _GENERATED_PASS = False
        _PASS_PERSISTED = True
    else:
        _PASS = secrets.token_urlsafe(16)
        _GENERATED_PASS = True
        _PASS_PERSISTED = _persist_password(_PASS)

# ══════════════════════════════════════════════════════════════════
#  Rate limiter for /login (5 attempts / min / IP)
# ══════════════════════════════════════════════════════════════════
#
# State is per-process: correct for the built-in single-worker server, but
# NOT shared across workers. For a multi-worker WSGI deployment install the
# `server` extra (flask-limiter + flask-wtf) and back it with redis/memcached.

_LOGIN_WINDOW_SEC = 60.0
_LOGIN_MAX_TRIES  = 5
_LOGIN_MAX_IPS    = 10_000   # soft cap: beyond this, sweep fully-expired buckets
_login_attempts: dict[str, deque[float]] = defaultdict(deque)
_login_lock = Lock()


def _client_ip() -> str:
    """Client IP for rate-limiting. Does not trust X-Forwarded-For by default."""
    return request.remote_addr or "unknown"


def _sweep_login_attempts(now: float) -> None:
    """
    Drop buckets whose entire window has expired. Caller must hold _login_lock.

    The rate-limit check does not remove emptied buckets, so this keeps the map
    from growing once per distinct source IP over time.
    """
    cutoff = now - _LOGIN_WINDOW_SEC
    stale = [ip for ip, bucket in _login_attempts.items()
             if not bucket or bucket[-1] < cutoff]
    for ip in stale:
        del _login_attempts[ip]


def _login_rate_limited(ip: str) -> bool:
    """
    Returns True if *ip* has exhausted its attempt quota in the window.
    Registers the current attempt when there is still quota.
    """
    now = time.monotonic()
    with _login_lock:
        if len(_login_attempts) > _LOGIN_MAX_IPS:
            _sweep_login_attempts(now)
        bucket = _login_attempts[ip]
        while bucket and bucket[0] < now - _LOGIN_WINDOW_SEC:
            bucket.popleft()
        if len(bucket) >= _LOGIN_MAX_TRIES:
            return True
        bucket.append(now)
        return False


def _safe_next(value: str) -> str:
    """
    Normalise the post-login ``next`` redirect target.

    Only same-site, root-relative paths are returned. Protocol-relative
    (``//host``) and absolute (``scheme://host``) URLs collapse to ``/``.
    """
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    # Browsers fold "\\" into "/", so "/\\host" resolves to "//host" (off-site).
    if "\\" in value:
        return "/"
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        return "/"
    return value


# ══════════════════════════════════════════════════════════════════
#  CSRF token (per-session, without external dependency)
# ══════════════════════════════════════════════════════════════════

def _get_csrf_token() -> str:
    """Returns the session's CSRF token, generating it if missing."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _csrf_ok(form_token: str) -> bool:
    """Constant-time comparison of the submitted token vs the session token."""
    expected = session.get("_csrf_token", "")
    if not expected or not form_token:
        return False
    return hmac.compare_digest(form_token, expected)


# ══════════════════════════════════════════════════════════════════
#  Auth helpers
# ══════════════════════════════════════════════════════════════════

def _check_credentials(username: str, password: str) -> bool:
    """Constant-time credential comparison to prevent timing attacks."""
    ok_user = hmac.compare_digest(username, _USER)
    ok_pass = hmac.compare_digest(password, _PASS)
    return ok_user and ok_pass


def login_required(f: Callable) -> Callable:
    """Route decorator: redirect to /login when no active session exists."""
    @wraps(f)
    def decorated(*args, **kwargs) -> ResponseReturnValue:
        if not session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════
#  HTML templates
# ══════════════════════════════════════════════════════════════════
#
# Rendered from droidnet/web/templates/ (login.html, dashboard.html,
# help.html); the shared design system lives in _base_css.html.


# ══════════════════════════════════════════════════════════════════
#  Data helper
# ══════════════════════════════════════════════════════════════════

def _fmt_time(ts: str) -> str:
    try:
        return datetime.strptime(ts, "%Y%m%d_%H%M%S").strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return ts


_DEFAULT_PAGE_SIZE = 20
_MAX_PAGE_SIZE     = 100


def _prepare_scans(page: int = 1, per_page: int = _DEFAULT_PAGE_SIZE) -> list[dict]:
    """Load *page* of scans with diffs and format timestamps."""
    offset = max(0, (page - 1) * per_page)
    scans = get_all_scans_with_diffs(limit=per_page, offset=offset)
    for s in scans:
        s["scan_time"] = _fmt_time(s.get("scan_time", ""))
    return scans


def _summarize(scans: list[dict]) -> dict:
    """Counts shown in the summary tiles at the top of the dashboard."""
    new_count = 0
    crit_count = 0
    for s in scans:
        new_count += len(s.get("new_ips", []))
        risks = s.get("risks", {}) or {}
        crit_count += sum(1 for r in risks.values() if r == "CRITICAL")
    return {"new_count": new_count, "crit_count": crit_count}


# ══════════════════════════════════════════════════════════════════
#  Auth routes
# ══════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login() -> ResponseReturnValue:
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error    = None
    next_url = request.args.get("next") or request.form.get("next") or "/"

    if request.method == "POST":
        ip = _client_ip()
        # Rate-limit: count every POST to /login by IP in a 60s window.
        if _login_rate_limited(ip):
            log.warning("login rate-limited ip=%s", ip)
            error = (
                f"Too many attempts. Wait {int(_LOGIN_WINDOW_SEC)}s "
                f"before retrying."
            )
            return render_template(
                "login.html",
                error=error,
                next_url=next_url,
                csrf_token=_get_csrf_token(),
            ), 429

        # CSRF: the token must match the one from the session that served the GET.
        if not _csrf_ok(request.form.get("_csrf", "")):
            log.warning("login csrf-fail ip=%s", ip)
            error = "Invalid CSRF token. Reload the page and try again."
            return render_template(
                "login.html",
                error=error,
                next_url=next_url,
                csrf_token=_get_csrf_token(),
            ), 400

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if _check_credentials(username, password):
            # Session opt-in to permanent so lifetime applies.
            session.clear()
            session.permanent        = True
            session["authenticated"] = True
            session["user"]          = username
            # Rotate CSRF token after login.
            session["_csrf_token"]   = secrets.token_urlsafe(32)
            log.info("login ok user=%s ip=%s", username, ip)
            return redirect(_safe_next(next_url))
        log.warning("login fail user=%s ip=%s", username, ip)
        error = "Invalid credentials. Try again."

    return render_template(
        "login.html",
        error=error,
        next_url=next_url,
        csrf_token=_get_csrf_token(),
    )


@app.route("/logout")
def logout() -> ResponseReturnValue:
    session.clear()
    return redirect(url_for("login"))


# ══════════════════════════════════════════════════════════════════
#  Dashboard routes
# ══════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def index() -> ResponseReturnValue:
    """Render the main HTML dashboard with pagination."""
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = int(request.args.get("per_page", _DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        per_page = _DEFAULT_PAGE_SIZE
    per_page = max(1, min(per_page, _MAX_PAGE_SIZE))

    total      = count_scans()
    total_pages = max(1, (total + per_page - 1) // per_page)
    page       = min(page, total_pages)

    scans = _prepare_scans(page=page, per_page=per_page)
    stats = _summarize(scans)

    return render_template(
        "dashboard.html",
        scans       = scans,
        stats       = stats,
        page        = page,
        per_page    = per_page,
        total       = total,
        total_pages = total_pages,
        has_prev    = page > 1,
        has_next    = page < total_pages,
    )


@app.route("/help")
@login_required
def help_page() -> ResponseReturnValue:
    """In-app help / user guide."""
    return render_template("help.html")


@app.route("/api/reports")
@login_required
def api_reports() -> ResponseReturnValue:
    """Return all scans as raw JSON (for external integrations)."""
    return jsonify(get_all_scans())


@app.route("/api/scan/<int:scan_id>/diff")
@login_required
def api_scan_diff(scan_id: int) -> ResponseReturnValue:
    """Return diff data for a specific scan vs the previous scan."""
    data = get_scan_diff(scan_id)
    if not data:
        abort(404)
    return jsonify(data)


# ══════════════════════════════════════════════════════════════════
#  Standalone entry point
# ══════════════════════════════════════════════════════════════════

def _print_startup_banner(host: str = "127.0.0.1", port: int = 5000) -> None:
    """Print server info, bind hint and credential warnings at startup."""
    # Ensure the schema exists before serving (idempotent). Done here, the
    # shared pre-serve hook, so importing the module never touches the DB.
    init_db()
    print("[*] Starting Command Center with authentication...")
    bind_label = "LAN (0.0.0.0)" if host == "0.0.0.0" else "loopback (127.0.0.1)"
    print(f"[+] Bind: {bind_label} port {port}")
    if host == "0.0.0.0":
        print("[!] Dashboard exposed to the LAN. Front it with a TLS proxy")
        print("    (nginx / caddy) — credentials travel in plaintext otherwise.")
        print("[!] Run a single worker: the built-in rate-limit and CSRF are")
        print("    per-process. Multi-worker needs the `server` extra + redis.")
    if _GENERATED_PASS:
        print("[!] SENTINEL_PASS not configured — a temporary password was generated.")
        if _PASS_PERSISTED:
            print(f"[+] Credentials saved to {_CRED_FILE} (mode 0600).")
            print(f"    Read with:  cat {_CRED_FILE}")
        else:
            # Fallback only — could not write the file (read-only FS, etc.).
            print("[!] Could not persist credentials. One-shot output below:")
            print(f"    username={_USER}  password={_PASS}")
        print(f"[+] http://{host}:{port}  (username: {_USER})")
        print("[!] Configure SENTINEL_PASS for production:")
        print('      export SENTINEL_PASS="your_secure_password"')
    else:
        print(f"[+] http://{host}:{port}  (username: {_USER})")


if __name__ == "__main__":
    _print_startup_banner(host="127.0.0.1")
    app.run(host="127.0.0.1", port=5000, debug=False)
