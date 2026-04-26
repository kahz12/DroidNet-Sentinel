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
from functools import wraps
from pathlib import Path
from threading import Lock

from flask import (
    Flask, render_template_string, jsonify,
    request, session, redirect, url_for, abort,
)

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

# Initialise DB schema (idempotent — safe to call on every restart).
init_db()


# ══════════════════════════════════════════════════════════════════
#  Rate limiter for /login (5 attempts / min / IP)
# ══════════════════════════════════════════════════════════════════
#
# If flask-limiter is available it is used; otherwise, in-memory
# fallback based on a sliding window with a deque per IP. Sufficient
# for a single process (the only mode supported by the dashboard today).

_LOGIN_WINDOW_SEC = 60.0
_LOGIN_MAX_TRIES  = 5
_login_attempts: dict[str, deque[float]] = defaultdict(deque)
_login_lock = Lock()


def _client_ip() -> str:
    """Client IP for rate-limiting. Does not trust X-Forwarded-For by default."""
    return request.remote_addr or "unknown"


def _login_rate_limited(ip: str) -> bool:
    """
    Returns True if *ip* has exhausted its attempt quota in the window.
    Registers the current attempt when there is still quota.
    """
    now = time.monotonic()
    with _login_lock:
        bucket = _login_attempts[ip]
        while bucket and bucket[0] < now - _LOGIN_WINDOW_SEC:
            bucket.popleft()
        if len(bucket) >= _LOGIN_MAX_TRIES:
            return True
        bucket.append(now)
        return False


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


def login_required(f):
    """Route decorator: redirect to /login when no active session exists."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════
#  HTML templates
# ══════════════════════════════════════════════════════════════════

_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DroidNet Sentinel | Login</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier New', monospace;
            background: #0d1117;
            color: #c9d1d9;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 40px;
            width: 100%;
            max-width: 360px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }
        h1 { color: #58a6ff; font-size: 1.4em; text-align: center; margin-bottom: 6px; }
        .subtitle { color: #8b949e; font-size: 0.82em; text-align: center; margin-bottom: 28px; }
        label { display: block; color: #8b949e; font-size: 0.82em; margin-bottom: 4px; }
        input {
            width: 100%; padding: 10px 12px;
            background: #0d1117; border: 1px solid #30363d;
            border-radius: 6px; color: #c9d1d9;
            font-family: inherit; font-size: 0.95em;
            margin-bottom: 16px; outline: none;
            transition: border-color 0.2s;
        }
        input:focus { border-color: #58a6ff; }
        button {
            width: 100%; padding: 10px;
            background: #238636; color: #fff;
            border: none; border-radius: 6px;
            font-family: inherit; font-size: 1em;
            cursor: pointer; transition: background 0.2s;
        }
        button:hover { background: #2ea043; }
        .error {
            background: #3d1a1a; border: 1px solid #f85149;
            border-radius: 6px; color: #f85149;
            padding: 10px; font-size: 0.82em;
            margin-bottom: 16px; text-align: center;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ DroidNet Sentinel</h1>
        <p class="subtitle">Command Center — Restricted Access</p>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST" action="{{ url_for('login') }}">
            <input type="hidden" name="next"   value="{{ next_url }}">
            <input type="hidden" name="_csrf"  value="{{ csrf_token }}">
            <label for="u">Username</label>
            <input type="text"     id="u" name="username" autocomplete="username" autofocus>
            <label for="p">Password</label>
            <input type="password" id="p" name="password" autocomplete="current-password">
            <button type="submit">Log in</button>
        </form>
    </div>
</body>
</html>
"""

_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DroidNet Sentinel | Command Center</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; }
        body {
            font-family: 'Courier New', Courier, monospace;
            background: #0d1117; color: #c9d1d9;
            padding: 20px; margin: 0;
        }
        header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 1px solid #30363d; padding-bottom: 12px; margin-bottom: 4px;
        }
        h1 { color: #58a6ff; font-size: 1.5em; }
        .subtitle { color: #8b949e; font-size: 0.85em; margin-bottom: 20px; }
        .logout {
            background: #21262d; border: 1px solid #30363d;
            color: #c9d1d9; padding: 6px 14px; border-radius: 6px;
            font-family: inherit; font-size: 0.82em;
            text-decoration: none; cursor: pointer;
        }
        .logout:hover { background: #30363d; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
        }
        .card {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .card-title { font-size: 1.05em; color: #e6edf3; font-weight: bold; margin-bottom: 4px; }
        .meta {
            font-size: 0.82em; color: #8b949e;
            border-bottom: 1px dashed #30363d;
            padding-bottom: 10px; margin-bottom: 12px;
        }
        .host {
            background: #0d1117; margin-top: 8px;
            border-left: 3px solid #238636; padding: 10px;
            border-radius: 0 4px 4px 0;
        }
        .host.vuln { border-left-color: #f85149; }
        .host.new  { border-left-color: #d29922; }
        .ip { font-weight: bold; color: #79c0ff; }
        .port-ok   { color: #3fb950; font-size: 0.82em; }
        .port-bad  { color: #ff7b72; font-size: 0.82em; }
        .badge {
            display: inline-block; font-size: 0.68em;
            padding: 1px 6px; border-radius: 10px;
            margin-left: 6px; vertical-align: middle;
        }
        .badge-new  { background: #3d2a00; color: #d29922; border: 1px solid #d29922; }
        .risk {
            font-size: 0.72em; font-weight: bold;
            margin-left: 4px; vertical-align: middle;
        }
        .r-critico { color: #f85149; }
        .r-medio   { color: #d29922; }
        .r-bajo    { color: #58a6ff; }
        .r-minimo  { color: #3fb950; }
        .diff-box {
            margin-top: 8px; padding: 8px;
            background: #161b22; border-radius: 4px; font-size: 0.78em;
            border: 1px solid #30363d;
        }
        .diff-label { color: #8b949e; margin-bottom: 3px; }
        .added   { color: #3fb950; }
        .removed { color: #f85149; }
        .gone-list { margin-top: 10px; font-size: 0.78em; color: #8b949e; }
        .pager {
            display: flex; justify-content: center; align-items: center;
            gap: 16px; margin-top: 24px; font-size: 0.85em; color: #8b949e;
        }
        .pager a, .pager span.disabled {
            background: #21262d; border: 1px solid #30363d;
            color: #c9d1d9; padding: 6px 12px; border-radius: 6px;
            text-decoration: none;
        }
        .pager span.disabled { color: #484f58; cursor: not-allowed; }
        .pager a:hover { background: #30363d; }
    </style>
</head>
<body>
    <header>
        <h1>🛡️ Sentinel Command Center</h1>
        <a href="{{ url_for('logout') }}" class="logout">Log out</a>
    </header>
    <p class="subtitle">Network audit history. <i>Powered by DroidNet.</i></p>

    <div class="grid">
    {% for scan in scans %}
        <div class="card">
            <div class="card-title">Network: {{ scan.network }}</div>
            <div class="meta">
                Scan: {{ scan.scan_time }}<br>
                Devices: {{ scan.total_devices }}
                {% if scan.new_ips %}
                  &middot; <span style="color:#d29922">{{ scan.new_ips|length }} new</span>
                {% endif %}
                {% if scan.gone_ips %}
                  &middot; <span style="color:#f85149">{{ scan.gone_ips|length }} disappeared</span>
                {% endif %}
            </div>

            {% for ip, ports in scan.targets.items() %}
                {% set risk    = scan.risks.get(ip, 'MÍNIMO') %}
                {% set is_new  = ip in scan.new_ips %}
                {% set is_vuln = risk in ('CRÍTICO', 'MEDIO', 'BAJO') %}
                <div class="host {% if is_new %}new{% elif is_vuln %}vuln{% endif %}">
                    <span class="ip">{{ ip }}</span>
                    {% if is_new %}<span class="badge badge-new">NEW</span>{% endif %}
                    <span class="risk
                        {% if risk == 'CRÍTICO' %}r-critico
                        {% elif risk == 'MEDIO'  %}r-medio
                        {% elif risk == 'BAJO'   %}r-bajo
                        {% else %}r-minimo{% endif %}">
                        [{{ risk }}]
                    </span><br>

                    {% for port in ports %}
                        {% if is_vuln %}
                            <span class="port-bad">⚠ {{ port }}</span><br>
                        {% else %}
                            <span class="port-ok">✓ {{ port }}</span><br>
                        {% endif %}
                    {% endfor %}

                    {% if ip in scan.port_changes %}
                    <div class="diff-box">
                        <div class="diff-label">Port changes:</div>
                        {% for p in scan.port_changes[ip].added %}
                            <span class="added">+ {{ p }}</span><br>
                        {% endfor %}
                        {% for p in scan.port_changes[ip].removed %}
                            <span class="removed">- {{ p }}</span><br>
                        {% endfor %}
                    </div>
                    {% endif %}
                </div>
            {% endfor %}

            {% if scan.gone_ips %}
            <div class="gone-list">Disappeared: {{ scan.gone_ips | join(', ') }}</div>
            {% endif %}
        </div>
    {% else %}
        <p>No scans in the database. Run a scan first.</p>
    {% endfor %}
    </div>

    {% if total_pages > 1 %}
    <nav class="pager">
        {% if has_prev %}
            <a href="{{ url_for('index', page=page-1, per_page=per_page) }}">← Previous</a>
        {% else %}
            <span class="disabled">← Previous</span>
        {% endif %}
        <span>Page {{ page }} / {{ total_pages }} &middot; {{ total }} scans</span>
        {% if has_next %}
            <a href="{{ url_for('index', page=page+1, per_page=per_page) }}">Next →</a>
        {% else %}
            <span class="disabled">Next →</span>
        {% endif %}
    </nav>
    {% endif %}
</body>
</html>
"""


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


# ══════════════════════════════════════════════════════════════════
#  Auth routes
# ══════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
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
            return render_template_string(
                _LOGIN_TEMPLATE,
                error=error,
                next_url=next_url,
                csrf_token=_get_csrf_token(),
            ), 429

        # CSRF: the token must match the one from the session that served the GET.
        if not _csrf_ok(request.form.get("_csrf", "")):
            log.warning("login csrf-fail ip=%s", ip)
            error = "Invalid CSRF token. Reload the page and try again."
            return render_template_string(
                _LOGIN_TEMPLATE,
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
            # Guard against open-redirect: only allow relative paths.
            safe_next = next_url if next_url.startswith("/") else "/"
            return redirect(safe_next)
        log.warning("login fail user=%s ip=%s", username, ip)
        error = "Invalid credentials. Try again."

    return render_template_string(
        _LOGIN_TEMPLATE,
        error=error,
        next_url=next_url,
        csrf_token=_get_csrf_token(),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ══════════════════════════════════════════════════════════════════
#  Dashboard routes
# ══════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def index():
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

    return render_template_string(
        _DASHBOARD_TEMPLATE,
        scans       = scans,
        page        = page,
        per_page    = per_page,
        total       = total,
        total_pages = total_pages,
        has_prev    = page > 1,
        has_next    = page < total_pages,
    )


@app.route("/api/reports")
@login_required
def api_reports():
    """Return all scans as raw JSON (for external integrations)."""
    return jsonify(get_all_scans())


@app.route("/api/scan/<int:scan_id>/diff")
@login_required
def api_scan_diff(scan_id: int):
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
    print("[*] Starting tactical server with authentication...")
    bind_label = "LAN (0.0.0.0)" if host == "0.0.0.0" else "loopback (127.0.0.1)"
    print(f"[+] Bind: {bind_label} port {port}")
    if host == "0.0.0.0":
        print("[!] Dashboard exposed to LAN. Use a TLS proxy (nginx/caddy)")
        print("    for HTTPS — credentials travel in plaintext otherwise.")
    if _GENERATED_PASS:
        print(f"[!] SENTINEL_PASS not configured — temporary password generated.")
        if _PASS_PERSISTED:
            print(f"[+] Credentials saved to {_CRED_FILE} (mode 0600).")
            print(f"    Read with:  cat {_CRED_FILE}")
        else:
            # Fallback only — could not write the file (read-only FS, etc.).
            print(f"[!] Could not persist credentials. One-shot output below:")
            print(f"    username={_USER}  password={_PASS}")
        print(f"[+] http://{host}:{port}  (username: {_USER})")
        print(f"[!] Configure SENTINEL_PASS for production:")
        print(f"      export SENTINEL_PASS=\"your_secure_password\"")
    else:
        print(f"[+] http://{host}:{port}  (username: {_USER})")


if __name__ == "__main__":
    _print_startup_banner(host="127.0.0.1")
    app.run(host="127.0.0.1", port=5000, debug=False)
