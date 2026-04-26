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
#  Shared CSS — design system
# ══════════════════════════════════════════════════════════════════
#
# Single source of truth for typography, palette and base layout so
# the login, dashboard and help pages share a consistent look.

_BASE_CSS = """
:root {
    --bg-deep:    #0a0e14;
    --bg:         #0d1117;
    --bg-soft:    #11161d;
    --bg-card:    #161b22;
    --bg-elev:    #1c222b;
    --border:     #2a313c;
    --border-mut: #1f242c;

    --text:       #e6edf3;
    --text-mut:   #8b949e;
    --text-dim:   #6b7380;

    --accent:     #58a6ff;
    --accent-2:   #7ee2ff;
    --ok:         #3fb950;
    --warn:       #d29922;
    --danger:     #f85149;
    --info:       #79c0ff;

    --radius:     10px;
    --radius-sm:  6px;
    --shadow:     0 8px 24px rgba(0,0,0,0.45);

    --font-sans:  ui-sans-serif, system-ui, -apple-system, "Segoe UI",
                  Roboto, "Helvetica Neue", Arial, sans-serif;
    --font-mono:  ui-monospace, SFMono-Regular, "JetBrains Mono",
                  "Cascadia Mono", Menlo, Consolas, monospace;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
    background: var(--bg-deep);
    color: var(--text);
    font-family: var(--font-sans);
    font-size: 15px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
}

body {
    background:
        radial-gradient(1200px 600px at 80% -10%,
                        rgba(88,166,255,0.08), transparent 60%),
        radial-gradient(900px 500px at -10% 110%,
                        rgba(126,226,255,0.06), transparent 60%),
        var(--bg-deep);
    min-height: 100vh;
}

a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-2); }

/* Top navigation, used on all authenticated pages. */
.topbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 28px;
    background: rgba(13,17,23,0.85);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 10;
}
.brand {
    display: flex; align-items: center; gap: 10px;
    font-weight: 700; letter-spacing: 0.2px;
}
.brand .logo {
    width: 28px; height: 28px;
    display: inline-flex; align-items: center; justify-content: center;
    border-radius: 7px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: #0a0e14;
    font-weight: 800; font-size: 14px;
}
.brand .name  { color: var(--text); }
.brand .ver   { color: var(--text-dim); font-weight: 400; font-size: 12px; }

.nav { display: flex; align-items: center; gap: 6px; }
.nav a, .nav button {
    background: transparent; border: 1px solid transparent;
    color: var(--text-mut);
    padding: 7px 12px; border-radius: var(--radius-sm);
    font: inherit; cursor: pointer;
    transition: background 0.15s, color 0.15s, border-color 0.15s;
}
.nav a:hover, .nav button:hover {
    color: var(--text); background: var(--bg-elev);
    border-color: var(--border);
}
.nav a.active { color: var(--text); background: var(--bg-elev);
                border-color: var(--border); }
.nav .danger { color: var(--danger); }
.nav .danger:hover { color: #fff; background: var(--danger);
                     border-color: var(--danger); }

.container { max-width: 1320px; margin: 0 auto; padding: 24px 28px 60px; }
.page-header { margin-bottom: 22px; }
.page-header h1 { font-size: 1.5rem; font-weight: 700; }
.page-header p  { color: var(--text-mut); margin-top: 4px; font-size: 0.92rem; }

.card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
}
"""


# ══════════════════════════════════════════════════════════════════
#  HTML templates
# ══════════════════════════════════════════════════════════════════

_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel · Sign in</title>
    <style>
""" + _BASE_CSS + """
        body {
            display: flex; align-items: center; justify-content: center;
            padding: 24px;
        }
        .login-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 36px 32px;
            width: 100%; max-width: 380px;
            box-shadow: var(--shadow);
        }
        .login-head {
            text-align: center; margin-bottom: 28px;
        }
        .login-head .logo {
            width: 52px; height: 52px;
            margin: 0 auto 14px;
            display: flex; align-items: center; justify-content: center;
            border-radius: 14px;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            color: #0a0e14; font-weight: 800; font-size: 22px;
            box-shadow: 0 8px 22px rgba(88,166,255,0.25);
        }
        .login-head h1 {
            font-size: 1.2rem; letter-spacing: 0.2px;
        }
        .login-head p {
            color: var(--text-mut); font-size: 0.85rem; margin-top: 4px;
        }
        label {
            display: block;
            color: var(--text-mut);
            font-size: 0.78rem; letter-spacing: 0.6px;
            text-transform: uppercase;
            margin: 14px 0 6px;
        }
        input[type=text], input[type=password] {
            width: 100%; padding: 11px 13px;
            background: var(--bg-deep);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text);
            font: inherit;
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }
        input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(88,166,255,0.18);
        }
        button.primary {
            width: 100%; margin-top: 22px; padding: 11px;
            background: linear-gradient(135deg, var(--accent), #4a92e8);
            color: #fff; border: none;
            border-radius: var(--radius-sm);
            font: inherit; font-weight: 600;
            cursor: pointer;
            transition: filter 0.15s, transform 0.05s;
        }
        button.primary:hover  { filter: brightness(1.08); }
        button.primary:active { transform: translateY(1px); }
        .error {
            background: rgba(248,81,73,0.10);
            border: 1px solid rgba(248,81,73,0.55);
            color: #ff8d85;
            padding: 10px 12px; border-radius: var(--radius-sm);
            font-size: 0.85rem;
            margin-bottom: 4px;
        }
        .footnote {
            text-align: center;
            color: var(--text-dim); font-size: 0.78rem;
            margin-top: 22px;
        }
    </style>
</head>
<body>
    <form class="login-card" method="POST" action="{{ url_for('login') }}">
        <div class="login-head">
            <div class="logo">S</div>
            <h1>Sentinel Command Center</h1>
            <p>Sign in to continue</p>
        </div>

        {% if error %}<div class="error">{{ error }}</div>{% endif %}

        <input type="hidden" name="next"  value="{{ next_url }}">
        <input type="hidden" name="_csrf" value="{{ csrf_token }}">

        <label for="u">Username</label>
        <input id="u" type="text" name="username"
               autocomplete="username" autofocus>

        <label for="p">Password</label>
        <input id="p" type="password" name="password"
               autocomplete="current-password">

        <button class="primary" type="submit">Sign in</button>

        <p class="footnote">Authorised use only.</p>
    </form>
</body>
</html>
"""

_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel · Dashboard</title>
    <style>
""" + _BASE_CSS + """
        .summary {
            display: grid; gap: 14px;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            margin-bottom: 22px;
        }
        .stat {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 14px 16px;
        }
        .stat .label {
            color: var(--text-mut); font-size: 0.75rem;
            letter-spacing: 0.7px; text-transform: uppercase;
        }
        .stat .value {
            margin-top: 4px;
            font-size: 1.5rem; font-weight: 700;
            font-variant-numeric: tabular-nums;
        }
        .stat.ok    .value { color: var(--ok);     }
        .stat.warn  .value { color: var(--warn);   }
        .stat.bad   .value { color: var(--danger); }
        .stat.info  .value { color: var(--info);   }

        .legend {
            display: flex; flex-wrap: wrap; gap: 14px;
            background: var(--bg-soft);
            border: 1px dashed var(--border);
            color: var(--text-mut);
            padding: 10px 14px;
            border-radius: var(--radius-sm);
            font-size: 0.82rem;
            margin-bottom: 22px;
        }
        .legend .dot {
            display: inline-block; width: 10px; height: 10px;
            border-radius: 50%; margin-right: 6px;
            vertical-align: middle;
        }
        .legend .dot.r-critico { background: var(--danger); }
        .legend .dot.r-medio   { background: var(--warn);   }
        .legend .dot.r-bajo    { background: var(--info);   }
        .legend .dot.r-minimo  { background: var(--ok);     }
        .legend .help-link { margin-left: auto; }

        .grid {
            display: grid; gap: 18px;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
        }

        .scan {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            display: flex; flex-direction: column;
            overflow: hidden;
        }
        .scan-head {
            padding: 14px 16px 10px;
            border-bottom: 1px solid var(--border-mut);
        }
        .scan-net {
            display: flex; align-items: baseline; gap: 8px;
            font-weight: 700; font-size: 1rem;
        }
        .scan-net .label { color: var(--text-mut); font-weight: 500;
                           font-size: 0.78rem; text-transform: uppercase;
                           letter-spacing: 0.7px; }
        .scan-meta {
            color: var(--text-mut); font-size: 0.82rem;
            margin-top: 4px; display: flex; gap: 10px; flex-wrap: wrap;
        }
        .scan-meta .pill {
            display: inline-flex; align-items: center;
            background: var(--bg-elev);
            border: 1px solid var(--border);
            border-radius: 999px;
            padding: 2px 9px; font-size: 0.74rem;
        }
        .scan-meta .pill.new  { color: var(--warn);
                                border-color: rgba(210,153,34,0.5); }
        .scan-meta .pill.gone { color: var(--danger);
                                border-color: rgba(248,81,73,0.5); }

        .scan-body { padding: 6px 16px 16px; }

        .host {
            background: var(--bg-deep);
            border-left: 3px solid var(--ok);
            border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
            padding: 10px 12px;
            margin-top: 10px;
        }
        .host.vuln { border-left-color: var(--danger); }
        .host.new  { border-left-color: var(--warn);   }

        .host-head {
            display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
        }
        .ip {
            font-family: var(--font-mono);
            font-weight: 700;
            color: var(--info);
        }
        .badge {
            display: inline-block; font-size: 0.68rem;
            font-weight: 600; letter-spacing: 0.5px;
            padding: 2px 8px; border-radius: 999px;
            text-transform: uppercase;
        }
        .badge-new {
            color: var(--warn);
            background: rgba(210,153,34,0.12);
            border: 1px solid rgba(210,153,34,0.5);
        }
        .risk {
            font-size: 0.72rem; font-weight: 700;
            letter-spacing: 0.5px;
            padding: 2px 8px; border-radius: 999px;
            text-transform: uppercase;
        }
        .r-critico { color: var(--danger);
                     background: rgba(248,81,73,0.12);
                     border: 1px solid rgba(248,81,73,0.5); }
        .r-medio   { color: var(--warn);
                     background: rgba(210,153,34,0.12);
                     border: 1px solid rgba(210,153,34,0.5); }
        .r-bajo    { color: var(--info);
                     background: rgba(121,192,255,0.12);
                     border: 1px solid rgba(121,192,255,0.5); }
        .r-minimo  { color: var(--ok);
                     background: rgba(63,185,80,0.12);
                     border: 1px solid rgba(63,185,80,0.5); }

        .ports { margin-top: 8px; font-family: var(--font-mono);
                 font-size: 0.82rem; color: var(--text-mut); }
        .ports .ok-line  { color: var(--ok);  display: block; }
        .ports .bad-line { color: #ff7b72;    display: block; }

        .diff-box {
            margin-top: 10px;
            background: var(--bg-soft);
            border: 1px solid var(--border-mut);
            border-radius: var(--radius-sm);
            padding: 8px 10px;
            font-size: 0.78rem;
            font-family: var(--font-mono);
        }
        .diff-box .diff-label {
            color: var(--text-mut); margin-bottom: 4px;
            font-family: var(--font-sans); font-size: 0.72rem;
            text-transform: uppercase; letter-spacing: 0.6px;
        }
        .added   { color: var(--ok);     display: block; }
        .removed { color: var(--danger); display: block; }

        .gone-list {
            margin-top: 14px;
            font-size: 0.78rem; color: var(--text-mut);
            border-top: 1px dashed var(--border-mut);
            padding-top: 10px;
        }

        .empty {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-mut);
        }
        .empty .big { font-size: 2rem; margin-bottom: 10px; }
        .empty a {
            display: inline-block; margin-top: 14px;
            background: var(--bg-elev); border: 1px solid var(--border);
            color: var(--text); padding: 8px 14px;
            border-radius: var(--radius-sm);
        }

        .pager {
            display: flex; justify-content: center; align-items: center;
            gap: 14px; margin-top: 28px;
            color: var(--text-mut); font-size: 0.9rem;
        }
        .pager a, .pager span.disabled {
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 7px 12px; border-radius: var(--radius-sm);
        }
        .pager span.disabled { color: var(--text-dim); cursor: not-allowed; }
        .pager a:hover { background: var(--bg-elev); }
    </style>
</head>
<body>
    <nav class="topbar">
        <div class="brand">
            <span class="logo">S</span>
            <span class="name">Sentinel</span>
            <span class="ver">Command Center</span>
        </div>
        <div class="nav">
            <a class="active" href="{{ url_for('index') }}">Dashboard</a>
            <a href="{{ url_for('help_page') }}">Help</a>
            <a class="danger" href="{{ url_for('logout') }}">Sign out</a>
        </div>
    </nav>

    <main class="container">
        <div class="page-header">
            <h1>Network audit history</h1>
            <p>Recent scans, diffs and risk assessment for every host on the
               networks you have audited.</p>
        </div>

        <section class="summary">
            <div class="stat info"><div class="label">Total scans</div>
                 <div class="value">{{ total }}</div></div>
            <div class="stat warn"><div class="label">New hosts (page)</div>
                 <div class="value">{{ stats.new_count }}</div></div>
            <div class="stat bad"><div class="label">Critical hosts (page)</div>
                 <div class="value">{{ stats.crit_count }}</div></div>
            <div class="stat ok"><div class="label">Page</div>
                 <div class="value">{{ page }} / {{ total_pages }}</div></div>
        </section>

        <div class="legend">
            <span><span class="dot r-critico"></span>Critical — high-risk service</span>
            <span><span class="dot r-medio"></span>Medium — exposed service</span>
            <span><span class="dot r-bajo"></span>Low — open ports, low impact</span>
            <span><span class="dot r-minimo"></span>Minimal — no open ports</span>
            <a class="help-link" href="{{ url_for('help_page') }}">What does this mean?</a>
        </div>

        <div class="grid">
        {% for scan in scans %}
            <article class="scan">
                <header class="scan-head">
                    <div class="scan-net">
                        <span class="label">Network</span>
                        <span>{{ scan.network }}</span>
                    </div>
                    <div class="scan-meta">
                        <span>{{ scan.scan_time }}</span>
                        <span class="pill">{{ scan.total_devices }} devices</span>
                        {% if scan.new_ips %}
                            <span class="pill new">+{{ scan.new_ips|length }} new</span>
                        {% endif %}
                        {% if scan.gone_ips %}
                            <span class="pill gone">-{{ scan.gone_ips|length }} gone</span>
                        {% endif %}
                    </div>
                </header>

                <div class="scan-body">
                {% for ip, ports in scan.targets.items() %}
                    {% set risk    = scan.risks.get(ip, 'MÍNIMO') %}
                    {% set is_new  = ip in scan.new_ips %}
                    {% set is_vuln = risk in ('CRÍTICO', 'MEDIO', 'BAJO') %}
                    <div class="host {% if is_new %}new{% elif is_vuln %}vuln{% endif %}">
                        <div class="host-head">
                            <span class="ip">{{ ip }}</span>
                            {% if is_new %}<span class="badge badge-new">new</span>{% endif %}
                            <span class="risk
                                {% if risk == 'CRÍTICO' %}r-critico
                                {% elif risk == 'MEDIO'  %}r-medio
                                {% elif risk == 'BAJO'   %}r-bajo
                                {% else %}r-minimo{% endif %}">{{ risk }}</span>
                        </div>

                        <div class="ports">
                        {% for port in ports %}
                            {% if is_vuln %}
                                <span class="bad-line">! {{ port }}</span>
                            {% else %}
                                <span class="ok-line">+ {{ port }}</span>
                            {% endif %}
                        {% endfor %}
                        </div>

                        {% if ip in scan.port_changes %}
                        <div class="diff-box">
                            <div class="diff-label">Port changes since last scan</div>
                            {% for p in scan.port_changes[ip].added %}
                                <span class="added">+ {{ p }}</span>
                            {% endfor %}
                            {% for p in scan.port_changes[ip].removed %}
                                <span class="removed">- {{ p }}</span>
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                {% endfor %}

                {% if scan.gone_ips %}
                <div class="gone-list">
                    Disappeared since last scan: {{ scan.gone_ips | join(', ') }}
                </div>
                {% endif %}
                </div>
            </article>
        {% else %}
            <div class="empty">
                <div class="big">No scans yet</div>
                <p>The database is empty. Run a Sentinel scan to populate it.</p>
                <a href="{{ url_for('help_page') }}">Open the user guide</a>
            </div>
        {% endfor %}
        </div>

        {% if total_pages > 1 %}
        <nav class="pager">
            {% if has_prev %}
                <a href="{{ url_for('index', page=page-1, per_page=per_page) }}">← Previous</a>
            {% else %}
                <span class="disabled">← Previous</span>
            {% endif %}
            <span>Page {{ page }} of {{ total_pages }} · {{ total }} scans</span>
            {% if has_next %}
                <a href="{{ url_for('index', page=page+1, per_page=per_page) }}">Next →</a>
            {% else %}
                <span class="disabled">Next →</span>
            {% endif %}
        </nav>
        {% endif %}
    </main>
</body>
</html>
"""

_HELP_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel · Help</title>
    <style>
""" + _BASE_CSS + """
        .layout {
            display: grid;
            grid-template-columns: 240px 1fr;
            gap: 28px;
        }
        @media (max-width: 800px) {
            .layout { grid-template-columns: 1fr; }
        }
        .toc {
            position: sticky; top: 80px;
            align-self: start;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 14px;
            font-size: 0.88rem;
        }
        .toc h3 {
            font-size: 0.72rem; letter-spacing: 0.7px;
            text-transform: uppercase;
            color: var(--text-mut); margin-bottom: 8px;
        }
        .toc a {
            display: block;
            color: var(--text-mut);
            padding: 6px 8px;
            border-radius: var(--radius-sm);
        }
        .toc a:hover { background: var(--bg-elev); color: var(--text); }

        .doc section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 22px 24px;
            margin-bottom: 18px;
            scroll-margin-top: 80px;
        }
        .doc h2 { font-size: 1.15rem; margin-bottom: 10px; }
        .doc h3 { font-size: 0.95rem; margin: 16px 0 6px; color: var(--text); }
        .doc p, .doc li { color: var(--text-mut); margin-bottom: 8px; }
        .doc ul { padding-left: 22px; }
        .doc strong { color: var(--text); }
        .doc code {
            font-family: var(--font-mono);
            background: var(--bg-deep);
            border: 1px solid var(--border-mut);
            color: var(--accent-2);
            padding: 1px 6px; border-radius: 4px;
            font-size: 0.86em;
        }
        .doc .kbd {
            font-family: var(--font-mono);
            background: var(--bg-elev);
            border: 1px solid var(--border);
            border-bottom-width: 2px;
            color: var(--text);
            padding: 1px 6px; border-radius: 5px;
            font-size: 0.82em;
        }
        .risk-table {
            width: 100%; border-collapse: collapse; margin-top: 10px;
            font-size: 0.88rem;
        }
        .risk-table th, .risk-table td {
            text-align: left; padding: 8px 10px;
            border-bottom: 1px solid var(--border-mut);
        }
        .risk-table th { color: var(--text-mut); font-weight: 600;
                         font-size: 0.78rem; text-transform: uppercase;
                         letter-spacing: 0.6px; }
        .risk-table td { color: var(--text); }
        .risk-table .pill {
            display: inline-block; padding: 2px 8px;
            border-radius: 999px; font-size: 0.72rem;
            font-weight: 700; letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        .feat-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 12px; margin-top: 8px;
        }
        .feat {
            background: var(--bg-soft);
            border: 1px solid var(--border-mut);
            border-radius: var(--radius-sm);
            padding: 12px 14px;
        }
        .feat h4 { color: var(--text); font-size: 0.95rem;
                   margin-bottom: 4px; }
        .feat p  { color: var(--text-mut); font-size: 0.85rem; margin: 0; }
    </style>
</head>
<body>
    <nav class="topbar">
        <div class="brand">
            <span class="logo">S</span>
            <span class="name">Sentinel</span>
            <span class="ver">Command Center</span>
        </div>
        <div class="nav">
            <a href="{{ url_for('index') }}">Dashboard</a>
            <a class="active" href="{{ url_for('help_page') }}">Help</a>
            <a class="danger" href="{{ url_for('logout') }}">Sign out</a>
        </div>
    </nav>

    <main class="container">
        <div class="page-header">
            <h1>User guide</h1>
            <p>How Sentinel works, how to read this dashboard, and how to use
               every feature responsibly.</p>
        </div>

        <div class="layout">
            <aside class="toc">
                <h3>On this page</h3>
                <a href="#overview">Overview</a>
                <a href="#workflow">Typical workflow</a>
                <a href="#features">Features</a>
                <a href="#dashboard">Reading the dashboard</a>
                <a href="#risk">Risk levels</a>
                <a href="#api">API endpoints</a>
                <a href="#security">Security & ethics</a>
            </aside>

            <div class="doc">
                <section id="overview">
                    <h2>What is Sentinel?</h2>
                    <p><strong>DroidNet Sentinel</strong> is a network-security
                       toolkit that audits the Wi-Fi networks you own or are
                       authorised to test. It discovers live hosts, fingerprints
                       open services, classifies risk, and tracks how the
                       network changes over time.</p>
                    <p>The CLI is the operator's surface; this web dashboard is
                       the read-only view of the audit history stored in
                       <code>sentinel.db</code>.</p>
                </section>

                <section id="workflow">
                    <h2>Typical workflow</h2>
                    <ol style="padding-left: 22px; color: var(--text-mut);">
                        <li>Connect to the network you want to audit.</li>
                        <li>Run <code>python main.py scan</code> (one-shot) or
                            <code>python main.py daemon</code> (continuous).</li>
                        <li>Open this dashboard to review the findings.</li>
                        <li>Use <code>python main.py hunt</code> to look up
                            known exploits for the services you found.</li>
                        <li>Use <code>python main.py cve</code> to check the
                            scan against recent CVEs.</li>
                    </ol>
                </section>

                <section id="features">
                    <h2>Features</h2>
                    <div class="feat-list">
                        <div class="feat">
                            <h4>Sentinel — Network scan</h4>
                            <p>Discovers live hosts, performs an Nmap-style port
                               scan and stores results in the database.</p>
                        </div>
                        <div class="feat">
                            <h4>Daemon mode</h4>
                            <p>Runs Sentinel in the background on a fixed cadence
                               and emits Telegram alerts when something changes.</p>
                        </div>
                        <div class="feat">
                            <h4>Hunter</h4>
                            <p>Cross-references the latest scan against the
                               local Exploit-DB index via <code>searchsploit</code>.</p>
                        </div>
                        <div class="feat">
                            <h4>CVE Watcher</h4>
                            <p>Fingerprints services and queries the NVD for
                               relevant CVEs published recently.</p>
                        </div>
                        <div class="feat">
                            <h4>Spoofer (ARP)</h4>
                            <p>Manual ARP-poisoning tool for cutting access to
                               an IP. <strong>Authorised use only.</strong></p>
                        </div>
                        <div class="feat">
                            <h4>Deauther (802.11)</h4>
                            <p>Sends 802.11 deauth frames against a target or
                               broadcast. Requires monitor mode and root.</p>
                        </div>
                    </div>
                </section>

                <section id="dashboard">
                    <h2>Reading the dashboard</h2>
                    <p>Each card represents one scan of one network. Hosts are
                       coloured by risk and decorated with badges:</p>
                    <ul>
                        <li><strong>Network</strong> — the SSID or CIDR of the
                            audited segment.</li>
                        <li><strong>Devices</strong> — total hosts that responded
                            in this scan.</li>
                        <li><span class="badge badge-new">new</span> — host
                            seen for the first time vs the previous scan of
                            the same network.</li>
                        <li><strong>Disappeared</strong> — host that was present
                            in the previous scan and is missing now.</li>
                        <li><strong>Port changes</strong> — diff of open services
                            between this scan and the previous one
                            (<span class="added" style="color:var(--ok)">+ added</span> /
                            <span class="removed" style="color:var(--danger)">- removed</span>).</li>
                    </ul>
                    <p>Press <span class="kbd">Ctrl</span> + <span class="kbd">F</span>
                       to filter visible cards by IP or by service banner.</p>
                </section>

                <section id="risk">
                    <h2>Risk levels</h2>
                    <p>Sentinel assigns one risk label per host based on the
                       set of open TCP ports it found:</p>
                    <table class="risk-table">
                        <tr><th>Label</th><th>Trigger</th><th>What it means</th></tr>
                        <tr>
                            <td><span class="pill r-critico">CRÍTICO</span></td>
                            <td>FTP / Telnet / SMB / NetBIOS / RDP</td>
                            <td>High-impact service that should not be
                                exposed on a typical home network.</td>
                        </tr>
                        <tr>
                            <td><span class="pill r-medio">MEDIO</span></td>
                            <td>HTTP / HTTP-alt / DNS / SSDP / NFS</td>
                            <td>Service exposed to the LAN. Often expected,
                                but worth a banner check.</td>
                        </tr>
                        <tr>
                            <td><span class="pill r-bajo">BAJO</span></td>
                            <td>Other open ports</td>
                            <td>Open service that did not match the higher
                                tiers. Worth a banner inspection.</td>
                        </tr>
                        <tr>
                            <td><span class="pill r-minimo">MÍNIMO</span></td>
                            <td>No open ports</td>
                            <td>Host is reachable but exposes no services.</td>
                        </tr>
                    </table>
                </section>

                <section id="api">
                    <h2>API endpoints</h2>
                    <p>All endpoints require an authenticated session and
                       return JSON. Useful for piping into your own tooling.</p>
                    <ul>
                        <li><code>GET /api/reports</code> — every scan stored
                            in the database.</li>
                        <li><code>GET /api/scan/&lt;id&gt;/diff</code> — diff
                            of one scan against the previous scan of the same
                            network.</li>
                    </ul>
                </section>

                <section id="security">
                    <h2>Security &amp; ethics</h2>
                    <ul>
                        <li>Sentinel is an offensive-security tool. Only use it
                            on networks you own or have explicit written
                            authorisation to test.</li>
                        <li>The dashboard is loopback-bound by default. Bind
                            to LAN only behind a TLS proxy (nginx / caddy);
                            credentials travel in plaintext otherwise.</li>
                        <li>Auto-generated passwords are stored at
                            <code>~/.sentinel/credentials</code> with mode
                            <code>0600</code>. Override with the
                            <code>SENTINEL_PASS</code> environment variable.</li>
                        <li>Login is rate-limited (5 attempts per minute per
                            IP) and protected by a per-session CSRF token.</li>
                    </ul>
                </section>
            </div>
        </div>
    </main>
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


def _summarize(scans: list[dict]) -> dict:
    """Counts shown in the summary tiles at the top of the dashboard."""
    new_count = 0
    crit_count = 0
    for s in scans:
        new_count += len(s.get("new_ips", []))
        risks = s.get("risks", {}) or {}
        crit_count += sum(1 for r in risks.values() if r == "CRÍTICO")
    return {"new_count": new_count, "crit_count": crit_count}


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
    stats = _summarize(scans)

    return render_template_string(
        _DASHBOARD_TEMPLATE,
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
def help_page():
    """In-app help / user guide."""
    return render_template_string(_HELP_TEMPLATE)


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
    print("[*] Starting Command Center with authentication...")
    bind_label = "LAN (0.0.0.0)" if host == "0.0.0.0" else "loopback (127.0.0.1)"
    print(f"[+] Bind: {bind_label} port {port}")
    if host == "0.0.0.0":
        print("[!] Dashboard exposed to the LAN. Front it with a TLS proxy")
        print("    (nginx / caddy) — credentials travel in plaintext otherwise.")
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
