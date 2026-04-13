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
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template_string, jsonify,
    request, session, redirect, url_for, abort,
)

from droidnet.core.database import init_db, get_all_scans, get_all_scans_with_diffs, get_scan_diff

# ── App setup ─────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SENTINEL_SECRET") or secrets.token_hex(32)

_USER = os.environ.get("SENTINEL_USER", "admin")

_PASS_FROM_ENV = os.environ.get("SENTINEL_PASS")
if _PASS_FROM_ENV:
    _PASS = _PASS_FROM_ENV
    _GENERATED_PASS = False
else:
    _PASS = secrets.token_urlsafe(16)
    _GENERATED_PASS = True

# Initialise DB schema (idempotent — safe to call on every restart).
init_db()


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
<html lang="es">
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
        <p class="subtitle">Command Center — Acceso restringido</p>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST" action="{{ url_for('login') }}">
            <input type="hidden" name="next" value="{{ next_url }}">
            <label for="u">Usuario</label>
            <input type="text"     id="u" name="username" autocomplete="username" autofocus>
            <label for="p">Contraseña</label>
            <input type="password" id="p" name="password" autocomplete="current-password">
            <button type="submit">Iniciar sesión</button>
        </form>
    </div>
</body>
</html>
"""

_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
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
    </style>
</head>
<body>
    <header>
        <h1>🛡️ Sentinel Command Center</h1>
        <a href="{{ url_for('logout') }}" class="logout">Cerrar sesión</a>
    </header>
    <p class="subtitle">Histórico de auditorías de red. <i>Powered by DroidNet.</i></p>

    <div class="grid">
    {% for scan in scans %}
        <div class="card">
            <div class="card-title">Red: {{ scan.network }}</div>
            <div class="meta">
                Escaneo: {{ scan.scan_time }}<br>
                Dispositivos: {{ scan.total_devices }}
                {% if scan.new_ips %}
                  &middot; <span style="color:#d29922">{{ scan.new_ips|length }} nuevo(s)</span>
                {% endif %}
                {% if scan.gone_ips %}
                  &middot; <span style="color:#f85149">{{ scan.gone_ips|length }} desaparecido(s)</span>
                {% endif %}
            </div>

            {% for ip, ports in scan.targets.items() %}
                {% set risk    = scan.risks.get(ip, 'MÍNIMO') %}
                {% set is_new  = ip in scan.new_ips %}
                {% set is_vuln = risk in ('CRÍTICO', 'MEDIO', 'BAJO') %}
                <div class="host {% if is_new %}new{% elif is_vuln %}vuln{% endif %}">
                    <span class="ip">{{ ip }}</span>
                    {% if is_new %}<span class="badge badge-new">NUEVO</span>{% endif %}
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
                        <div class="diff-label">Cambios de puertos:</div>
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
            <div class="gone-list">Desaparecidos: {{ scan.gone_ips | join(', ') }}</div>
            {% endif %}
        </div>
    {% else %}
        <p>No hay escaneos en la base de datos. Ejecuta un escaneo primero.</p>
    {% endfor %}
    </div>
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


def _prepare_scans() -> list[dict]:
    """Load all scans with diffs and format timestamps for display."""
    scans = get_all_scans_with_diffs()
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
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if _check_credentials(username, password):
            session["authenticated"] = True
            session["user"]          = username
            # Guard against open-redirect: only allow relative paths.
            safe_next = next_url if next_url.startswith("/") else "/"
            return redirect(safe_next)
        error = "Credenciales incorrectas. Inténtalo de nuevo."

    return render_template_string(_LOGIN_TEMPLATE, error=error, next_url=next_url)


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
    """Render the main HTML dashboard."""
    return render_template_string(_DASHBOARD_TEMPLATE, scans=_prepare_scans())


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

def _print_startup_banner() -> None:
    """Print server info and credential warnings at startup."""
    print("[*] Levantando servidor táctico con autenticación...")
    if _GENERATED_PASS:
        print(f"[!] SENTINEL_PASS no configurado — contraseña temporal generada.")
        print(f"[+] Credenciales: usuario={_USER}  contraseña={_PASS}")
        print(f"[!] Configura SENTINEL_PASS para producción:")
        print(f"      export SENTINEL_PASS=\"tu_contraseña_segura\"")
    else:
        print(f"[+] http://127.0.0.1:5000  (usuario: {_USER})")


if __name__ == "__main__":
    _print_startup_banner()
    app.run(host="0.0.0.0", port=5000, debug=False)
