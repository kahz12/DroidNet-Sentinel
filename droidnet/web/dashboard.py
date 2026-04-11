"""
Flask Command Center — web dashboard for Sentinel audit reports.

Routes:
    GET /            → HTML dashboard
    GET /api/reports → Raw JSON (for integrations)

Design notes:
    · HTML/CSS is inlined in HTML_TEMPLATE — no static file dependencies.
    · render_template_string() keeps everything portable in Termux.
    · host="0.0.0.0" exposes the server on all interfaces so it can be
      reached from other devices on the LAN.

Warning: no authentication — only use on trusted local networks.
"""

import json
import os

from datetime import datetime
from flask    import Flask, render_template_string, jsonify

from droidnet.config import REPORTS_DIR

app = Flask(__name__)


# ══════════════════════════════════════════════════════════════════
#  HTML template (GitHub Dark palette, responsive grid)
# ══════════════════════════════════════════════════════════════════

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DroidNet Sentinel | Command Center</title>
    <style>
        body {
            font-family: 'Courier New', Courier, monospace;
            background-color: #0d1117;
            color: #c9d1d9;
            padding: 20px;
            margin: 0;
        }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .grid-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .report-card {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .report-header { font-size: 1.2em; color: #e6edf3; margin-bottom: 5px; font-weight: bold; }
        .meta-data {
            font-size: 0.9em; color: #8b949e; margin-bottom: 15px;
            border-bottom: 1px dashed #30363d; padding-bottom: 10px;
        }
        .target {
            background-color: #0d1117; margin-top: 10px;
            border-left: 3px solid #238636; padding: 10px; border-radius: 0 4px 4px 0;
        }
        .target.vulnerable { border-left-color: #f85149; }
        .ip-address { font-weight: bold; color: #79c0ff; }
        .port-safe  { color: #3fb950; font-size: 0.9em; }
        .port-vuln  { color: #ff7b72; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>🛡️ Sentinel Command Center</h1>
    <p>Histórico de auditorías de red. <i>Powered by DroidNet.</i></p>
    <div class="grid-container">
        {% for report in reports %}
        <div class="report-card">
            <div class="report-header">Red: {{ report.network }}</div>
            <div class="meta-data">
                Escaneo: {{ report.scan_time }}<br>
                Dispositivos: {{ report.total_devices }}
            </div>
            {% for ip, ports in report.targets.items() %}
                {% set is_vuln = "Escudo intacto" not in ports[0] and "Error" not in ports[0] %}
                <div class="target {% if is_vuln %}vulnerable{% endif %}">
                    <span class="ip-address">{{ ip }}</span><br>
                    {% for port in ports %}
                        {% if not is_vuln %}
                            <span class="port-safe">✓ {{ port }}</span><br>
                        {% else %}
                            <span class="port-vuln">⚠ {{ port }}</span><br>
                        {% endif %}
                    {% endfor %}
                </div>
            {% endfor %}
        </div>
        {% else %}
        <p>No hay reportes generados aún. Ejecuta un escaneo primero.</p>
        {% endfor %}
    </div>
</body>
</html>
"""


# ══════════════════════════════════════════════════════════════════
#  Data loading
# ══════════════════════════════════════════════════════════════════

def _parse_time(time_str: str) -> str:
    """Convert raw sentinel timestamp to a human-readable string."""
    try:
        return datetime.strptime(time_str, "%Y%m%d_%H%M%S").strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return time_str


def get_all_reports() -> list[dict]:
    """
    Load all JSON reports from REPORTS_DIR, sorted newest-first.

    Corrupted files are skipped silently to keep the dashboard alive.
    """
    files = sorted(REPORTS_DIR.glob("*.json"), key=os.path.getmtime, reverse=True)
    reports: list[dict] = []

    for path in files:
        try:
            with path.open() as fh:
                data = json.load(fh)

            data["scan_time"]     = _parse_time(data.get("time", ""))
            data["total_devices"] = data.get("total_devices") or len(data.get("targets", {}))
            reports.append(data)
        except Exception as exc:
            print(f"[dashboard] Error leyendo {path.name}: {exc}")

    return reports


# ══════════════════════════════════════════════════════════════════
#  Routes
# ══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Render the main HTML dashboard."""
    return render_template_string(HTML_TEMPLATE, reports=get_all_reports())


@app.route("/api/reports")
def api_reports():
    """Return all reports as raw JSON (for external integrations)."""
    return jsonify(get_all_reports())


# ══════════════════════════════════════════════════════════════════
#  Standalone
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("[*] Levantando servidor local táctico...")
    print("[+] http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
