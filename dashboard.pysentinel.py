"""
╔══════════════════════════════════════════════════════════════════╗
║              DroidNet Dashboard — Command Center UI              ║
║──────────────────────────────────────────────────────────────────║
║  Descripción:                                                    ║
║  Servidor web local que expone una interfaz visual para          ║
║  consultar el historial completo de auditorías generadas         ║
║  por sentinel.py. Accesible desde cualquier navegador en         ║
║  la misma red local (celular, PC, tablet).                       ║
║                                                                  ║
║  Diseño técnico:                                                 ║
║  · Todo el HTML/CSS va inline en HTML_TEMPLATE para evitar       ║
║    dependencias de archivos estáticos. Flask sirve todo          ║
║    desde un solo archivo Python — cero configuración extra.      ║
║  · render_template_string() renderiza Jinja2 desde string,       ║
║    no desde archivos en /templates. Más portable en Termux.      ║
║  · host="0.0.0.0" expone el servidor en todas las interfaces,    ║
║    permitiendo acceso desde la IP local del celular.             ║
║                                                                  ║
║  Rutas disponibles:                                              ║
║  GET /             → Dashboard visual HTML                       ║
║  GET /api/reports  → Datos en JSON crudo (para integraciones)    ║
║                                                                  ║
║  Dependencia:                                                    ║
║  sentinel.py debe haber generado al menos un reporte en          ║
║  la carpeta reports/ para que el dashboard muestre datos.        ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Terceros ──────────────────────────────────────────────────────
from flask import Flask, render_template_string, jsonify

# ── Stdlib ────────────────────────────────────────────────────────
import os            # Para os.path.getmtime() al ordenar reportes
import glob          # Para buscar archivos con wildcard reports/*.json
import json          # Para parsear los reportes JSON de sentinel.py
from datetime import datetime  # Para formatear timestamps legibles

# ── Instancia Flask ───────────────────────────────────────────────
app = Flask(__name__)


#  TEMPLATE: HTML/CSS del dashboard — todo inline

# El template usa Jinja2 (motor de Flask). Puntos clave:
#
# {{ variable }}           → Imprime variable en el HTML
# {% for x in lista %}     → Bucle Jinja2
# {% if condición %}       → Condicional Jinja2
# {% set var = valor %}    → Variable local Jinja2
# {% else %} en {% for %}  → Se ejecuta si la lista está vacía
#
# Paleta de colores: GitHub Dark (#0d1117, #161b22, #30363d)
# Verde para hosts seguros (#238636, #3fb950)
# Rojo para hosts vulnerables (#f85149, #ff7b72)
# Azul para IPs y títulos (#58a6ff, #79c0ff)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <!-- viewport: escala correcta en móvil, sin zoom forzado -->
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DroidNet Sentinel | Command Center</title>
    <style>
        /* Base: fuente monospace + fondo oscuro estilo GitHub Dark */
        body {
            font-family: 'Courier New', Courier, monospace;
            background-color: #0d1117;
            color: #c9d1d9;
            padding: 20px;
            margin: 0;
        }

        h1 {
            color: #58a6ff;
            border-bottom: 1px solid #30363d;
            padding-bottom: 10px;
        }

        /* Grid responsivo: columnas de mínimo 300px, se ajusta al ancho */
        .grid-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        /* Tarjeta individual por reporte/red escaneada */
        .report-card {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }

        .report-header {
            font-size: 1.2em;
            color: #e6edf3;
            margin-bottom: 5px;
            font-weight: bold;
        }

        .meta-data {
            font-size: 0.9em;
            color: #8b949e;
            margin-bottom: 15px;
            border-bottom: 1px dashed #30363d;
            padding-bottom: 10px;
        }

        /* Bloque por dispositivo detectado */
        /* border-left verde = host sin puertos abiertos (seguro) */
        .target {
            background-color: #0d1117;
            margin-top: 10px;
            border-left: 3px solid #238636;
            padding: 10px;
            border-radius: 0 4px 4px 0;
        }

        /* border-left rojo = host con puertos abiertos (potencialmente vulnerable) */
        .target.vulnerable {
            border-left-color: #f85149;
        }

        .ip-address { font-weight: bold; color: #79c0ff; }
        .port-safe  { color: #3fb950; font-size: 0.9em; }  /* Puerto cerrado */
        .port-vuln  { color: #ff7b72; font-size: 0.9em; }  /* Puerto abierto */
    </style>
</head>
<body>
    <h1>🛡️ Sentinel Command Center</h1>
    <p>Histórico de auditorías de red. <i>Powered by DroidNet.</i></p>

    <div class="grid-container">
        {% for report in reports %}
        <div class="report-card">
            <!-- Nombre de la red WiFi auditada -->
            <div class="report-header">Red: {{ report.network }}</div>

            <!-- Metadata del escaneo: timestamp y total de dispositivos -->
            <div class="meta-data">
                Escaneo: {{ report.scan_time }}<br>
                Dispositivos: {{ report.total_devices }}
            </div>

            <!-- Iteramos sobre cada IP y sus puertos detectados -->
            {% for ip, ports in report.targets.items() %}
                <!--
                    is_vuln = True si el primer elemento de ports NO es
                    "Escudo intacto" ni "Error" → tiene puertos abiertos reales.
                    Usamos ports[0] para el check porque todos los marcadores
                    especiales (Escudo intacto, Error) van en esa posición.
                -->
                {% set is_vuln = "Escudo intacto" not in ports[0] and "Error" not in ports[0] %}

                <div class="target {% if is_vuln %}vulnerable{% endif %}">
                    <span class="ip-address">{{ ip }}</span><br>

                    {% for port in ports %}
                        {% if not is_vuln %}
                            <!-- Puerto cerrado o host protegido → verde con checkmark -->
                            <span class="port-safe">✓ {{ port }}</span><br>
                        {% else %}
                            <!-- Puerto abierto → rojo con advertencia -->
                            <span class="port-vuln">⚠ {{ port }}</span><br>
                        {% endif %}
                    {% endfor %}
                </div>
            {% endfor %}
        </div>

        <!-- Bloque {% else %} del {% for %}: se muestra si reports está vacío -->
        {% else %}
        <p>No hay reportes generados aún. Ejecuta sentinel.py primero.</p>
        {% endfor %}
    </div>
</body>
</html>
"""


#  MÓDULO UTILS: Formateo de timestamps

def parse_time(time_str):
    """
    Convierte el timestamp del reporte al formato legible para la UI.

    sentinel.py guarda los timestamps con strftime("%Y%m%d_%H%M%S"):
        Formato raw    : "20240315_143022"
        Formato display: "15/03/2024 14:30:22"

    Si el parseo falla (formato inesperado o campo vacío),
    devuelve el string original sin modificar — fail safe.

    Args:
        time_str (str): Timestamp en formato "YYYYMMDD_HHMMSS"

    Returns:
        str: Fecha formateada como "DD/MM/YYYY HH:MM:SS" o el original si falla.
    """
    try:
        dt = datetime.strptime(time_str, "%Y%m%d_%H%M%S")
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except:
        return time_str


#  MÓDULO DATOS: Carga y preparación de todos los reportes

def get_all_reports():
    """
    Carga todos los reportes JSON de la carpeta reports/ y los
    prepara para ser renderizados en el dashboard.

    Proceso:
    1. glob busca todos los archivos .json en reports/
    2. Se ordenan por fecha de modificación (más reciente primero)
    3. Cada archivo se lee, parsea y se formatea su timestamp
    4. Los reportes con error de lectura se saltan sin romper el resto

    El campo 'scan_time' del JSON usa el formato raw de sentinel.py
    ("20240315_143022"). Lo reemplazamos por la versión legible
    antes de pasarlo al template.

    El campo 'total_devices' no siempre existe en reportes viejos,
    por eso usamos data.get() con fallback a len(targets).

    Returns:
        list: Lista de dicts con los datos de cada reporte,
              ordenados del más reciente al más antiguo.
    """
    files = glob.glob("reports/*.json")

    # Ordenamos por mtime del archivo (más reciente primero)
    # Más confiable que ordenar por nombre porque no depende del formato
    files.sort(key=os.path.getmtime, reverse=True)

    reports = []
    for f in files:
        try:
            with open(f, "r") as file:
                data = json.load(file)

                # Convertimos el timestamp al formato legible para la UI
                data['scan_time'] = parse_time(data.get('time', ''))

                # total_devices puede no existir en reportes antiguos
                # Calculamos como fallback contando las IPs en targets
                if 'total_devices' not in data:
                    data['total_devices'] = len(data.get('targets', {}))

                reports.append(data)

        except Exception as e:
            # Un reporte corrupto no debe tumbar todo el dashboard
            print(f"Error leyendo {f}: {e}")

    return reports


#  RUTAS FLASK

@app.route("/")
def index():
    """
    Ruta principal — renderiza el dashboard HTML completo.

    Carga todos los reportes y los inyecta en HTML_TEMPLATE
    usando render_template_string() de Flask/Jinja2.

    render_template_string() vs render_template():
    · render_template()       → lee el template desde /templates/archivo.html
    · render_template_string() → renderiza el template desde un string en memoria
    Usamos la segunda opción para mantener todo en un solo archivo.

    Returns:
        str: HTML renderizado con los datos de los reportes.
    """
    reports_data = get_all_reports()
    return render_template_string(HTML_TEMPLATE, reports=reports_data)


@app.route("/api/reports")
def api_reports():
    """
    Endpoint REST que expone los reportes en formato JSON crudo.

    Útil para:
    · Integrar con otras herramientas o scripts externos
    · Consumir los datos desde una app Android nativa
    · Debugging — ver exactamente qué datos llegan al template

    Acceso: GET http://<IP_CELU>:5000/api/reports

    Returns:
        Response: JSON array con todos los reportes serializados.
    """
    return jsonify(get_all_reports())


#  ENTRYPOINT

if __name__ == "__main__":
    """
    Uso:
        python dashboard.py

    Acceso local (mismo dispositivo):
        http://127.0.0.1:5000

    Acceso desde otro dispositivo en la misma red:
        http://<IP_DEL_CELU>:5000
        (obtén tu IP con: ip addr show wlan0 | grep inet)

    host="0.0.0.0" hace que Flask escuche en todas las interfaces
    de red del dispositivo — no solo en localhost. Necesario para
    acceder al dashboard desde la PC usando la IP del celular.

    ⚠ No exponer este servidor a internet — no tiene autenticación.
    Solo para uso en red local de confianza.
    """
    print("[*] Levantando servidor local táctico...")
    print("[+] Accede desde el navegador de tu celular en: http://127.0.0.1:5000")

    # debug=False en producción — debug=True expone el Werkzeug debugger
    # que permite ejecución de código arbitrario desde el navegador
    app.run(host="0.0.0.0", port=5000, debug=False)
