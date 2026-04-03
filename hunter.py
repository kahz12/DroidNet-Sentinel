"""
╔══════════════════════════════════════════════════════════════════╗
║              DroidNet Hunter — Exploit Lookup Module             ║
║──────────────────────────────────────────────────────────────────║
║  Descripción:                                                    ║
║  Módulo de análisis ofensivo. Toma el reporte JSON más reciente  ║
║  generado por sentinel.py y cruza cada servicio detectado contra ║
║  la base de datos de Exploit-DB usando searchsploit.             ║
║                                                                  ║
║  Para cada servicio abierto (ej: "Apache httpd 2.4.29") busca    ║
║  exploits públicos verificados y los presenta en tabla por IP.   ║
║                                                                  ║
║  Dependencia externa:                                            ║
║  searchsploit → parte del paquete exploitdb                      ║
║  Instalar en Termux: pkg install exploitdb                       ║
║                                                                  ║
║  Flujo:                                                          ║
║  get_latest_report → parse targets → clean_service_name          ║
║                   → hunt_exploits → display tabla por IP         ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Stdlib ────────────────────────────────────────────────────────
import json        # Para parsear los reportes JSON de sentinel.py
import glob        # Para buscar archivos con wildcards (reports/*.json)
import os          # Para comparar timestamps de archivos (getmtime)
import subprocess  # Para ejecutar searchsploit como proceso externo

# ── Terceros ──────────────────────────────────────────────────────
from rich.console import Console  # Output enriquecido en terminal
from rich.table   import Table    # Tablas visuales en terminal
from rich         import print as rprint  # Print con markup de colores Rich

# ── Instancia global de consola Rich ─────────────────────────────
console = Console()


#  MÓDULO PERSISTENCIA: Localización del reporte más reciente

def get_latest_report():
    """
    Localiza el reporte de escaneo más reciente en la carpeta reports/.

    Los reportes son generados por sentinel.py con el formato:
    reports/SSID_YYYYMMDD_HHMMSS.json

    Usamos os.path.getmtime para comparar por fecha de modificación
    en lugar de parsear el nombre del archivo, lo que es más robusto
    ante cambios de naming convention en el futuro.

    Returns:
        str | None: Ruta al archivo JSON más reciente,
                    o None si la carpeta está vacía o no existe.
    """
    files = glob.glob("reports/*.json")
    if not files:
        return None
    # max() con key=getmtime → devuelve el más recientemente modificado
    return max(files, key=os.path.getmtime)


#  MÓDULO PARSING: Limpieza de nombres de servicio para searchsploit

def clean_service_name(raw_service):
    """
    Extrae y limpia el nombre del software desde la salida cruda de nmap
    para usarlo como query en searchsploit.

    Transformación:
        Input : "80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))"
        Output: "Apache httpd 2.4.29"

    Lógica de parsing (índices del split por espacios):
        [0] → "80/tcp"     (puerto, descartado)
        [1] → "open"       (estado, descartado)
        [2] → "http"       (protocolo, descartado)
        [3:] → "Apache httpd 2.4.29 ((Ubuntu))" (lo que nos interesa)

    El texto entre paréntesis (info del OS) se descarta porque
    confunde a searchsploit y no aporta al query de exploits.

    Args:
        raw_service (str): Línea de puerto en formato nmap.

    Returns:
        str | None: Nombre limpio del servicio para usar en searchsploit,
                    o None si la línea no es parseable.
    """
    parts = raw_service.split()

    # Guard: líneas muy cortas, marcadores internos o errores no son parseables
    if len(parts) < 4 or "Escudo" in raw_service or "Error" in raw_service:
        return None

    # Tomamos todo a partir del índice 3 (después de puerto/open/protocolo)
    service_query = " ".join(parts[3:])

    # Eliminamos todo lo que esté entre paréntesis y después
    # Ejemplo: "Apache httpd 2.4.29 ((Ubuntu))" → "Apache httpd 2.4.29"
    service_query = service_query.split('(')[0].strip()

    return service_query


#  MÓDULO EXPLOIT: Consulta a Exploit-DB via searchsploit

def hunt_exploits(query):
    """
    Ejecuta searchsploit con la query dada y devuelve los exploits
    encontrados en la base de datos local de Exploit-DB.

    Flags usados:
    -j               → Output en formato JSON (parseable sin regex)
    --disable-colour → Evita códigos ANSI que rompen el parse JSON

    El campo "RESULTS_EXPLOIT" del JSON contiene la lista de exploits.
    Cada entrada tiene al menos:
        - "Title" : Nombre descriptivo del exploit
        - "Path"  : Ruta al archivo en la BD local de Exploit-DB

    Nota: searchsploit trabaja contra una copia local de Exploit-DB.
    Actualizar con: searchsploit -u

    Args:
        query (str): Nombre del servicio a buscar (ej: "Apache httpd 2.4.29")

    Returns:
        list: Lista de dicts con los exploits encontrados, o [] si no hay.
    """
    try:
        proc = subprocess.run(
            ['searchsploit', query, '--disable-colour', '-j'],
            capture_output=True,
            text=True
        )

        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            return data.get("RESULTS_EXPLOIT", [])

    except Exception as e:
        rprint(f"[red]Error al consultar Exploit-DB: {e}[/red]")

    return []


#  CORE: Orquestador principal del módulo Hunter

def run_hunter():
    """
    Función principal del módulo Hunter.

    Flujo de ejecución:
    1. Localiza el reporte JSON más reciente de sentinel.py
    2. Itera sobre cada IP con servicios detectados
    3. Para cada servicio, limpia el nombre y consulta Exploit-DB
    4. Muestra los resultados en tablas Rich por IP objetivo

    Filtros aplicados:
    - Hosts sin puertos abiertos ("Escudo intacto") → se saltan
    - Hosts con error de escaneo → se saltan
    - Queries menores a 4 caracteres → se saltan (muy genéricas)
    - Por IP se muestran máximo 5 exploits en pantalla para no
      inundar la terminal, con contador de los ocultos

    La función no retorna nada — su output es puramente visual.
    """
    rprint("[bold red][☠][/bold red] Iniciando módulo DroidNet Hunter...")

    # ── 1. Cargar reporte más reciente ────────────────────────────
    latest_report = get_latest_report()
    if not latest_report:
        rprint("[yellow][-] No hay reportes de Sentinel para analizar. "
               "Ejecuta sentinel.py primero.[/yellow]")
        return

    rprint(f"[*] Cargando último escaneo: [bold white]{latest_report}[/bold white]")

    with open(latest_report, "r") as f:
        data = json.load(f)

    # ── 2. Iterar sobre targets del reporte ───────────────────────
    # Estructura del JSON: {"network": ..., "time": ..., "targets": {ip: [servicios]}}
    for ip, services in data.get("targets", {}).items():

        # Saltamos hosts sin vectores de ataque relevantes
        if "Escudo intacto" in services or "Error" in services[0]:
            continue

        rprint(f"\n[bold green][+][/bold green] Analizando vector: [bold cyan]{ip}[/bold cyan]")

        # ── 3. Procesar cada servicio del host ────────────────────
        for raw_service in services:

            # Extraemos el nombre limpio para la query
            query = clean_service_name(raw_service)

            # Query muy corta = demasiado genérica = demasiados falsos positivos
            if not query or len(query) < 4:
                continue

            rprint(f"  [*] Interrogando base de datos por: [yellow]{query}[/yellow]")
            exploits = hunt_exploits(query)

            # ── 4. Mostrar resultados en tabla ────────────────────
            if exploits:
                table = Table(show_header=True, header_style="bold red")
                table.add_column("Exploit Title", style="white")
                table.add_column("Path / EDB-ID", style="dim", justify="right")

                # Limitamos a 5 para no saturar la terminal en móvil
                for ex in exploits[:5]:
                    table.add_row(
                        ex.get("Title", "Desconocido"),
                        ex.get("Path",  "")
                    )

                console.print(table)

                # Informamos si hay más exploits disponibles no mostrados
                if len(exploits) > 5:
                    rprint(f"  [dim]... y {len(exploits) - 5} exploits más ocultos.[/dim]")

            else:
                rprint("  [dim][-] No se encontraron exploits públicos verificados.[/dim]")


#  ENTRYPOINT

if __name__ == "__main__":
    """
    Uso:
        python hunter.py

    Requiere:
        - Haber ejecutado sentinel.py al menos una vez (genera reports/)
        - searchsploit instalado: pkg install exploitdb
        - Base de datos actualizada: searchsploit -u
    """
    run_hunter()
