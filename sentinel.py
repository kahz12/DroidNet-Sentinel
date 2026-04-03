"""
╔══════════════════════════════════════════════════════════════════╗
║              DroidNet Sentinel — Core Scanner Module             ║
║──────────────────────────────────────────────────────────────────║
║  Descripción:                                                    ║
║  Módulo principal del toolkit. Se encarga de detectar la red     ║
║  WiFi activa, hacer un ping sweep para descubrir hosts, un       ║
║  deep scan de puertos/servicios, evaluar riesgos, generar        ║
║  reportes JSON, notificar vía Telegram y cortar el acceso a      ║
║  dispositivos no reconocidos vía ARP Spoofing (spoofer.py).      ║
║                                                                  ║
║  Flujo:                                                          ║
║  WiFi info → ping_sweep → deep_scan → evaluar_riesgo             ║
║           → save_report → display_table → cortar_desconocidos    ║
║           → send_telegram_alert                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Stdlib ────────────────────────────────────────────────────────
import subprocess   # Para ejecutar nmap, termux-notification, etc.
import json         # Lectura/escritura de config.json y reportes
import re           # Regex para parsear salida cruda de nmap
import os           # Manejo de rutas, carpetas y comandos de sistema
import time         # Sleep entre ciclos del daemon
import threading    # Hilos para lanzar ARP spoofing en paralelo

# ── Terceros ──────────────────────────────────────────────────────
import requests     # HTTP para Telegram API y MAC vendor lookup
from datetime import datetime, timedelta  # Control de tiempo entre re-scans
from rich.console import Console          # Output enriquecido en terminal
from rich.table   import Table            # Tablas visuales en terminal
from rich         import print as rprint  # Print con markup de colores Rich

# ── Instancia global de consola Rich ─────────────────────────────
console = Console()

# ── Constantes de configuración ───────────────────────────────────
CONFIG_FILE    = "config.json"  # Ruta al archivo de IPs confiables/excluidas
CHECK_INTERVAL = 300            # Segundos entre ciclos en modo daemon (5 min)
RESCAN_HOURS   = 6              # Horas mínimas antes de re-escanear la misma red

# ── Credenciales Telegram C2 ──────────────────────────────────────
# IMPORTANTE: Reemplaza estos valores con los tuyos antes de usar.
# Obtén el TOKEN en @BotFather y el CHAT_ID con @userinfobot.
# Nunca subas estos valores reales a un repositorio público.
TELEGRAM_TOKEN   = "TOKEN_DE_BOTFATHER"
TELEGRAM_CHAT_ID = "ID_NUMERICO"


#  MÓDULO C2: Notificaciones remotas vía Telegram

def send_telegram_alert(message):
    """
    Envía un mensaje de alerta al canal C2 de Telegram.

    Usa la Bot API de Telegram con parse_mode Markdown para
    formatear el mensaje. Falla silenciosamente si el token
    no ha sido configurado, para no interrumpir el flujo principal.

    Args:
        message (str): Texto del mensaje. Soporta markdown de Telegram.
    """
    # Guard: si el token sigue siendo el placeholder, no hacemos nada
    if TELEGRAM_TOKEN == "TOKEN_DE_BOTFATHER":
        return

    url     = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id"    : TELEGRAM_CHAT_ID,
        "text"       : message,
        "parse_mode" : "Markdown"
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        # No rompemos la ejecución si Telegram no está disponible
        rprint(f"[dim][-] Fallo en enlace satelital con Telegram: {e}[/dim]")


#  MÓDULO OSINT: Identificación de fabricante por MAC

def get_mac_vendor(mac_address):
    """
    Consulta la API pública de macvendors.com para identificar
    el fabricante de un dispositivo a partir de su dirección MAC.

    Útil para fingerprinting rápido: saber si un dispositivo
    desconocido es un router Xiaomi, una cámara TP-Link, etc.

    Args:
        mac_address (str): Dirección MAC en formato XX:XX:XX:XX:XX:XX

    Returns:
        str: Nombre del fabricante o "Desconocido" si falla.
    """
    if not mac_address or mac_address == "Unknown":
        return "Fabricante Oculto"
    try:
        url      = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Desconocido"


#  MÓDULO DE ANÁLISIS: Evaluación de riesgo por puertos abiertos

def evaluar_riesgo(puertos_lista):
    """
    Clasifica el nivel de amenaza de un host según sus puertos abiertos.

    Lógica de clasificación:
    - MÍNIMO  → Sin puertos abiertos detectados
    - BAJO    → Puertos abiertos pero no en listas de riesgo
    - MEDIO   → Servicios sin cifrar o potencialmente expuestos (HTTP, DNS...)
    - CRÍTICO → Vectores de ataque clásicos (FTP, Telnet, SMB, RDP...)

    Args:
        puertos_lista (list): Lista de strings con formato nmap
                              Ejemplo: ["80/tcp open http Apache 2.4"]

    Returns:
        str: String Rich con markup de color para la tabla.
    """
    if not puertos_lista or "Escudo intacto" in puertos_lista:
        return "[bold green]MÍNIMO[/bold green]"

    # Vectores de ataque críticos — presencia inmediata = CRÍTICO
    criticos = [
        "21/tcp",   # FTP — credenciales en claro, brute-force trivial
        "23/tcp",   # Telnet — sin cifrado, MITM trivial
        "445/tcp",  # SMB — EternalBlue, ransomware, lateral movement
        "139/tcp",  # NetBIOS — enumeración de recursos compartidos
        "3389/tcp"  # RDP — brute-force, BlueKeep
    ]

    # Servicios expuestos o sin cifrar — nivel MEDIO
    medios = [
        "80/tcp",    # HTTP — sin cifrado, posible panel admin expuesto
        "8080/tcp",  # HTTP alt — proxies, paneles de gestión
        "53/tcp",    # DNS — posible zone transfer
        "1900/tcp",  # UPnP — exploits de routers domésticos
        "2049/tcp"   # NFS — montaje remoto de filesystems
    ]

    nivel = "[bold green]BAJO[/bold green]"
    for p in puertos_lista:
        port_id = p.split()[0]  # Extraemos solo "80/tcp" del string completo
        if port_id in criticos:
            return "[bold red]CRÍTICO[/bold red]"
        if port_id in medios:
            nivel = "[bold yellow]MEDIO[/bold yellow]"
    return nivel


#  MÓDULO UI: Tabla visual de resultados en terminal

def display_results_table(ssid, scan_data):
    """
    Renderiza una tabla Rich con los resultados del escaneo.

    Columnas: IP objetivo | Nivel de riesgo | Puertos | Servicios

    Tres casos visuales:
    1. Host sin puertos abiertos → verde, "Dispositivo Protegido"
    2. Error en el escaneo → rojo, "Error de escaneo"
    3. Host con puertos abiertos → datos completos con nivel de riesgo

    Args:
        ssid (str): Nombre de la red WiFi (para el título de la tabla)
        scan_data (dict): {ip: [lista de puertos]} generado por deep_scan()
    """
    table = Table(
        title        = f"[bold cyan]Auditoría Sentinel: {ssid}[/bold cyan]",
        show_header  = True,
        header_style = "bold magenta"
    )

    table.add_column("Objetivo (IP)", style="dim", width=15)
    table.add_column("Riesgo", justify="center")
    table.add_column("Puertos/Versiones", style="green")
    table.add_column("Servicios", style="yellow")

    for ip, results in scan_data.items():
        riesgo = evaluar_riesgo(results)

        if results == ["Escudo intacto"]:
            # Host activo pero sin puertos detectados
            table.add_row(ip, riesgo, "[blue]Cerrado[/blue]", "Dispositivo Protegido")

        elif "Error" in results[0]:
            # El escaneo nmap falló para este host
            table.add_row(ip, "[white]???[/white]", "[red]Falla[/red]", "Error de escaneo")

        else:
            # Host con puertos abiertos — extraemos columnas por separado
            # Formato raw nmap: "80/tcp open http Apache httpd 2.4.29"
            puertos   = "\n".join([p.split()[0]           for p in results])  # "80/tcp"
            servicios = "\n".join([" ".join(p.split()[2:]) for p in results])  # "http Apache..."
            table.add_row(ip, riesgo, puertos, servicios)

    console.print("\n", table, "\n")


#  MÓDULO RED: Información de conexión WiFi activa

def get_wifi_info():
    """
    Obtiene la información de la conexión WiFi activa usando
    la API nativa de Termux (termux-wifi-connectioninfo).

    Solo devuelve datos si el estado del supplicant es COMPLETED,
    es decir, si hay una conexión WiFi activa y autenticada.

    Returns:
        dict | None: JSON con ssid, ip, bssid, etc. o None si no hay WiFi.
    """
    try:
        result = subprocess.run(
            ['termux-wifi-connectioninfo'],
            capture_output=True,
            text=True
        )
        data = json.loads(result.stdout)
        if data.get("supplicant_state") == "COMPLETED":
            return data
    except:
        return None
    return None


#  MÓDULO DESCUBRIMIENTO: Ping sweep de la subred /24

def ping_sweep(ip_address, excluded_list):
    """
    Descubre hosts activos en la subred /24 usando nmap -sn (sin port scan).

    El flag -sn hace solo detección de hosts (ARP en LAN),
    sin escanear puertos. Es rápido y silencioso.

    Args:
        ip_address    (str):  IP propia del dispositivo (ej: 192.168.1.100)
        excluded_list (list): IPs a excluir del escaneo (la nuestra, etc.)

    Returns:
        list: Lista de IPs activas encontradas en la red.
    """
    # Construimos el rango de red: 192.168.1.100 → 192.168.1.0/24
    network_range = ".".join(ip_address.split('.')[:-1]) + ".0/24"

    # Argumento --exclude solo si hay IPs a excluir
    exclude_args = ['--exclude', ",".join(excluded_list)] if excluded_list else []

    try:
        cmd  = ['nmap', '-sn', network_range] + exclude_args
        proc = subprocess.run(cmd, capture_output=True, text=True)

        # Parseamos las IPs de la salida: "Nmap scan report for 192.168.1.X"
        return re.findall(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', proc.stdout)
    except:
        return []


#  MÓDULO ESCANEO: Deep scan de puertos y servicios

def deep_scan(live_ips):
    """
    Realiza un escaneo rápido de puertos y detección de versiones
    sobre cada host activo descubierto por ping_sweep().

    Flags nmap usados:
    -F   → Fast scan (top 100 puertos más comunes)
    -sV  → Version detection (identifica el software y versión)
    -T4  → Timing agresivo (rápido, aceptable en LAN)

    Args:
        live_ips (list): Lista de IPs a escanear.

    Returns:
        dict: {ip: [lista de puertos abiertos]} o {ip: ["Escudo intacto"]}
    """
    results = {}

    for ip in live_ips:
        try:
            proc  = subprocess.run(
                ['nmap', '-F', '-sV', '-T4', ip],
                capture_output=True,
                text=True
            )
            # Extraemos líneas con puertos abiertos tcp
            # Formato: "80/tcp   open  http    Apache httpd 2.4.29"
            ports = re.findall(r'(\d+/tcp\s+open\s+.*)', proc.stdout)

            # Si no hay puertos abiertos, el host tiene "escudo intacto"
            results[ip] = [p.strip() for p in ports] if ports else ["Escudo intacto"]

        except:
            results[ip] = ["Error"]

    return results


#  MÓDULO RESPUESTA: Corte ARP para dispositivos desconocidos

def cortar_desconocidos(objetivos, my_ip, config):
    """
    Compara los hosts activos contra la lista de trusted_ips del config.
    Para cada host no reconocido, lanza un hilo de ARP spoofing
    usando el módulo spoofer.py (basado en arpspoof/dsniff).

    El gateway se asume como la .1 de la subred. Si tu router
    tiene otra IP, ajústalo manualmente aquí o agrégalo al config.

    Args:
        objetivos (list): IPs activas descubiertas por ping_sweep()
        my_ip     (str):  IP propia del dispositivo
        config    (dict): Configuración cargada desde config.json
    """
    # Importación deferida: si spoofer.py no existe, fallamos con gracia
    try:
        from spoofer import poison
    except ImportError:
        rprint("[yellow][-] spoofer.py no encontrado. Saltando corte ARP.[/yellow]")
        return

    # Asumimos que el gateway es la .1 de la subred
    # Ejemplo: 192.168.1.100 → gateway = 192.168.1.1
    gateway_ip = ".".join(my_ip.split('.')[:-1]) + ".1"

    # IPs de confianza definidas en config.json → "trusted_ips"
    trusted = config.get("trusted_ips", [])

    # Filtramos: solo actuamos sobre IPs que NO están en la lista blanca
    unknown = [ip for ip in objetivos if ip not in trusted]

    if not unknown:
        rprint("[dim][-] Sin desconocidos. Red limpia.[/dim]")
        return

    # Lanzamos un hilo de envenenamiento ARP por cada intruso detectado
    # daemon=True → el hilo muere solo cuando el proceso principal termine
    for ip in unknown:
        rprint(f"[bold red][☠][/bold red] Desconocido detectado: [cyan]{ip}[/cyan] — ejecutando corte ARP.")
        t = threading.Thread(
            target = poison,
            args   = (ip, gateway_ip),
            daemon = True
        )
        t.start()


#  MÓDULO PERSISTENCIA: Guardado de reportes JSON

def save_report(ssid, scan_data):
    """
    Persiste los resultados del escaneo en un archivo JSON
    dentro de la carpeta reports/.

    Naming convention: SSID_YYYYMMDD_HHMMSS.json
    Ejemplo: MURCIA_5G_20240315_143022.json

    Estos reportes son consumidos por hunter.py y dashboard.py.
    La carpeta reports/ está en .gitignore — nunca se sube al repo.

    Args:
        ssid      (str):  Nombre de la red WiFi
        scan_data (dict): Resultados del deep_scan()
    """
    if not os.path.exists("reports"):
        os.makedirs("reports")

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{ssid.replace(' ', '_')}_{ts}.json"

    with open(filename, "w") as f:
        json.dump(
            {"network": ssid, "time": ts, "targets": scan_data},
            f,
            indent=4
        )


#  CORE: Bucle principal de Sentinel

def run_sentinel(interactive=False):
    """
    Bucle principal del módulo Sentinel.

    Modos de operación:
    - interactive (default): ejecuta un solo ciclo y termina.
      Útil para uso manual y debugging.
    - daemon (--daemon flag): bucle infinito con sleep de CHECK_INTERVAL.
      Re-escanea automáticamente si:
      · Se conecta a una red diferente (SSID distinto)
      · Han pasado más de RESCAN_HOURS horas desde el último scan

    Flujo por ciclo:
    1. Obtener info WiFi actual
    2. Cargar config.json (IPs excluidas y de confianza)
    3. Verificar si corresponde escanear
    4. ping_sweep → deep_scan → save_report → display_table
    5. Cortar ARP a desconocidos
    6. Notificación nativa Android + alerta Telegram

    Args:
        interactive (bool): True = un ciclo, False = daemon infinito
    """
    last_ssid      = None         # SSID del último escaneo
    last_scan_time = datetime.min # Timestamp del último escaneo (inicio = nunca)

    rprint("[bold yellow][!][/bold yellow] DroidNet Sentinel listo.")

    while True:
        # ── 1. Info de conexión WiFi actual ───────────────────────
        info   = get_wifi_info()
        config = {"excluded_ips": [], "trusted_ips": []}

        # ── 2. Cargar configuración si existe ─────────────────────
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)

        if info:
            current_ssid = info.get('ssid', 'Desconocida')
            my_ip        = info.get('ip')
            now          = datetime.now()

            # ── 3. Decidir si toca escanear ───────────────────────
            # Se escanea si: modo interactivo, red nueva, o han pasado X horas
            should_scan = (
                interactive or
                (current_ssid != last_ssid) or
                (now - last_scan_time > timedelta(hours=RESCAN_HOURS))
            )

            if should_scan and my_ip and my_ip != "0.0.0.0":
                rprint(f"\n[bold green][*][/bold green] Scan en curso: [bold white]{current_ssid}[/bold white]")

                # Agregamos nuestra propia IP a las excluidas si no está
                excluded = config.get("excluded_ips", [])
                if my_ip not in excluded:
                    excluded.append(my_ip)

                # ── 4. Descubrimiento y escaneo ───────────────────
                objetivos = ping_sweep(my_ip, excluded)
                res       = {}

                if objetivos:
                    res = deep_scan(objetivos)
                    save_report(current_ssid, res)
                    display_results_table(current_ssid, res)

                    # ── 5. Respuesta activa: cortar intrusos ──────
                    cortar_desconocidos(objetivos, my_ip, config)

                else:
                    rprint("[yellow][-] Sin hosts detectados en la red.[/yellow]")

                # ── 6a. Notificación nativa Android ───────────────
                os.system(
                    f'termux-notification '
                    f'-t "Sentinel Alert" '
                    f'-c "{len(objetivos)} hosts analizados en {current_ssid}"'
                )

                # ── 6b. Alerta remota Telegram C2 ─────────────────
                telegram_msg  = "🛡️ *DroidNet Sentinel Report*\n\n"
                telegram_msg += f"📡 *Red:* `{current_ssid}`\n"
                telegram_msg += f"🎯 *Objetivos vivos:* {len(objetivos)}\n"
                telegram_msg += "⚠️ *Revisa el Command Center para ver vulnerabilidades.*"
                send_telegram_alert(telegram_msg)

                # Actualizamos estado para el próximo ciclo
                last_ssid, last_scan_time = current_ssid, now

        # ── Fin de ciclo ──────────────────────────────────────────
        if interactive:
            break  # Modo manual: salimos después del primer ciclo

        # Modo daemon: esperamos antes del próximo ciclo
        time.sleep(CHECK_INTERVAL)


#  ENTRYPOINT

if __name__ == "__main__":
    """
    Uso:
        python sentinel.py           → Escaneo único interactivo
        python sentinel.py --daemon  → Modo daemon (bucle infinito)
    """
    import sys
    run_sentinel(interactive="--daemon" not in sys.argv)
