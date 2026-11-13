# DroidNet Sentinel — Guía de usuario

Una guía completa y práctica para instalar, configurar y operar DroidNet
Sentinel. Está pensada para alguien que no ha usado nunca la herramienta y
termina con material de referencia al que volver.

Hay un resumen más corto en el [README](../README.md) del proyecto. La
versión en inglés de esta guía es [`user-guide.en.md`](user-guide.en.md).

---

## Índice

1. [Qué es DroidNet Sentinel](#1-qué-es-droidnet-sentinel)
2. [Uso solo autorizado](#2-uso-solo-autorizado)
3. [Cómo funciona](#3-cómo-funciona)
4. [Requisitos](#4-requisitos)
5. [Instalación](#5-instalación)
6. [Herramientas opcionales](#6-herramientas-opcionales)
7. [Primera ejecución y el menú interactivo](#7-primera-ejecución-y-el-menú-interactivo)
8. [Referencia de la línea de comandos](#8-referencia-de-la-línea-de-comandos)
9. [Configuración](#9-configuración)
10. [Los módulos en detalle](#10-los-módulos-en-detalle)
11. [Niveles de riesgo](#11-niveles-de-riesgo)
12. [Notificaciones](#12-notificaciones)
13. [El panel web](#13-el-panel-web)
14. [Dónde se guardan los datos](#14-dónde-se-guardan-los-datos)
15. [Ejecución con y sin root](#15-ejecución-con-y-sin-root)
16. [Resolución de problemas](#16-resolución-de-problemas)
17. [Preguntas frecuentes](#17-preguntas-frecuentes)
18. [Desarrollo y pruebas](#18-desarrollo-y-pruebas)
19. [Glosario](#19-glosario)

---

## 1. Qué es DroidNet Sentinel

DroidNet Sentinel es un auditor de redes Wi-Fi para Android (a través de
Termux) y Linux. Desde una sola herramienta de línea de comandos:

- descubre los dispositivos activos de tu red local,
- escanea sus puertos TCP abiertos e identifica el software que hay detrás,
- clasifica cada dispositivo por nivel de riesgo,
- busca exploits públicos y vulnerabilidades conocidas (CVEs) del software
  detectado,
- registra cómo cambia la red entre un escaneo y otro,
- y puede, si se lo pides, cortar el acceso a la red de un dispositivo no
  confiable.

También incluye un panel web (el Command Center) que muestra el historial de
escaneos con el detalle por dispositivo y las diferencias entre escaneos
consecutivos.

El mismo código funciona en un portátil Linux y en un teléfono Android
dentro de Termux. No todas las funciones están disponibles en todas las
plataformas; las diferencias se indican a lo largo de la guía.

---

## 2. Uso solo autorizado

DroidNet Sentinel es una herramienta de auditoría de seguridad. Varias de
sus funciones son intrusivas: el escaneo de puertos, el corte por ARP y la
desautenticación 802.11 pueden interrumpir una red y son ilegales en la
mayoría de jurisdicciones si se hacen sin autorización.

Úsala únicamente en:

- una red de tu propiedad, o
- una red para la que tengas permiso explícito y documentado de auditar.

Las funciones de escaneo y monitorización (Sentinel, Hunter, CVE Watcher,
panel) solo leen; no modifican los demás dispositivos. Las funciones de
respuesta activa (Spoofer, Deauther y `scan --auto-cut`) interfieren con
otros dispositivos de forma deliberada y nunca deben dirigirse a una red o a
un equipo que no tengas autorización para interrumpir. Tú eres responsable
del uso que hagas de la herramienta.

---

## 3. Cómo funciona

Un único punto de entrada, `main.py`, ofrece un menú interactivo y un
conjunto de subcomandos no interactivos. Por debajo, el código se organiza
en capas:

```
main.py
  cli/        análisis de argumentos y el menú interactivo (Rich)
  core/       base de datos, sondeo del entorno, notificador, motor de riesgo, escape de texto,
              identificación de dispositivos (DNS del router, mDNS, UPnP, Google Cast, DHCP)
  modules/    sentinel, hunter, cve_watcher, spoofer, deauther
  platform/   utilidades multiplataforma (Android / Linux)
  web/        el panel Flask y su guía en /help
```

Un ciclo de escaneo normal, que realiza el módulo Sentinel, consiste en:

1. Leer el nombre de la red (SSID) y la IP local.
2. Hacer un barrido de la subred `/24` local para encontrar dispositivos
   activos.
3. Preguntar al router, por mDNS, por UPnP y por Google Cast el nombre y el
   modelo de cada dispositivo.
4. Escanear cada dispositivo activo: primero sus puertos y luego las
   versiones del software en los puertos abiertos.
5. Clasificar cada dispositivo por riesgo según los puertos que expone.
6. Guardar el resultado en la base de datos SQLite y en un archivo JSON con
   marca de tiempo.
7. Opcionalmente cortar los dispositivos no confiables y enviar
   notificaciones.

Los demás módulos trabajan sobre el resultado de un escaneo: Hunter y CVE
Watcher leen el último escaneo guardado, y el panel lee todo el historial.

---

## 4. Requisitos

### Python

- Python 3.10 o posterior.

### Paquetes de Python (se instalan con pip)

| Paquete  | Para qué sirve                                | ¿Obligatorio? |
|----------|-----------------------------------------------|---------------|
| requests | Cliente HTTP para NVD, Vulners y Exploit-DB   | Sí            |
| rich     | Interfaz de terminal (tablas, colores, menú)  | Sí            |
| flask    | El panel web                                  | Sí            |
| scapy    | Deauther, y el modo de reserva del Spoofer    | Opcional      |

Los paquetes obligatorios están fijados a rangos compatibles en
`requirements.txt`. `scapy` también aparece ahí, pero solo lo necesitan el
Deauther y el modo de reserva del Spoofer; el resto de la herramienta
funciona sin él.

### Herramientas del sistema

`nmap` es obligatorio para todo el escaneo. Lo demás es opcional y solo lo
necesita un módulo concreto; consulta
[Herramientas opcionales](#6-herramientas-opcionales).

---

## 5. Instalación

### Linux (Debian, Ubuntu, Kali y similares)

```bash
sudo apt install python3 python3-pip python3-venv nmap dsniff libnotify-bin iw
git clone https://github.com/kahz12/DroidNet-Sentinel.git
cd DroidNet-Sentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

La línea de `apt` instala más que lo mínimo para que funcionen todos los
módulos: `nmap` (escaneo), `dsniff` (el `arpspoof` del Spoofer),
`libnotify-bin` (notificaciones de escritorio) e `iw` (leer el nombre de la
red Wi-Fi y poner una interfaz en modo monitor). Si solo vas a escanear,
basta con `nmap`.

### Android (Termux)

```bash
pkg install python nmap termux-api
git clone https://github.com/kahz12/DroidNet-Sentinel.git
cd DroidNet-Sentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Instala también la aplicación complementaria Termux:API, para que funcionen
`termux-wifi-connectioninfo` y `termux-notification`.

Limitaciones en Termux:

- `dsniff` no está empaquetado para Termux, así que el módulo Spoofer es solo
  para Linux.
- La mayoría de los chips Wi-Fi integrados de Android no admiten modo monitor
  ni inyección de paquetes, por lo que el Deauther suele necesitar un
  adaptador USB externo.
- `searchsploit` no está empaquetado para Termux. Hunter funciona sin él (ver
  [Hunter](#102-hunter-búsqueda-de-exploits)); para usarlo, clónalo
  manualmente (más abajo).

### Verificar la instalación

```bash
python main.py
```

Debería aparecer el banner y el menú interactivo. Si falta `nmap`, el
escaneo no funcionará; instálalo antes de continuar.

---

## 6. Herramientas opcionales

Cada una habilita un módulo. Instala solo lo que necesites.

| Herramienta                   | Habilita                           | Instalación en Linux             |
|-------------------------------|------------------------------------|----------------------------------|
| `nmap`                        | Todo el escaneo (obligatoria)      | `apt install nmap`               |
| `iw`                          | Nombre de la red Wi-Fi; modo monitor | `apt install iw`               |
| `nmcli` (NetworkManager)      | Nombre de la red Wi-Fi (preferido) | no hace falta si tienes `iw`     |
| `libnotify-bin`               | Notificaciones de escritorio       | `apt install libnotify-bin`      |
| `searchsploit` (exploitdb)    | Hunter (opcional, ver 10.2)        | Kali: `apt install exploitdb`; otras: ver notas |
| `dsniff` (`arpspoof`)         | Spoofer (solo Linux)               | `apt install dsniff`             |
| `aircrack-ng` (`aireplay-ng`) | Prueba de inyección del Deauther   | `apt install aircrack-ng`        |
| `scapy`                       | Deauther; reserva del Spoofer      | `pip install scapy`              |

Notas:

- La herramienta lee el nombre de la red Wi-Fi primero con `nmcli` y, si no
  está disponible, con `iw`. Basta con uno de los dos. Sin ninguno, cada red
  se guarda con una etiqueta genérica y el historial no puede distinguir unas
  de otras.
- `searchsploit` solo está empaquetado en Kali (`apt install exploitdb`). En
  Ubuntu, Debian y otras distribuciones, clona el repositorio de Exploit-DB en
  `/opt/exploitdb`, la ruta que espera su `.searchsploit_rc`, y enlaza el
  script en tu `PATH`:

  ```bash
  sudo git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
  sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
  searchsploit vsftpd 2.3.4    # comprobación: muestra la puerta trasera de vsftpd 2.3.4
  ```

  Para actualizarlo más adelante: `sudo searchsploit -u`.
- En Termux no existe `/opt`. Clona el repositorio en tu carpeta personal,
  enlaza el script y dale a `searchsploit` una copia de su configuración que
  apunte al clon (lee `~/.searchsploit_rc` antes que la suya):

  ```bash
  git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git ~/exploitdb
  ln -s ~/exploitdb/searchsploit $PREFIX/bin/searchsploit
  sed "s|/opt/exploitdb|$HOME/exploitdb|" ~/exploitdb/.searchsploit_rc > ~/.searchsploit_rc
  ```

  En cualquier caso, Hunter funciona sin `searchsploit` (ver
  [Hunter](#102-hunter-búsqueda-de-exploits)).

---

## 7. Primera ejecución y el menú interactivo

Ejecuta la herramienta sin argumentos para abrir el menú:

```bash
python main.py
```

El menú es:

```
[1]  Sentinel — Escaneo rápido    Un escaneo único de la red actual
[2]  Sentinel — Modo demonio      Escaneo continuo en segundo plano + alertas
[3]  Hunter — Búsqueda de exploits Cruza el último escaneo con Exploit-DB
[4]  CVE Watcher                  Cruza la red con CVEs conocidas
[5]  Dashboard — Command Center   Abre el panel web en http://127.0.0.1:5000
[6]  Spoofer — Corte ARP manual   Corta un dispositivo de la LAN   (root)
[7]  Deauther — Deauth 802.11     Expulsa a un cliente del AP      (root)
[8]  Informes guardados           Lista los informes JSON en reports/
[9]  Ayuda y guía de usuario      Guía rápida integrada
[0]  Salir
```

Qué hace cada opción:

- **[1] Escaneo rápido.** Ejecuta un ciclo de escaneo completo de la red
  actual y vuelve al menú. Antes de escanear pregunta si quieres activar el
  corte ARP automático de los dispositivos no confiables; por defecto es no,
  porque cortar es intrusivo.
- **[2] Modo demonio.** Escanea en bucle. Vuelve a escanear cada vez que
  cambia la red Wi-Fi o pasan seis horas, y comprueba cada cinco minutos.
  Pulsa `Ctrl+C` para detenerlo; limpia cualquier respuesta ARP activa antes
  de volver.
- **[3] Hunter.** Lee el último escaneo y busca en Exploit-DB cada servicio
  detectado.
- **[4] CVE Watcher.** Lee el último escaneo y cruza la versión de cada
  servicio detectado con la NVD. Pregunta si hacer una auditoría completa de
  todas las fechas, o la vigilancia por defecto de los últimos 120 días.
- **[5] Dashboard.** Inicia la interfaz web Flask en
  `http://127.0.0.1:5000` e imprime las credenciales de acceso o dónde
  encontrarlas. Pulsa `Ctrl+C` para detenerlo.
- **[6] Spoofer.** Pide una IP víctima, la IP de la puerta de enlace y la
  interfaz, y realiza un corte ARP bidireccional. Requiere root.
- **[7] Deauther.** Pide una MAC objetivo (o `broadcast`), el BSSID del punto
  de acceso y una interfaz en modo monitor, y envía tramas de
  desautenticación. Requiere root y hardware compatible.
- **[8] Informes guardados.** Lista los informes JSON guardados en
  `reports/`.
- **[9] Ayuda.** Muestra una guía rápida integrada. El panel incluye la misma
  guía en `/help`.
- **[0] Salir.** Cierra la herramienta. `Ctrl+C` también sale.

---

## 8. Referencia de la línea de comandos

Cada acción del menú tiene un equivalente no interactivo, que es lo que se
usa para scripts, tareas programadas (cron) o sesiones remotas. La forma
general es:

```bash
python main.py [opciones globales] <comando> [opciones del comando]
```

### Opciones globales

| Opción            | Efecto                                                           |
|-------------------|------------------------------------------------------------------|
| `-v`, `--verbose` | Registro de nivel DEBUG en pantalla.                             |
| `-q`, `--quiet`   | Solo errores en pantalla. El registro completo se sigue guardando en el archivo de log. |

### Comandos

```bash
python main.py scan [--auto-cut]
python main.py daemon [--auto-cut]
python main.py hunt
python main.py cve [--all-time]
python main.py dashboard [--expose]
python main.py reports
python main.py spoof IP_VICTIMA IP_PUERTA_ENLACE [--iface IFACE]
python main.py deauth MAC_OBJETIVO BSSID --iface IFACE [--channel N] [--count N]
python main.py db purge [--days N]
```

| Comando     | Descripción                                                          |
|-------------|---------------------------------------------------------------------|
| `scan`      | Un ciclo de escaneo completo y termina.                            |
| `daemon`    | Escaneo continuo hasta `Ctrl+C`.                                    |
| `hunt`      | Búsqueda de exploits sobre el último escaneo.                      |
| `cve`       | CVE Watcher. Con `--all-time`, audita CVEs de cualquier fecha; si no, los últimos 120 días. Alias: `cve-watch`. |
| `dashboard` | Inicia el panel web. Con `--expose`, escucha en todas las interfaces (LAN) en lugar de solo en loopback. |
| `reports`   | Lista los informes JSON guardados.                                 |
| `spoof`     | Corte ARP de un solo dispositivo. `--iface` toma por defecto la interfaz detectada. Requiere root. |
| `deauth`    | Envía tramas de desautenticación 802.11. `--iface` es obligatorio; `--channel` fija un canal (si no, salta entre 1/6/11); `--count` es el número de tramas (0 significa ilimitado). Requiere root. |
| `db purge`  | Borra los escaneos de más de `--days` días (por defecto 90).       |

Añade `--help` a cualquier comando para ver sus parámetros exactos, por
ejemplo `python main.py deauth --help`.

Ejemplos:

```bash
# Un escaneo, silencioso, para una tarea de cron
python main.py -q scan

# Monitorización continua con corte automático de dispositivos no confiables
python main.py daemon --auto-cut

# Auditoría completa de vulnerabilidades del software detectado
python main.py cve --all-time

# Exponer el panel a la LAN (solo detrás de un proxy TLS)
python main.py dashboard --expose

# Cortar un dispositivo de la red
python main.py spoof 192.168.1.50 192.168.1.1

# Desautenticar un cliente concreto en el canal 6
python main.py deauth AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 --iface wlan0mon --channel 6

# Borrar los escaneos de más de 30 días
python main.py db purge --days 30
```

### Parámetros antiguos

Las invocaciones antiguas con parámetros sueltos (`--scan`, `--daemon`,
`--hunt`, `--dashboard`, `--reports`, `--cve-watch`, `--spoof`, `--deauth`)
siguen funcionando pero muestran un aviso de obsolescencia. Prefiere los
subcomandos de arriba.

---

## 9. Configuración

### config.json

Un archivo opcional llamado `config.json` en la raíz del proyecto ajusta
algunos comportamientos. Si no existe, la herramienta funciona con listas
vacías y la retención por defecto. Ejemplo:

```json
{
    "excluded_ips":      ["192.168.1.100"],
    "trusted_ips":       ["192.168.1.1", "192.168.1.50"],
    "db_retention_days": 90
}
```

| Campo               | Significado                                                        |
|---------------------|-------------------------------------------------------------------|
| `excluded_ips`      | IPs (o rangos CIDR) que el escaneo omite. Tu propio dispositivo siempre se omite. |
| `trusted_ips`       | IPs o rangos CIDR que nunca se cortan. El equipo local y la puerta de enlace están siempre protegidos aunque no aparezcan. |
| `db_retention_days` | Cuántos días de escaneos conserva `db purge` (por defecto 90).    |

El archivo se valida al cargarlo. Las entradas con un tipo incorrecto
vuelven a su valor por defecto en lugar de hacer fallar la herramienta, y
las entradas de las listas que no son IPs ni rangos CIDR válidos se
descartan con un aviso.

### Variables de entorno

| Variable           | Para qué sirve                                      | Valor por defecto                           |
|--------------------|-----------------------------------------------------|---------------------------------------------|
| `TELEGRAM_TOKEN`   | Token del bot de Telegram para las alertas          | sin definir (alertas de Telegram desactivadas) |
| `TELEGRAM_CHAT_ID` | ID numérico del chat de Telegram                    | sin definir (alertas de Telegram desactivadas) |
| `SENTINEL_USER`    | Usuario del panel                                   | `admin`                                     |
| `SENTINEL_PASS`    | Contraseña del panel                                | se genera y se guarda en `~/.sentinel/credentials` (modo 0600) |
| `SENTINEL_SECRET`  | Clave secreta de sesión de Flask                    | aleatoria en cada arranque                  |
| `NVD_API_KEY`      | Clave de API de NVD para subir el límite de peticiones del CVE Watcher | sin definir (límite más lento) |
| `VULNERS_API_KEY`  | Clave de API de Vulners; fuente de Hunter sin searchsploit | sin definir (se usa el catálogo de Exploit-DB) |
| `DROIDNET_LOG_DIR` | Directorio del archivo de log                       | `logs/` bajo la raíz del proyecto           |

Define las que necesites antes de arrancar, por ejemplo:

```bash
export SENTINEL_USER="operador"
export SENTINEL_PASS="una-contraseña-fuerte"
export TELEGRAM_TOKEN="123456:abcdef..."
export TELEGRAM_CHAT_ID="987654321"
python main.py dashboard
```

Para que persistan, ponlas en un archivo `.env` en la raíz del proyecto, una
por línea con la forma `NOMBRE=valor` (se aceptan `export`, comillas y
comentarios con `#`):

```bash
VULNERS_API_KEY="tu-clave"
TELEGRAM_TOKEN="123456:abcdef..."
TELEGRAM_CHAT_ID="987654321"
```

El archivo se lee al arrancar y git lo ignora. Una variable ya definida en el
entorno tiene prioridad sobre el archivo. Usa los nombres de variable de la
tabla anterior; una línea que no sea `NOMBRE=valor` se ignora. Como el
archivo guarda secretos, haz que solo tú puedas leerlo: `chmod 600 .env`.
También puedes añadir las líneas `export` al perfil de tu shell (`~/.bashrc`
o `~/.zshrc`).

---

## 10. Los módulos en detalle

### 10.1 Sentinel (el escáner)

Sentinel es el núcleo. Un ciclo de escaneo hace lo siguiente:

1. **Leer la red.** Determina el nombre de la Wi-Fi actual y tu IP local. En
   Linux el nombre viene de `nmcli` o de `iw` cuando no se usa
   NetworkManager. Sin ninguno de los dos, la red se etiqueta de forma
   genérica y el historial no puede distinguir una red de otra.
2. **Descubrimiento.** Un barrido de la `/24` local encuentra los
   dispositivos activos. Cuando un primer intento falla por completo (no
   simplemente una red vacía), se reintenta en el ciclo siguiente.
3. **Identificación.** Cuatro fuentes rellenan las columnas Hostname y
   Device, en paralelo, en pocos segundos y sin root:
   - el DNS inverso del router, que en la mayoría de routers domésticos
     devuelve el nombre que cada dispositivo dio por DHCP;
   - mDNS (Bonjour/Avahi), preguntado directamente a cada dispositivo: su
     nombre `.local`, su modelo (dispositivos Apple, Chromecast, dispositivos
     AirPlay y HomeKit, impresoras de red) y el nombre que le puso su dueño;
   - una búsqueda SSDP: routers, smart TVs, altavoces y servidores
     multimedia describen su fabricante y modelo por UPnP;
   - la descripción que los dispositivos Google Cast sirven en el puerto
     8008, que identifica Chromecasts y Google TVs que no responden ni a
     mDNS ni a SSDP.

   Si nmap ya encontró un hostname, se conserva. La columna Device muestra
   el modelo cuando el dispositivo lo dio y, si no, el fabricante de la MAC.
   Cuando se conoce la MAC pero no su prefijo (normalmente un móvil con
   dirección privada por red), muestra `Randomized MAC`. Es lo normal en
   Android e iOS, así que es solo informativo y no cambia el riesgo. Los
   móviles sin ninguna app que anuncie servicios a menudo no responden a
   ninguna de estas consultas, y un router sin DNS ni UPnP no añade nada; el
   escaneo sigue igual. La descripción de un dispositivo solo se descarga
   por HTTP plano del propio dispositivo, nunca de otra dirección.

   **Huellas DHCP pasivas (root).** Con root, Sentinel además escucha en el
   puerto UDP 67 durante toda la sesión y registra las peticiones que los
   dispositivos difunden al unirse a la red: el hostname que anuncian
   (opción 12), su clase de vendedor (opción 60) y su lista de parámetros
   solicitados (opción 55). Una MAC aleatoria oculta el fabricante, pero no
   el cliente DHCP, así que la columna Device gana una segunda línea con el
   sistema operativo: `Android 14`, `Windows`, `Apple (iOS/macOS)`,
   `Linux (Raspberry Pi)`. Solo las señales claras se convierten en
   etiqueta; cualquier otra lista se escribe en el log como huella para
   buscarla en fingerbank.org. El listener nunca envía nada. Las
   renovaciones del préstamo van directas al router y no se ven, así que un
   dispositivo solo aparece cuando se une o se vuelve a unir (una
   reconexión Wi-Fi, al despertar): es más útil en modo daemon, que corre
   durante horas. Un cortafuegos en el equipo, como ufw, descarta estos
   broadcasts salvo que una regla los deje entrar (ver
   [Resolución de problemas](#16-resolución-de-problemas)); Sentinel avisa
   cuando ufw está activo sin ella. Algunos puntos de acceso no reenvían
   los broadcasts de un cliente a los demás, y entonces tampoco se oye nada.
4. **Escaneo por dispositivo, en dos pasadas.** Primero se escanean rápido
   los 100 puertos TCP más comunes. Luego, solo en los puertos abiertos, una
   detección de versiones más lenta identifica el software. Separar el
   trabajo importa: la detección de versiones puede ser lenta cuando un
   servicio no responde a las sondas, y una pasada de versiones lenta o
   fallida conserva igualmente la lista de puertos abiertos, de modo que el
   dispositivo se evalúa de todas formas. Cada pasada tiene su propio límite
   de tiempo.
5. **Clasificación de riesgo.** Cada dispositivo se puntúa según los puertos
   que expone (ver [Niveles de riesgo](#11-niveles-de-riesgo)). Un
   dispositivo con todos los puertos cerrados o filtrados se informa como
   protegido. Un dispositivo que no se pudo escanear se escanea una vez
   más cuando terminan todos los demás; si vuelve a fallar, queda como
   `UNKNOWN`.
6. **Persistencia.** El resultado se escribe en la base de datos SQLite y en
   un archivo JSON con marca de tiempo en `reports/`. Un escaneo completo que
   no encuentra dispositivos también se guarda, para que el panel pueda
   mostrar que hubo dispositivos que desaparecieron.
7. **Respuesta activa y alertas (opcional).** Con `--auto-cut`, los
   dispositivos no confiables se cortan. En todos los casos se envía una
   notificación del sistema operativo y, si está configurada, una alerta de
   Telegram.

El **modo demonio** repite este ciclo. Comprueba cada cinco minutos y vuelve
a escanear cada vez que la red Wi-Fi cambia o cuando han pasado seis horas
desde el último escaneo de la red actual. Pulsa `Ctrl+C` para detenerlo;
espera a que terminen los escaneos en curso o a que alcancen su límite de
tiempo, y restaura las respuestas ARP que haya iniciado. La restauración se
intenta al salir, pero su éxito depende de la red y del sistema operativo.

### 10.2 Hunter (búsqueda de exploits)

Hunter lee el último escaneo guardado que encontró al menos un servicio,
que es el mismo escaneo que analiza CVE Watcher, extrae el nombre del
producto y la versión de cada servicio y busca en Exploit-DB. El escaneo se
toma de la base de datos del historial, no de los archivos JSON de
`reports/`. Muestra hasta cinco coincidencias por servicio.

Hunter usa la primera fuente disponible:

1. **`searchsploit`**, si está instalado: el Exploit-DB local, sin conexión.
2. **Vulners**, si `VULNERS_API_KEY` está definida. Vulners no responde a
   clientes sin clave. La clave viaja en una cabecera de la petición, nunca
   en una URL, y se elimina de cualquier mensaje de error.
3. **El catálogo de Exploit-DB** en cualquier otro caso. Hunter descarga el
   índice público de Exploit-DB (`files_exploits.csv`, unos 10 MB) en
   `exploitdb_cache/` la primera vez y lo consulta sin conexión. Se revalida
   una vez por semana, sin descargar nada mientras no cambie, y una copia
   existente sigue funcionando sin internet. También se usa cuando falla una
   consulta a Vulners.

Igual que `searchsploit`, un exploit solo cuenta cuando su título cubre la
versión detectada: dnsmasq 2.85 no coincide con "Dnsmasq < 2.78". Una búsqueda fallida se informa como tal y se distingue de una
búsqueda con éxito que simplemente no encontró nada. Los resultados se
almacenan en caché solo durante una ejecución de Hunter.

### 10.3 CVE Watcher

CVE Watcher lee el último escaneo y cruza la versión de cada servicio
detectado con la NVD (National Vulnerability Database del NIST). Tiene dos
modos:

```bash
python main.py cve              # vigilancia: CVEs publicadas en los últimos 120 días
python main.py cve --all-time   # auditoría completa: CVEs de cualquier fecha
```

- El **modo vigilancia** sirve para detectar vulnerabilidades recién
  publicadas. Es el modo por defecto y el adecuado para ejecutar con
  regularidad.
- La **auditoría completa** cruza con CVEs de cualquier fecha. Es el modo que
  saca a la luz vulnerabilidades antiguas y conocidas de software viejo, por
  ejemplo el firmware anticuado de un router. El menú interactivo pregunta
  qué modo ejecutar.

Por cada servicio, se consulta a la NVD de dos formas:

- **Por CPE** (un identificador preciso de producto y versión): la propia
  coincidencia de la NVD de la versión exacta contra cada CVE. Un mismo
  producto puede estar registrado en la NVD bajo más de un nombre de
  fabricante; en ese caso se consultan todos los nombres y los resultados se
  unen sin duplicados.
- **Por búsqueda en la descripción**: para captar CVEs que la NVD ha
  publicado pero aún no ha analizado (que una consulta por CPE no puede ver).
  Una coincidencia por descripción solo se conserva cuando el texto nombra el
  producto seguido inmediatamente de las versiones afectadas que cubren la
  versión detectada; si no, se descarta como ruido. Estas se etiquetan como
  **candidatas** para indicar que su aplicabilidad se infiere de la
  descripción, no está confirmada por la NVD.

Cada coincidencia se puntúa (CVSS 3.1, 3.0, 4.0 o 2.0, lo que ofrezca la
NVD), recibe un resumen de impacto en lenguaje claro y se guarda en la tabla
`cve_alerts`. Las alertas se anuncian una vez: una nueva detección solo
vuelve a avisar si cambia su gravedad o si una candidata se confirma luego
por CPE. Una consulta que falla produce un resultado explícito de
"incompleto" en lugar de un falso "no se encontró nada". Las respuestas se
guardan en caché en disco durante 24 horas, con una clave distinta por modo,
así que una repetición el mismo día usa la caché y no espera entre
peticiones.

Los servicios que nmap informa sin versión no se pueden cruzar con ningún
rango afectado. Samba, por ejemplo, suele aparecer como
`Samba smbd 3.X - 4.X`, y Postfix casi nunca anuncia su versión. Esos
servicios no se consultan: la ejecución termina con una línea "Not checked,
version not detected" que los nombra, para que la ausencia de coincidencias
nunca se interprete como un resultado limpio. Las versiones también se
normalizan antes de cruzarlas: MariaDB se anuncia como
`5.5.5-<versión real>` por compatibilidad con clientes MySQL antiguos, y se
usa la versión real que va tras el prefijo.

Define `NVD_API_KEY` para subir el límite de peticiones.

### 10.4 Dashboard

Ver [El panel web](#13-el-panel-web).

### 10.5 Spoofer (corte ARP)

El Spoofer realiza un ataque de envenenamiento ARP bidireccional que corta a
un solo dispositivo de la red: le dice a la víctima que la puerta de enlace
está en tu MAC, y a la puerta de enlace que la víctima está en tu MAC, de
modo que el tráfico entre ambos deja de circular. Prefiere dos procesos
`arpspoof` gestionados (de `dsniff`) y recurre a una implementación con Scapy
cuando `arpspoof` no está disponible y `scapy` sí. Con `Ctrl+C` o si el
arranque falla, los procesos se detienen y las tablas ARP se reparan.
Requiere root. `dsniff` no está disponible en Termux, así que el Spoofer es
solo para Linux.

### 10.6 Deauther (desautenticación 802.11)

El Deauther construye e inyecta tramas de desautenticación 802.11 (trama de
gestión tipo `0xC0`, código de motivo 7) para desconectar a un cliente
concreto o a todos los clientes de un punto de acceso (broadcast). Requiere
root y una interfaz en modo monitor; usa `iw` para cambiar la interfaz y,
cuando está disponible, `aireplay-ng` para comprobar si el chipset puede
inyectar tramas de verdad. Si no se indica canal, salta entre los canales 1,
6 y 11. No tiene efecto sobre puntos de acceso WPA3 con protección de tramas
de gestión (802.11w) activada; esto es por diseño del protocolo, no una
limitación de la herramienta. La mayoría de los chips integrados de Android
no pueden inyectar, así que en un teléfono suele hacer falta un adaptador USB
externo.

### 10.7 Modo guardián (auto-cut continuo)

`daemon --auto-cut` convierte a Sentinel en un control de acceso rudimentario:
en cada ciclo vuelve a escanear la red y corta por ARP todo dispositivo que no
esté en tu lista blanca `trusted_ips`, de modo que un equipo que no debería
estar ahí queda fuera de la LAN. Es destructivo y está apagado por defecto;
úsalo solo en una red que tengas autorización para defender.

Dos cosas lo hacen seguro para dejarlo corriendo sin vigilancia:

- **La lista blanca es obligatoria.** Con `trusted_ips` vacía, "no se confía en
  nadie" cortaría todos los dispositivos de la red, así que el auto-cut se niega
  y sigue solo monitorizando, dejando constancia del rechazo. Empieza a vigilar
  en cuanto añades al menos una entrada de confianza: el daemon relee
  `config.json` en cada ciclo, sin reiniciar.
- **Los objetivos nunca se reproducen desde disco.** El conjunto a cortar se
  vuelve a derivar de un escaneo fresco en cada ciclo. Si un intruso cambia de
  IP (una renovación DHCP), se le sigue detectando por "no está en la lista"; si
  un dispositivo de confianza toma la IP antigua del intruso, no se le corta por
  error. Por eso el guardián no guarda una lista de objetivos para "retomarla":
  re-derivar es más seguro y más eficaz.

**Diario de auditoría.** Cada corte, restauración y rechazo se escribe en un
diario dentro de la base de datos, separado del historial de escaneos para que
purgar escaneos viejos nunca lo borre. Léelo con `python main.py guard-log` (lo
más reciente primero; `--limit N` para más filas). Responde a "a quién se cortó,
cuándo y en qué red".

**Cierre y energía.** El guardián repara las tablas ARP de cada host que cortó
cuando se detiene: con `Ctrl+C`, y también con `SIGTERM` (`systemctl stop`) y
`SIGHUP` (cerrar la terminal). Un `SIGKILL` no se puede atrapar, así que una
muerte dura del killer de poca memoria o del Phantom Process de Android se salta
la reparación; la red se recupera sola al caducar las cachés ARP, y el diario
conserva el registro. En Termux, un wake lock (de `termux-api`) evita que Doze
congele el daemon entre escaneos.

**Autoarranque al encender.** Para reanudar la vigilancia tras un reinicio,
arranca el daemon desde el sistema operativo, no desde un estado de ataque
guardado:

- **Linux (systemd).** Crea `/etc/systemd/system/droidnet-guard.service`:

  ```ini
  [Unit]
  Description=DroidNet Sentinel guardian
  After=network-online.target
  Wants=network-online.target

  [Service]
  ExecStart=/ruta/al/venv/bin/python /ruta/a/DroidNet-Sentinel/main.py daemon --auto-cut
  WorkingDirectory=/ruta/a/DroidNet-Sentinel
  Restart=on-failure
  # SIGTERM detiene el servicio, lo que dispara la restauración ARP.

  [Install]
  WantedBy=multi-user.target
  ```

  Luego `sudo systemctl enable --now droidnet-guard`.

- **Android (Termux).** Instala el complemento Termux:Boot y crea
  `~/.termux/boot/droidnet-guard.sh` (hazlo ejecutable):

  ```bash
  #!/data/data/com.termux/files/usr/bin/sh
  termux-wake-lock
  cd ~/DroidNet-Sentinel && ./venv/bin/python main.py daemon --auto-cut
  ```

Ninguna de las dos recetas se instala sola: un operador avanzado la monta a
propósito, y un usuario casual no la dispara por accidente.

---

## 11. Niveles de riesgo

Cada dispositivo se puntúa según el conjunto de puertos TCP abiertos que
expone. Solo se tiene en cuenta el número de puerto, no el banner del
servicio.

| Nivel    | Lo activa                                                       | Significado                                          |
|----------|----------------------------------------------------------------|------------------------------------------------------|
| CRITICAL | FTP (21), Telnet (23), NetBIOS (139), SMB (445), RDP (3389)    | Un servicio de alto riesgo que no debería estar expuesto. |
| MEDIUM   | HTTP (80, 8080), DNS (53), SSDP (1900), NFS (2049), MQTT (1883, 8883), CoAP (5683) | Un servicio expuesto que conviene revisar. |
| LOW      | Cualquier otro puerto abierto                                  | Puertos abiertos, de menor impacto.                  |
| MINIMAL  | Sin puertos abiertos (todos cerrados o filtrados)             | Accesible pero no expone nada.                       |
| UNKNOWN  | Un escaneo fallido, inalcanzable o no concluyente              | No se pudo evaluar el dispositivo; reintenta antes de sacar conclusiones. |

La clasificación es una única regla compartida, así que la tabla del
terminal, la base de datos y el panel siempre coinciden. En el panel, un
dispositivo UNKNOWN se muestra como no evaluado y no como sano, de modo que
un error de escaneo nunca se confunde con un resultado limpio.

---

## 12. Notificaciones

Después de cada ciclo de escaneo, Sentinel envía una notificación breve. Hay
dos canales.

### Notificación de escritorio o de Termux

En Linux usa `notify-send` (de `libnotify-bin`); en Termux usa
`termux-notification`. Si no hay ninguno disponible, el mensaje se imprime en
el terminal.

### Telegram

Para recibir alertas en Telegram:

1. Crea un bot con `@BotFather` en Telegram y copia su token.
2. Averigua tu ID de chat numérico (varios bots públicos lo indican, por
   ejemplo escribiendo a `@userinfobot`).
3. Exporta ambos valores antes de arrancar:

   ```bash
   export TELEGRAM_TOKEN="123456:abcdef..."
   export TELEGRAM_CHAT_ID="987654321"
   ```

Cuando las dos variables están definidas, se envía un resumen después de
cada escaneo y por las alertas de CVE. Los mensajes usan el formato HTML de
Telegram, y todo el texto controlado por la red (nombres de red, banners de
servicio) se escapa para que no pueda romper el mensaje ni inyectar en él. Si
Telegram rechaza un mensaje o la red falla, el motivo se informa en pantalla
y en el log, y el escaneo continúa; el token del bot nunca se imprime en esos
mensajes. Si las variables no están definidas, el paso de Telegram se omite
en silencio.

Un apunte sobre las alertas de CVE: una alerta se envía una vez. Si
configuras Telegram cuando ya había alertas guardadas, esas alertas
existentes no se reenvían; solo las nuevas, los cambios de gravedad y las
confirmaciones de candidata a CPE generan un mensaje nuevo.

---

## 13. El panel web

Arráncalo con:

```bash
python main.py dashboard
```

Escucha en `http://127.0.0.1:5000` por defecto. La consola imprime el usuario
y, o bien la contraseña, o bien la ruta donde se guardó una contraseña
generada automáticamente.

### Iniciar sesión

- El usuario viene de `SENTINEL_USER` (por defecto `admin`).
- La contraseña viene de `SENTINEL_PASS`. Si no la defines, se genera una
  contraseña fuerte y se escribe en `~/.sentinel/credentials` con permisos
  solo para el propietario (modo 0600), en lugar de imprimirla donde los logs
  podrían capturarla. Léela con `cat ~/.sentinel/credentials`.

El acceso está protegido por un token CSRF por sesión, una comprobación de
credenciales de tiempo constante y un límite de cinco intentos por minuto y
por dirección IP.

### Páginas y API

| Ruta                    | Descripción                                           |
|-------------------------|-------------------------------------------------------|
| `/login`, `/logout`     | Autenticación de sesión.                              |
| `/`                     | El panel: tarjetas de escaneo, indicadores resumen, vista de diferencias. |
| `/alerts`               | Las alertas de CVE, de la más urgente a la menos, con filtros. |
| `/help`                 | La guía de usuario integrada.                          |
| `/api/reports`          | El historial de escaneos en JSON.                     |
| `/api/scan/<id>/diff`   | Las diferencias de un escaneo frente al anterior.     |
| `/api/alerts`           | Las alertas de CVE en JSON, con los mismos filtros que `/alerts`. |

`/api/reports` devuelve un array JSON. Sin parámetros devuelve todo el
historial. Con `page` y `per_page` pagina (por defecto 20 por página, máximo
100); las cabeceras de respuesta `X-Total-Count`, `X-Page`, `X-Per-Page` y
`Link` describen la paginación, y la cabecera `Link` apunta a la página
siguiente.

### Alertas de CVE

La página **CVE alerts** (`/alerts`, enlazada desde la barra de navegación)
lista las vulnerabilidades que CVE Watcher ha encontrado, ordenadas por
gravedad, después por puntuación CVSS y después de la más reciente a la más
antigua. Cada fila muestra la gravedad, la puntuación, el identificador del
CVE (enlazado a su ficha en la NVD), el dispositivo y su red, el servicio
afectado, cómo se encontró y cuándo se detectó por primera vez (en UTC). Al
desplegar una fila aparecen el resumen de impacto y la descripción del CVE.

- **Match: CPE** significa que la propia NVD cruzó la versión exacta
  detectada. **Candidate** significa que la NVD aún no ha analizado el CVE y
  las versiones afectadas se leyeron de su descripción; compruébalo antes de
  actuar.
- Los filtros de la parte superior acotan la lista por red y por gravedad.
  Elegir un dispositivo desde una fila, o desde una tarjeta de escaneo,
  añade un filtro por dispositivo.
- En el panel principal, un indicador **CVE alerts** muestra el total y
  cuántas son críticas o altas, y cada dispositivo con alertas lleva un
  distintivo como "4 CVEs", del color de su alerta más grave, que abre la
  página filtrada por ese dispositivo.

`/api/alerts` devuelve los mismos datos como un array JSON y admite los
mismos parámetros `network`, `ip` y `severity`. La página y la API solo leen
las alertas; las genera la ejecución de `python main.py cve`.

### Exponerlo a la red

Por defecto el panel escucha solo en loopback, así que es accesible desde la
propia máquina. Para hacerlo accesible desde la LAN:

```bash
python main.py dashboard --expose
```

Hazlo solo detrás de un proxy inverso que termine TLS, como nginx o caddy.
Sobre HTTP plano, las credenciales de acceso viajan en texto claro. El banner
de arranque avisa de esto cuando usas `--expose`.

---

## 14. Dónde se guardan los datos

Todas las rutas son relativas a la raíz del proyecto salvo que se indique lo
contrario.

| Ruta                        | Contenido                                                     |
|-----------------------------|---------------------------------------------------------------|
| `sentinel.db`               | Base de datos SQLite: escaneos, dispositivos, puertos y alertas de CVE. |
| `reports/`                  | Un archivo JSON con marca de tiempo por escaneo, por portabilidad. |
| `nvd_cache/`                | Respuestas de la NVD en caché (vigencia de 24 horas).        |
| `exploitdb_cache/`          | Catálogo de Exploit-DB para Hunter (se revalida cada semana). |
| `logs/droidnet.log`         | Archivo de log rotatorio (se puede cambiar con `DROIDNET_LOG_DIR`). |
| `config.json`               | Configuración opcional (ver [Configuración](#9-configuración)). |
| `~/.sentinel/credentials`   | Contraseña del panel generada automáticamente (modo 0600), en tu carpeta personal. |

Las tablas de la base de datos son:

```
scans       id, network, scan_time, total_devices, created_at
hosts       id, scan_id, ip, risk
ports       id, host_id, port_entry
cve_alerts  id, cve_id, severity, score, service, ip, summary,
            impact, network, scan_id, created_at, match_type, notified_key
guard_events id, ts, action, ip, mac, network, reason
```

`guard_events` es el diario de auditoría del auto-cut (ver
[Modo guardián](#107-modo-guardián-auto-cut-continuo)); la purga por retención
de escaneos no lo toca.

Los informes JSON se escriben en paralelo a la base de datos, así que puedes
mover o archivar escaneos individuales sin la base de datos.

---

## 15. Ejecución con y sin root

La mayor parte de la herramienta funciona sin root, pero algunas funciones lo
necesitan.

| Función                              | Sin root                                        | Con root               |
|--------------------------------------|-------------------------------------------------|------------------------|
| Descubrimiento y escaneo de puertos  | Funciona (usa sondas basadas en TCP)            | Funciona (puede usar ARP/ICMP) |
| Columna Hostname                     | De nmap, del DNS del router, de mDNS, UPnP o Cast | Igual                |
| Columna Device: modelo               | De mDNS, UPnP o Cast, en los dispositivos que responden | Igual          |
| Columna Device: fabricante de la MAC | Vacía (la MAC necesita ARP, que necesita root)  | Rellena; las direcciones privadas se muestran como `Randomized MAC` |
| Columna Device: sistema por DHCP     | No disponible (el puerto 67 necesita root)      | De los dispositivos que se unen mientras Sentinel corre; mejor en modo daemon |
| CVE Watcher, Hunter, panel           | Funciona                                        | Funciona               |
| Spoofer (corte ARP)                  | No disponible                                   | Obligatorio            |
| Deauther (deauth 802.11)             | No disponible                                   | Obligatorio            |

Ejecutar un escaneo sin privilegios es el modo normal y es suficiente para
auditar la exposición. Root solo se vuelve necesario para los módulos de
respuesta activa y para los datos de descubrimiento más completos.

---

## 16. Resolución de problemas

**"nmap no encontrado" o el escaneo no hace nada.**
Instala nmap (`apt install nmap`, o `pkg install nmap` en Termux) y vuelve a
ejecutar. nmap es obligatorio para todo el escaneo.

**Cada red se guarda como "Wired Network" o "Unknown Wi-Fi".**
La herramienta no pudo leer el nombre de la Wi-Fi. Instala `iw`
(`apt install iw`) o asegúrate de que `nmcli` está disponible. En Termux,
instala la app Termux:API. Las tareas programadas (cron, systemd) suelen
arrancar con un `PATH` mínimo; Sentinel también busca en `/usr/sbin` y
`/sbin`, donde está `iw`, así que lo encuentra aunque esos directorios no
estén en el `PATH` del servicio.

**Un dispositivo aparece como UNKNOWN o "Scan error".**
El dispositivo no respondió de forma constante durante el escaneo, a menudo
porque se durmió (habitual en teléfonos con el ahorro de energía del Wi-Fi).
Sentinel ya vuelve a escanear ese dispositivo una segunda vez al final del
escaneo, así que UNKNOWN significa que falló los dos intentos y no se pudo
evaluar en ese momento. Vuelve a escanear más tarde, o despierta antes el
dispositivo, para reintentarlo.

**El acceso al panel siempre falla con un error.**
Si `SENTINEL_PASS` contiene bytes que no son UTF-8 válido, no se puede
teclear en el formulario de acceso. El banner de arranque avisa de esto.
Define `SENTINEL_PASS` con un valor de texto normal.

**No definí contraseña; ¿dónde está?**
Se generó y se guardó en `~/.sentinel/credentials`. Léela con
`cat ~/.sentinel/credentials`, o define `SENTINEL_PASS` tú mismo.

**No llegan las alertas de Telegram.**
Comprueba que `TELEGRAM_TOKEN` y `TELEGRAM_CHAT_ID` están definidas y son
correctas. Un fallo de entrega se informa en pantalla y en el log con el
motivo que da la propia Telegram. Si alguna vez viste el token en un mensaje
de error o en una captura, revócalo en `@BotFather` y usa uno nuevo.

**CVE Watcher no informa nada de software antiguo.**
La vigilancia por defecto solo mira los últimos 120 días. Ejecuta
`python main.py cve --all-time` para una auditoría completa de todas las
fechas; ese es el modo que informa de vulnerabilidades antiguas y conocidas.

**El Deauther no tiene efecto.**
Las redes modernas con WPA3 y protección de tramas de gestión (802.11w) son
inmunes a la desautenticación por diseño. Comprueba también que la interfaz
está en modo monitor y que el chipset puede inyectar (el módulo lo prueba
cuando `aireplay-ng` está disponible).

**Las peticiones a la NVD son lentas.**
Sin clave de API, el límite de ritmo público de la NVD es bajo. Define
`NVD_API_KEY` para subirlo. Las ejecuciones repetidas el mismo día se
sirven desde la caché local.

**Las huellas DHCP no aparecen nunca, aun ejecutando como root.**
La causa habitual es un cortafuegos en el propio equipo: tcpdump ve las
peticiones porque captura antes del cortafuegos, pero el listener solo
recibe lo que este deja pasar. Con ufw, permite la entrada de las
peticiones: `sudo ufw allow proto udp from any port 68 to any port 67`.
Sentinel muestra un aviso al arrancar cuando ufw está activo sin esa regla.
Recuerda que un dispositivo solo envía estas peticiones al unirse a la red:
reconecta su Wi-Fi para verlo enseguida.

---

## 17. Preguntas frecuentes

**¿El escaneo cambia algo en los demás dispositivos?**
No. El descubrimiento, el escaneo de puertos, Hunter, CVE Watcher y el panel
solo leen. Solo el Spoofer, el Deauther y `scan --auto-cut` interfieren con
otros dispositivos, y lo hacen únicamente cuando se lo pides de forma
explícita.

**¿Puedo ejecutarlo de forma continua?**
Sí. El modo demonio (`python main.py daemon`) escanea en bucle y vuelve a
escanear cuando cambia la red. Combínalo con las alertas de Telegram para
enterarte de los cambios.

**¿Necesita conexión a internet?**
El escaneo y el panel funcionan sin conexión. CVE Watcher necesita internet
para llegar a la NVD. Hunter funciona sin conexión con `searchsploit`, o con
el catálogo de Exploit-DB una vez descargado; la fuente Vulners necesita
internet.

**¿De dónde salen los datos de vulnerabilidades?**
CVE Watcher consulta la NVD del NIST. Hunter busca en Exploit-DB: en local
con `searchsploit`, a través de la API de Vulners si hay clave, o en el
catálogo de Exploit-DB descargado.

**¿Una coincidencia de CVE garantiza que sea explotable?**
No. Una coincidencia de CVE significa que la versión detectada cae dentro de
un rango afectado. Las coincidencias candidatas se infieren de las
descripciones de los CVE y se etiquetan como tales. Los fabricantes a veces
publican actualizaciones de seguridad sin cambiar el número de versión, así que
confírmalo con la versión real del firmware o del paquete.

---

## 18. Desarrollo y pruebas

Instala las dependencias de desarrollo y ejecuta las comprobaciones:

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check droidnet main.py tests --select F,E9,B
python -m vulture droidnet main.py --min-confidence 80
```

La batería de pruebas simula el escaneo, el envío de paquetes, los cambios de
interfaz y las peticiones a APIs externas; no toca la red real, la base de
datos real ni el log real. Las pruebas de base de datos usan archivos
temporales, y el directorio de logs se redirige durante toda la ejecución de
las pruebas. El hardware Wi-Fi real y los servicios externos en vivo
requieren una validación aparte y manual. `scapy` puede no estar disponible
en entornos restringidos; los módulos que lo usan lo informan sin romper
importaciones ni pruebas ajenas.

Las mismas comprobaciones se ejecutan automáticamente en GitHub Actions
(`.github/workflows/ci.yml`) en cada push a `main` y en cada pull request: la
batería de pruebas en Python 3.10, 3.11, 3.12, 3.13 y 3.14, y después `ruff`
y `vulture`. Un pull request muestra el resultado de cada job antes de
fusionarse.

---

## 19. Glosario

- **Corte ARP / envenenamiento ARP.** Envenenar las tablas ARP de dos
  dispositivos para que el tráfico entre ellos deje de circular, cortando a
  un dispositivo de la red.
- **BSSID.** La dirección MAC de un punto de acceso Wi-Fi.
- **CPE.** Common Platform Enumeration, un identificador estandarizado de un
  producto y versión, usado para consultar la NVD con precisión.
- **CVE.** Common Vulnerabilities and Exposures, un identificador público de
  una vulnerabilidad conocida.
- **CVSS.** El sistema de puntuación que asigna una gravedad (0 a 10) a un
  CVE.
- **Desautenticación.** Una trama de gestión 802.11 que desconecta a un
  cliente de un punto de acceso.
- **Modo monitor.** Un modo de interfaz Wi-Fi capaz de observar e inyectar
  tramas 802.11 en crudo; lo necesita el Deauther.
- **NVD.** La National Vulnerability Database del NIST, la fuente de los datos
  de CVE.
- **SSID.** El nombre legible de una red Wi-Fi.
- **Barrido / ping sweep.** Sondear todas las direcciones de una subred para
  encontrar los dispositivos activos.

---

Publicado bajo la licencia MIT. Para un resumen conciso, consulta el
[README](../README.md).
