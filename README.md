```markdown
# 🛡️ DroidNet Sentinel

> Autonomous network auditor built for Android/Termux using Nmap, Python and Flask.

DroidNet Sentinel is a modular network security toolkit designed to run
natively on Android via Termux. Escanea tu red WiFi automáticamente,
detecta dispositivos desconocidos, analiza puertos y servicios, busca
exploits públicos y envía alertas en tiempo real vía Telegram.

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized network
auditing only**. Only use it on networks you own or have explicit
permission to test. Unauthorized network scanning is illegal in most
jurisdictions. The author is not responsible for misuse.

---

## 📦 Modules

| Módulo | Archivo | Función |
|---|---|---|
| Scanner | `sentinel.py` | Escaneo automático de red + alertas |
| Hunter | `hunter.py` | Búsqueda de exploits via Exploit-DB |
| Dashboard | `dashboard.py` | Interfaz web con historial de reportes |
| Spoofer | `spoofer.py` | Corte de red via ARP Spoofing |

---

## 📱 Requisitos

### Android (Termux)

**Hardware:** Android con root · Termux instalado (F-Droid, no Play Store)

```bash
# Paquetes Termux
pkg update && pkg upgrade
pkg install python nmap dsniff termux-api

# Dependencias Python
pip install -r requirements.txt
```

### 🖥️ Linux PC (Ubuntu/Debian/Kali)

```bash
# Herramientas de red
sudo apt install nmap dsniff libnotify-bin wireless-tools

# (Opcional) Para búsqueda de exploits
sudo apt install exploitdb

# Dependencias Python
pip install -r requirements.txt
```

> **Nota:** El toolkit detecta automáticamente la plataforma y usa
> las herramientas nativas de cada una (nmcli en PC, termux-api en Android).

---

## ⚙️ Configuración

Crea el archivo `config.json` en la raíz del proyecto:

```json
{
    "excluded_ips": ["192.168.1.100"],
    "trusted_ips":  ["192.168.1.1", "192.168.1.100"]
}
```

| Campo | Descripción |
|---|---|
| `excluded_ips` | IPs que Nmap no escaneará (tu propio dispositivo) |
| `trusted_ips` | IPs conocidas — el resto se considera intruso |

### Telegram (opcional)
Edita en `sentinel.py`:
```python
TELEGRAM_TOKEN   = "TU_TOKEN_DE_BOTFATHER"
TELEGRAM_CHAT_ID = "TU_CHAT_ID"
```

---

## 🚀 Uso

### Escaneo manual
```bash
python sentinel.py
```

### Modo daemon (background)
```bash
python sentinel.py --daemon
```

### Buscar exploits sobre el último escaneo
```bash
python hunter.py
```

### Levantar dashboard web
```bash
python dashboard.py
# Abre en el navegador: http://127.0.0.1:5000
```

### Corte ARP de un dispositivo
```bash
python spoofer.py <IP_VICTIMA> <IP_GATEWAY> <INTERFAZ>
# Ejemplo:
python spoofer.py 192.168.1.105 192.168.1.1 wlan0
```

---

## 🔄 Flujo de trabajo

```
WiFi conectada
     │
     ▼
Sentinel escanea la red (nmap -sn)
     │
     ▼
Deep scan de hosts activos (-F -sV)
     │
     ├── IP conocida → solo reportar
     │
     └── IP desconocida → Spoofer corta ARP
                      → Telegram alert
                      → Reporte JSON guardado
                      │
                      ▼
                   Hunter busca exploits
                   en Exploit-DB
                      │
                      ▼
                   Dashboard muestra
                   historial completo
```

---

## 📁 Estructura del proyecto

```
DroidNet-Sentinel/
├── main.py            # CLI interactivo (punto de entrada)
├── sentinel.py        # Módulo principal de escaneo
├── hunter.py          # Módulo de exploits (Exploit-DB)
├── dashboard.py       # Servidor Flask (Command Center)
├── spoofer.py         # Módulo ARP Spoofing
├── deauther.py        # Módulo Deauth 802.11
├── platform_utils.py  # Abstracción cross-platform (PC/Android)
├── core_env.py        # Detección de capacidades del sistema
├── config.json        # Tu configuración (no se sube)
├── requirements.txt
├── .gitignore
├── README.md
└── reports/           # Reportes JSON generados
    └── Red_SSID_timestamp.json
```

---

## 📊 Dashboard

El dashboard web muestra el historial completo de auditorías con
código de colores por nivel de riesgo:

- 🟢 **Mínimo** — sin puertos abiertos
- 🟡 **Medio** — servicios HTTP/DNS expuestos  
- 🔴 **Crítico** — FTP, Telnet, SMB, RDP detectados

Accesible desde cualquier dispositivo en la red local en
`http://<IP_DEL_CELU>:5000`

---

Desarrollado con ❤️ por Ale
