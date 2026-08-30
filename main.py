"""
DroidNet Sentinel — Entry Point

Usage (interactive menu):
    python main.py

Usage (non-interactive / scripted):
    python main.py --scan
    python main.py --daemon
    python main.py --hunt
    python main.py --dashboard
    python main.py --reports
    python main.py --spoof 192.168.1.105 192.168.1.1 [wlan0]
    python main.py --deauth A1:B2:C3:D4:E5:F6 AA:BB:CC:DD:EE:FF wlan0mon
    python main.py --deauth broadcast AA:BB:CC:DD:EE:FF wlan0mon
"""

from droidnet.cli import main

if __name__ == "__main__":
    main()
