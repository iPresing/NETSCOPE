#!/usr/bin/env python3
"""
NETSCOPE Discover — Trouve la sonde NETSCOPE sur le réseau local.

Écoute les broadcasts UDP envoyés par le beacon de la sonde
et affiche ses informations dès qu'elle est détectée.

Usage:
    python3 discover_probe.py              # Attend 30s par défaut
    python3 discover_probe.py --timeout 60 # Attend 60s
    python3 discover_probe.py --loop       # Écoute en continu
"""

import argparse
import json
import socket
import sys
import time

BEACON_PORT = 5742
BEACON_MAGIC = "NETSCOPE_PROBE"

# Couleurs ANSI
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
NC = "\033[0m"
BOLD = "\033[1m"


def format_uptime(seconds):
    """Formate l'uptime en format lisible."""
    if seconds < 0:
        return "inconnu"
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}j")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def listen(timeout=30, loop=False):
    """Écoute les beacons NETSCOPE sur le réseau."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # SO_REUSEPORT n'existe pas sur Windows
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass

    sock.bind(("", BEACON_PORT))
    sock.settimeout(1.0)

    seen = {}
    deadline = None if loop else time.monotonic() + timeout

    mode = "continu" if loop else f"timeout {timeout}s"
    print(f"\n{CYAN}{'=' * 58}{NC}")
    print(f"{CYAN}  NETSCOPE Probe Discovery — {mode}{NC}")
    print(f"{CYAN}  Écoute sur le port UDP {BEACON_PORT}…{NC}")
    print(f"{CYAN}{'=' * 58}{NC}\n")

    try:
        while True:
            if deadline and time.monotonic() > deadline:
                break

            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue

            try:
                payload = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            if payload.get("magic") != BEACON_MAGIC:
                continue

            probe_ip = payload.get("ip", addr[0])
            now = time.strftime("%H:%M:%S")

            if probe_ip not in seen:
                # Nouvelle sonde détectée
                seen[probe_ip] = payload
                print(f"  {GREEN}{BOLD}Sonde NETSCOPE trouvée !{NC}")
                print(f"  ┌─────────────────────────────────────────")
                print(f"  │ IP        : {BOLD}{probe_ip}{NC}")
                print(f"  │ Hostname  : {payload.get('hostname', '?')}")
                print(f"  │ Version   : {payload.get('version', '?')}")
                print(f"  │ Uptime    : {format_uptime(payload.get('uptime', -1))}")
                print(f"  │ Port web  : {payload.get('port_web', 80)}")
                print(f"  │ Heure     : {now}")
                print(f"  │ Interface : http://{probe_ip}:{payload.get('port_web', 80)}")
                print(f"  └─────────────────────────────────────────\n")

                if not loop:
                    # En mode timeout, on s'arrête dès qu'on a trouvé une sonde
                    break
            else:
                # Sonde déjà vue — mise à jour silencieuse
                seen[probe_ip] = payload

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    if not seen:
        print(f"  {YELLOW}Aucune sonde NETSCOPE détectée.{NC}")
        print(f"  Vérifiez que :")
        print(f"    - La sonde est allumée et connectée au même réseau")
        print(f"    - Le service netscope-beacon est actif sur la sonde")
        print(f"    - Aucun firewall ne bloque le port UDP {BEACON_PORT}\n")
        return 1

    print(f"\n  {GREEN}Sonde(s) détectée(s) : {len(seen)}{NC}\n")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Découvre les sondes NETSCOPE sur le réseau local",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=30,
        help="Durée max d'écoute en secondes (défaut: 30)",
    )
    parser.add_argument(
        "--loop", "-l",
        action="store_true",
        help="Écoute en continu (Ctrl+C pour arrêter)",
    )
    args = parser.parse_args()
    sys.exit(listen(timeout=args.timeout, loop=args.loop))


if __name__ == "__main__":
    main()
