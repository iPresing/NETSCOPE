#!/usr/bin/env python3
"""
NETSCOPE Beacon — Broadcast UDP pour identification de la sonde sur le réseau.

Envoie un paquet UDP broadcast toutes les BEACON_INTERVAL secondes
sur le port BEACON_PORT, contenant les informations d'identification
de la sonde (hostname, IP, version, uptime).

Usage:
    python3 netscope_beacon.py
    # ou via systemd: netscope-beacon.service
"""

import json
import socket
import time
import logging
import signal
import sys
import os

BEACON_PORT = 5742
BEACON_INTERVAL = 10  # secondes
BEACON_MAGIC = "NETSCOPE_PROBE"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [beacon] %(levelname)s %(message)s",
)
log = logging.getLogger("netscope-beacon")

_running = True


def _handle_signal(signum, _frame):
    global _running
    log.info("Signal %s reçu, arrêt du beacon.", signum)
    _running = False


def get_probe_ip():
    """Récupère l'IP principale de la sonde (celle qui a une route par défaut)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "unknown"


def get_uptime():
    """Retourne l'uptime système en secondes."""
    try:
        with open("/proc/uptime", "r") as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError):
        return -1


def get_version():
    """Lit la version depuis netscope.yaml si disponible."""
    config_paths = [
        os.path.join(os.path.dirname(__file__), "..", "data", "config", "netscope.yaml"),
        "/opt/netscope/netscope/data/config/netscope.yaml",
    ]
    for path in config_paths:
        try:
            with open(path, "r") as f:
                for line in f:
                    if line.strip().startswith("version:"):
                        return line.split(":", 1)[1].strip().strip('"').strip("'")
        except OSError:
            continue
    return "unknown"


def build_payload():
    """Construit le payload JSON du beacon."""
    return json.dumps({
        "magic": BEACON_MAGIC,
        "hostname": socket.gethostname(),
        "ip": get_probe_ip(),
        "version": get_version(),
        "uptime": get_uptime(),
        "port_web": 80,
    }).encode("utf-8")


def main():
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(1.0)

    log.info("Beacon NETSCOPE démarré — port %d, intervalle %ds", BEACON_PORT, BEACON_INTERVAL)

    while _running:
        try:
            payload = build_payload()
            sock.sendto(payload, ("255.255.255.255", BEACON_PORT))
            log.debug("Beacon envoyé: %s", payload.decode())
        except OSError as e:
            log.warning("Erreur envoi beacon: %s", e)

        # Attente interruptible
        deadline = time.monotonic() + BEACON_INTERVAL
        while _running and time.monotonic() < deadline:
            time.sleep(0.5)

    sock.close()
    log.info("Beacon arrêté.")


if __name__ == "__main__":
    main()
