# NETSCOPE — Scénarios de démonstration

Script de génération de trafic réseau pour démontrer les capacités de détection de NETSCOPE.
**Usage éducatif uniquement — réseau isolé.**

## Prérequis

```bash
pip install requests scapy
```

Scapy optionnel — fallback automatique sur `socket`/`ping` si absent.

## Lancement

```bash
python demo_scenario.py              # menu interactif
python demo_scenario.py --all        # tous les scénarios
python demo_scenario.py --scenario 1 3 6  # scénarios spécifiques
python demo_scenario.py --all --delay 10  # 10s entre chaque (pour présentation)
```

Gateway auto-détectée. Override possible avec `--gateway <IP>`.

## Scénarios

| # | Nom | Technique | Ce que NETSCOPE détecte |
|---|-----|-----------|------------------------|
| 1 | **Blacklist IP (C2)** | Connexions TCP vers IPs Cobalt Strike | Anomalie IP blacklistée (score 85+) |
| 2 | **Domaines phishing/malware** | Requêtes DNS vers paypa1.com, flash-player-update.com... | Anomalie domaine blacklisté (score 80) |
| 3 | **Ports suspects** | Connexions sur ports 4444, 31337, 6666... | Détection ports inhabituels (+15 bonus) |
| 4 | **Exfiltration ICMP** | Données sensibles (mots de passe, clés API, SSN) cachées dans payload ICMP + flood de couverture | Top talker + volume anormal + payload suspect |
| 5 | **Termes suspects** | Payloads contenant reverse shells, Log4j, mimikatz... | Anomalie terme suspect (score 65) |
| 6 | **Attaque combinée** | IP blacklistée + port suspect + volume élevé | Multiplicateur 1.2x — score maximum |

## Déroulé recommandé pour la présentation

1. Ouvrir le dashboard NETSCOPE — montrer l'état "sain" (score ~100)
2. Lancer scénario **1** (C2) → score chute, alertes rouges
3. Lancer scénario **2** (phishing) → nouvelles anomalies domaines
4. Lancer scénario **4** (exfiltration ICMP) → top talker + données sensibles dans le trafic
5. Lancer scénario **6** (combiné) → score critique
6. Montrer les résultats d'analyse et l'export CSV/JSON
