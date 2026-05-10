# NETSCOPE — Architecture Technique

**Terminal de surveillance réseau pour Raspberry Pi**

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Structure du projet](#2-structure-du-projet)
3. [Flux de données](#3-flux-de-données)
4. [Modules core](#4-modules-core)
5. [Services](#5-services)
6. [Modèles de données](#6-modèles-de-données)
7. [Blueprints Flask](#7-blueprints-flask)
8. [Patterns de conception](#8-patterns-de-conception)
9. [Configuration et démarrage](#9-configuration-et-démarrage)
10. [Stack technique](#10-stack-technique)
11. [Tests](#11-tests)
12. [Déploiement](#12-déploiement)

---

## 1. Vue d'ensemble

NETSCOPE est une application Flask mono-processus, multi-threads, conçue pour fonctionner sur Raspberry Pi (Zero à Pi 5). L'architecture suit un modèle en couches :

```
┌─────────────────────────────────────────────────────────┐
│                    Interface Web (Flask)                 │
│            Dashboard │ Admin │ API │ Captive             │
├─────────────────────────────────────────────────────────┤
│                    Services (Singletons)                 │
│  Version │ Export │ Update │ Hardware │ Thread │ Resource │
├─────────────────────────────────────────────────────────┤
│                    Core (Traitement)                     │
│    Capture │ Analyse │ Détection │ Inspection            │
├─────────────────────────────────────────────────────────┤
│                    Modèles de données                    │
│   Capture │ Anomaly │ Blacklist │ Whitelist │ Score      │
├─────────────────────────────────────────────────────────┤
│                    Système / Hardware                    │
│         tcpdump │ Scapy │ iptables │ Raspberry Pi        │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Structure du projet

```
netscope/
├── app/
│   ├── __init__.py              # App factory (create_app)
│   ├── config.py                # Configuration Flask
│   ├── core/                    # Modules de traitement
│   │   ├── capture/             # Capture réseau
│   │   ├── analysis/            # Analyse et scoring
│   │   ├── detection/           # Détection d'anomalies
│   │   └── inspection/          # Inspection approfondie
│   ├── services/                # Services transversaux
│   ├── models/                  # Modèles de données
│   ├── blueprints/              # Routes Flask
│   │   ├── dashboard/           # Interface principale
│   │   ├── api/                 # API REST
│   │   ├── admin/               # Administration
│   │   └── captive/             # Portail captif
│   └── static/                  # Assets (CSS, JS, images, vidéo)
├── data/
│   └── config/
│       └── netscope.yaml        # Configuration principale
├── tests/
│   ├── unit/                    # Tests unitaires
│   ├── integration/             # Tests d'intégration
│   ├── e2e/                     # Tests end-to-end
│   └── conftest.py              # Fixtures pytest
├── VERSION                      # Source unique de la version
├── requirements.txt             # Dépendances production
├── requirements-dev.txt         # Dépendances développement
├── pytest.ini                   # Configuration pytest
└── run.py                       # Point d'entrée
```

---

## 3. Flux de données

### Pipeline de capture et analyse

```
tcpdump (capture brute)
    │
    ▼
PacketParser (extraction headers)
    │
    ▼
FourEssentials (analyse protocoles : IP, TCP/UDP, DNS, HTTP)
    │
    ▼
BlacklistDetector (correspondance IP/domaine/terme)
    │
    ▼
Scoring (calcul score de risque multi-critères)
    │
    ▼
AnomalyStore (stockage en mémoire)
    │
    ▼
HealthScore (agrégation → score de santé réseau)
    │
    ▼
Dashboard (affichage web)
```

### Pipeline d'inspection approfondie

```
Utilisateur clique "Inspecter"
    │
    ▼
JobQueue (file séquentielle, thread-safe)
    │
    ▼
ScapyInspector (dissection couches réseau)
    │
    ▼
HumanContext (enrichissement contextuel)
    │
    ▼
PacketViewer (visionneuse web)
```

### Pipeline de mise à jour OTA

```
Vérification version (GitHub API)
    │
    ▼
Backup version actuelle (.backup)
    │
    ▼
Téléchargement release (tar.gz)
    │
    ▼
Extraction + swap atomique (rename)
    │
    ▼
Health check (/api/health, timeout 30s)
    │
    ├── Succès → mise à jour terminée
    └── Échec → rollback automatique depuis backup
```

---

## 4. Modules core

### Capture (`app/core/capture/`)

| Fichier | Rôle |
|---------|------|
| `tcpdump_manager.py` | Gestion du processus tcpdump, collecte des paquets bruts |
| `packet_parser.py` | Parsing des paquets en structures de données |
| `packet_dissector.py` | Dissection protocole via Scapy (couches 2/3/4) |
| `interface_detector.py` | Détection automatique de l'interface réseau et du routage |
| `bpf_filters.py` | Génération de filtres BPF pour tcpdump |

### Analyse (`app/core/analysis/`)

| Fichier | Rôle |
|---------|------|
| `four_essentials.py` | Extraction des 4 analyses essentielles (IP, TCP/UDP, DNS, HTTP) |
| `scoring.py` | Algorithme de scoring cascade multi-critères |
| `health_score.py` | Calcul du score de santé réseau (0-100, bandes vert/jaune/rouge) |

### Détection (`app/core/detection/`)

| Fichier | Rôle |
|---------|------|
| `blacklist_detector.py` | Matching paquets contre blacklists (3 types : IP, domaine, terme) |
| `blacklist_manager.py` | Singleton avec hot-reload via watchdog |
| `anomaly_store.py` | Stockage en mémoire des événements d'anomalie |
| `human_context.py` | Enrichissement contextuel (raisons lisibles, criticité) |

### Inspection (`app/core/inspection/`)

| Fichier | Rôle |
|---------|------|
| `job_queue.py` | File d'attente thread-safe, exécution séquentielle |
| `job_models.py` | Dataclass InspectionJob (spec, statut, progression) |
| `scapy_inspector.py` | Inspection Scapy avec boucle itérative (timeout 1s + stop_event) |

---

## 5. Services

Tous les services suivent le pattern **singleton** avec factory `get_*()` et reset `reset_*()` pour les tests.

| Service | Fichier | Rôle |
|---------|---------|------|
| **VersionService** | `version_service.py` | Lecture VERSION file, info système, uptime, modèle Pi |
| **ExportService** | `export_service.py` | Export CSV/JSON avec filtrage anomalies |
| **UpdateService** | `update_service.py` | Vérification GitHub, download, backup, rollback, health check |
| **HardwareDetection** | `hardware_detection.py` | Détection modèle Pi (enum PiModel), specs matériel |
| **PerformanceConfig** | `performance_config.py` | Cibles de performance adaptées au hardware |
| **ThreadManager** | `thread_manager.py` | Gestion du cycle de vie des threads daemon |
| **ResourceMonitor** | `resource_monitor.py` | Sampling CPU/RAM avec seuils configurables |
| **GracefulDegradation** | `graceful_degradation.py` | Transitions NORMAL → DEGRADED → CRITICAL |
| **WhitelistManager** | `whitelist_manager.py` | Whitelist persistante IP/domaine/terme |
| **BlacklistUserManager** | `blacklist_user_manager.py` | Blacklist utilisateur JSON-persistante |
| **HealthScoreHistory** | `health_score_history.py` | Historique time-series du score de santé |
| **CaptiveManager** | `captive_manager.py` | État portail captif, release clients, toggle système |

---

## 6. Modèles de données

| Modèle | Fichier | Champs principaux |
|--------|---------|-------------------|
| **Capture** | `capture.py` | id, interface, duration, packet_count, timestamp |
| **AnomalyEvent** | `anomaly.py` | ip_src, ip_dst, ports, protocol, score, reason, type |
| **BlacklistEntry** | `blacklist.py` | value, type (IP/DOMAIN/TERM), source |
| **WhitelistEntry** | `whitelist.py` | value, type (IP/DOMAIN/TERM), added_at |
| **HealthScore** | `health_score.py` | score (0-100), band (GREEN/YELLOW/RED), components |
| **RiskScore** | `scoring.py` | total, factors, blacklist_match |
| **SystemInfo** | `version_service.py` | version, install_date, pi_model, uptime |

---

## 7. Blueprints Flask

### Dashboard (`/`)

Interface principale. Routes HTML :

| Route | Template | Fonction |
|-------|----------|----------|
| `/` | `dashboard.html` | Score de santé, cartes de statut |
| `/anomalies` | `anomalies.html` | Liste filtrable des anomalies |
| `/whitelist` | `whitelist.html` | CRUD whitelist |
| `/blacklist` | `blacklist.html` | CRUD blacklist + enrichissement |
| `/packets` | `packets.html` | Visionneuse de paquets |
| `/jobs` | `jobs.html` | File de jobs d'inspection |

### API (`/api`)

Endpoints JSON :

| Méthode | Route | Réponse |
|---------|-------|---------|
| GET | `/api/health` | `{status, version}` |
| GET | `/api/hardware` | `{model, specs, targets}` |

### Admin (`/admin`)

Administration :

| Route | Fonction |
|-------|----------|
| `/admin/` | Informations système |
| `/admin/update` | Gestion mises à jour OTA |
| `/admin/config` | Configuration |

### Captive (`/captive`)

Portail captif :

| Composant | Fonction |
|-----------|----------|
| `@before_app_request` | Interception globale des requêtes clients non libérés |
| `/captive/portal` | Page d'accueil portail captif |

---

## 8. Patterns de conception

### Singleton avec factory

```python
_instance: Optional['ServiceName'] = None

def get_service_name() -> ServiceName:
    global _instance
    if _instance is None:
        _instance = ServiceName()
    return _instance

def reset_service_name() -> None:
    global _instance
    _instance = None
```

Utilisé par : tous les services, BlacklistManager, JobQueue, CaptiveManager.

### Thread management

- `ThreadManager` gère le cycle de vie des threads daemon
- `ResourceMonitor` sample CPU/RAM en arrière-plan
- `threading.Event` pour signaler l'arrêt aux threads
- Opérations d'annulation atomiques (tout dans le lock)

### Dégradation gracieuse

```
NORMAL ──(seuil CPU/RAM dépassé)──► DEGRADED ──(critique)──► CRITICAL
   ▲                                                              │
   └──────────(ressources libérées, recovery automatique)─────────┘
```

- En mode DEGRADED : avertissement, jobs ralentis
- En mode CRITICAL : jobs suspendus, reprise automatique

### Hot-reload

- `watchdog` surveille `netscope.yaml`
- `BlacklistManager` recharge les listes automatiquement sur modification fichier
- Pas de redémarrage nécessaire

### Context Processors

Variables injectées dans tous les templates Jinja :
- `hardware_info` : modèle Pi, specs
- `blacklist_stats` : nombre d'entrées par type
- `version` : version courante depuis VERSION file

---

## 9. Configuration et démarrage

### App Factory (`create_app`)

Séquence d'initialisation :

1. Charger la configuration Flask (Dev/Test/Prod)
2. Configurer le logging (`NetScopeFormatter`)
3. Détecter le hardware (Raspberry Pi model)
4. Détecter l'interface réseau
5. Charger les blacklists depuis `netscope.yaml`
6. Initialiser le hot-reload watchdog
7. Initialiser `GracefulDegradationManager` + `ResourceMonitor`
8. Enregistrer les 4 blueprints
9. Enregistrer les context processors
10. Enregistrer les error handlers

### Configuration principale (`data/config/netscope.yaml`)

```yaml
network:
  interface: auto          # ou eth0, wlan0
  capture_duration: 30     # secondes
  snap_length: 1500        # bytes (MTU Ethernet)

detection:
  blacklists:
    ip: [...]
    domains: [...]
    terms: [...]

application:
  name: NETSCOPE
  debug: false
```

### Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `FLASK_ENV` | `production` | Environnement Flask |
| `SECRET_KEY` | `dev-secret-key` | Clé secrète Flask |

---

## 10. Stack technique

### Production

| Composant | Technologie | Version |
|-----------|------------|---------|
| Runtime | Python | 3.11+ |
| Framework web | Flask | >= 3.0.0 |
| WSGI | Gunicorn | >= 21.0.0 |
| Capture réseau | tcpdump | Système |
| Inspection paquets | Scapy | >= 2.5.0 |
| Monitoring système | psutil | >= 5.9.0 |
| Hot-reload config | watchdog | >= 4.0.0 |
| HTTP client | requests | >= 2.31.0 |
| Config | PyYAML | >= 6.0.0 |
| HTML parsing | beautifulsoup4 | >= 4.12.0 |

### Développement

| Outil | Usage |
|-------|-------|
| pytest | Tests (unit, integration, e2e) |
| ruff | Linting et formatage |
| pytest-flask | Fixtures Flask |

### Frontend

| Technologie | Usage |
|-------------|-------|
| HTML/CSS/JS | Vanilla (pas de framework) |
| Thème sombre | CSS custom avec glassmorphism |
| Fond vidéo | MP4 720p avec overlays CSS |
| Responsive | `meta viewport` + media queries |

---

## 11. Tests

### Organisation

```
tests/
├── conftest.py              # Fixtures globales, reset singletons
├── unit/                    # Tests isolés par composant
├── integration/             # Tests inter-composants
└── e2e/                     # Tests flux complets
```

### Fixtures clés (`conftest.py`)

- `app` : crée l'application Flask en mode test, reset tous les singletons après chaque test
- `client` : client HTTP Flask pour les tests de routes
- Fonctions `reset_*()` pour chaque singleton

### Couverture

- ~2000 tests au total (Epics 1-5)
- Pattern systématique : Unit + Integration + E2E par story
- 0 régression connue

---

## 12. Déploiement

### Architecture de déploiement

```
┌─────────────────────────┐
│     Raspberry Pi        │
│                         │
│  ┌───────────────────┐  │
│  │  Gunicorn (WSGI)  │  │
│  │    ├── Worker 1   │  │
│  │    └── Worker N   │  │
│  ├───────────────────┤  │
│  │   Flask App       │  │
│  │   (NETSCOPE)      │  │
│  ├───────────────────┤  │
│  │   tcpdump         │  │
│  │   (capture)       │  │
│  ├───────────────────┤  │
│  │   iptables/DNS    │  │
│  │   (captive portal)│  │
│  └───────────────────┘  │
│                         │
│  /opt/netscope/         │
│  /opt/netscope.backup/  │
└─────────────────────────┘
```

### Fichiers système

| Chemin | Rôle |
|--------|------|
| `/opt/netscope/` | Installation de l'application |
| `/opt/netscope.backup/` | Backup pour rollback OTA |
| `/usr/local/sbin/netscope-captive-toggle.sh` | Script toggle portail captif |
| `VERSION` | Source unique de la version |

### Mise à jour OTA

Le système OTA utilise un swap atomique (`os.rename`) pour garantir la cohérence de l'installation. En cas d'échec du health check post-redémarrage, le rollback restaure automatiquement la version précédente depuis le backup.

---

*NETSCOPE — Architecture documentée le 2026-05-10*
*Version : 0.1.0*
