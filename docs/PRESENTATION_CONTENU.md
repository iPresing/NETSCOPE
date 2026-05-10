# NETSCOPE — Contenu enrichi pour la présentation YDAYS

**Date de soutenance :** Mercredi 14 mai 2026
**Destinataires :** Équipe NETSCOPE pour intégration dans le .odp

---

## SLIDE À AJOUTER : Commits dans le temps

### Données brutes

| Mois | Commits | Epic(s) | Événement clé |
|------|---------|---------|---------------|
| Janvier 2026 | 27 | Epic 1 + Epic 2 | Fondation + Détection |
| Février 2026 | 16 | Epic 3 + Epic 4 (début) | Santé réseau + Inspection |
| Mars 2026 | 25 | Epic 4 + Epic 4b (début) | Visionneuse paquets + Stabilisation |
| Avril 2026 | 14 | Epic 4b + Epic 5 (début) | Blacklists + Export |
| Mai 2026 | 10 | Epic 5 (fin) | OTA + Admin + Rétro finale |

**Total : 92 commits, dont 59 liés directement aux stories**

### Graphique suggéré (barres)

```
Jan  ████████████████████████████  27
Fév  ████████████████              16
Mar  █████████████████████████     25
Avr  ██████████████                14
Mai  ██████████                    10
```

**Note :** Le pic de mars s'explique par le pivot architectural (re-parsing pcap au lieu de re-capture Scapy) + la refonte visuelle cinématique + le début de l'Epic 4b de stabilisation.

---

## SLIDE À AJOUTER : Tests dans le temps

### Données brutes

| Jalon | Tests cumulés | Delta | Couverture |
|-------|--------------|-------|------------|
| Fin Epic 1 (15 jan) | ~150 | +150 | Fondation Flask, capture, hardware |
| Fin Epic 2 (28 jan) | ~700 | +550 | Détection, scoring, dashboard, UI |
| Fin Epic 3 (8 fév) | 933 | +233 | Santé réseau, whitelists, CRUD |
| Fin Epic 4 (22 mar) | 1268 | +335 | Inspection, jobs, packets, dégradation |
| Fin Epic 4b (13 avr) | ~1630 | +362 | Stabilisation, blacklists web, toasts |
| Fin Epic 5 (10 mai) | ~1990 | +360 | Export, OTA, admin, rollback |

### Graphique suggéré (courbe ascendante)

```
2000 ┤                                          ●
     │                                    ●╱
1500 ┤                              ●╱
     │                         ╱
1000 ┤                   ●╱
     │             ●╱
 500 ┤       ●╱
     │  ●╱
   0 ┤─────────────────────────────────────────
     Jan   Fév   Mar   Avr   Mai
```

**~2000 tests, 0 régression connue, croissance linéaire constante (~350 tests/epic)**

---

## SLIDE À AJOUTER : Failles découvertes par code review

### Statistiques globales

| Sévérité | Total découvertes | Corrigées | Taux |
|----------|------------------|-----------|------|
| CRITICAL | 2 | 2 | 100% |
| HIGH | 42+ | 40+ | 95% |
| MEDIUM | 56+ | 44+ | 79% |
| LOW | 31+ | 10+ | 32% |
| **TOTAL** | **~142** | **~96** | **68%** |

### Par epic

| Epic | Issues trouvées | Catégorie dominante |
|------|----------------|---------------------|
| Epic 2 | ~50 | XSS, validation |
| Epic 3 | ~40 | Race conditions, whitelist |
| Epic 4 | 59 | Thread safety, XSS, path traversal |
| Epic 4b | ~50 | CSS, listeners, path traversal |
| Epic 5 | 83 | Sécurité OTA, atomicité, tests faux |

### Types de failles les plus fréquentes

| Type | Occurrences | Exemple |
|------|------------|---------|
| **XSS / Échappement HTML** | ~15 | innerHTML sans escapeHtml, data-attributes |
| **Path traversal** | ~8 | Accès fichier pcap non validé, extraction tar |
| **Thread safety** | ~12 | Mutation sans lock, race conditions singleton |
| **Symlink attack** | 2 | Extraction tar avec liens symboliques |
| **URL scheme injection** | 2 | `javascript:` dans href sans validation |
| **Tests faux** (passent sans rien vérifier) | 2 | Tests CRITICAL en story 5.8 |

**Point clé pour la soutenance :** Chaque story passe par un adversarial code review qui cherche activement des failles. Ce processus a découvert 142+ vulnérabilités et en a corrigé 96+. Les issues LOW sont acceptées comme dette technique documentée.

---

## SLIDE À AJOUTER : Rétrospectives et brainstorm

### Timeline

```
7 jan     29 jan     8 fév      22 mar      10 mai
  │         │         │           │           │
  ●─────────●─────────●───────────●───────────●
  │         │         │           │           │
Setup    Rétro     Rétro       Rétro       Rétro
BMAD     Epic 2    Epic 3      Epic 4      Epic 5
```

### Résumé des échanges

**Setup BMAD (7-12 janvier 2026)**
- Brainstorm initial : définition du product brief, PRD, architecture
- Création des epics et stories via workflow BMAD
- Configuration des agents IA (PM, Architecte, Dev, QA, SM)

**Rétro Epic 2 (29 janvier)**
- Constat : détection fonctionnelle, UI responsive
- Problème : tests E2E superficiels, XSS récurrent
- Décision : renforcer les tests, ajouter checklist sécurité

**Rétro Epic 3 (8 février)**
- Constat : score de santé réseau opérationnel, CRUD whitelist complet
- Problème : race conditions singletons, exports __init__.py oubliés
- Décision : enums obligatoires, 1 test E2E sans mock par story

**Rétro Epic 4 (22 mars)**
- Constat : inspection complète livrée, pivot re-parsing pcap réussi
- **Découverte majeure** : retours terrain de l'équipe (Wi-Fi bloqué, boutons non fonctionnels, CSS bugué)
- Décision : **création d'un Epic 4b de stabilisation** (10 stories) avant Epic 5
- Principe adopté : *stabilité > features*

**Rétro Epic 5 (10 mai)**
- Constat : 9/9 stories livrées, OTA complet, exports CSV/JSON
- Enseignement : proportionner la sécurité au modèle de menace (Pi jetable ≠ serveur bancaire)
- Enseignement : la code review EST le filet de sécurité (100% CRITICAL corrigés)
- Décision : centraliser la version, documenter pour la soutenance

---

## SLIDE À AJOUTER : Framework BMAD — Méthodologie

### Qu'est-ce que BMAD ?

**BMAD** (BMad Methodology for AI-assisted Development) est un framework de gestion de projet qui orchestre des agents IA spécialisés pour couvrir l'ensemble du cycle de développement logiciel.

### Agents IA de l'équipe NETSCOPE

| Agent | Rôle | Persona | Responsabilité |
|-------|------|---------|----------------|
| **John** (PM) | Product Manager | Pose les bonnes questions | PRD, requirements, vision produit |
| **Winston** (Architect) | Architecte | Pragmatique, "boring technology" | Architecture, stack, décisions techniques |
| **Bob** (SM) | Scrum Master | Checklist-driven, zéro ambiguïté | Stories, sprint planning, rétrospectives |
| **Amelia** (Dev) | Développeur | Ultra-succincte, cite les ACs | Implémentation, tests red-green-refactor |
| **Murat** (TEA) | Test Architect | Risk-based, data-driven | Stratégie de test, couverture, CI |
| **Mary** (Analyst) | Business Analyst | Enthousiaste, cherche les patterns | Analyse des besoins, études de marché |
| **Sally** (UX Designer) | UX Designer | Empathique, user-first | Interface, parcours utilisateur |

### Comment BMAD s'intègre avec l'équipe Ynov

```
┌──────────────────────────────────────────────────┐
│              ÉQUIPE YNOV (8 personnes)            │
│                                                    │
│  Timothée (Tech Lead)  ──── Interface BMAD ───┐   │
│  Thomas, Lucas, Anas   ──── Tests terrain     │   │
│  Louis, Hugo           ──── Hardware/Setup    │   │
│  Florian, Corentin     ──── Déploiement/Doc   │   │
│                                                │   │
│                           ┌────────────────────┘   │
│                           ▼                        │
│              ┌─────────────────────┐               │
│              │   AGENTS BMAD (IA)  │               │
│              │  John, Winston, Bob │               │
│              │  Amelia, Murat, ...│               │
│              └─────────────────────┘               │
│                           │                        │
│                           ▼                        │
│              Workflows automatisés :               │
│              create-prd → architecture →            │
│              epics → stories → dev → review →      │
│              retro → sprint planning               │
└──────────────────────────────────────────────────┘
```

### Workflow type d'une story

1. **SM (Bob)** crée la story avec ACs précis
2. **Dev (Amelia)** implémente en red-green-refactor
3. **Code Review** adversariale (3-10 issues minimum)
4. **Corrections** appliquées
5. Story marquée **done** dans sprint-status

### Résultats concrets de BMAD sur NETSCOPE

| Métrique | Valeur |
|----------|--------|
| Epics livrés | 6 (1, 2, 3, 4, 4b, 5) |
| Stories livrées | 43 stories |
| Tests | ~2000 |
| Code reviews | 43 (adversariales) |
| Failles corrigées | ~96 |
| Rétrospectives | 5 formelles |
| Règles de code consolidées | 28 |
| Durée totale | ~4 mois (jan → mai 2026) |

---

## SLIDE À AJOUTER : Schéma fonctionnel NETSCOPE

### Diagramme de flux principal

```
┌─────────────────────────────────────────────────────────────┐
│                    RASPBERRY PI ZERO 2 W                     │
│                                                               │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐ │
│  │ tcpdump  │───►│ Parser   │───►│Détection │───►│Scoring │ │
│  │ (capture)│    │(headers) │    │(blacklist)│    │(0-100) │ │
│  └──────────┘    └──────────┘    └──────────┘    └───┬────┘ │
│                                                       │      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐        │      │
│  │  Scapy   │───►│  Job     │───►│ Packet   │        │      │
│  │(inspect) │    │  Queue   │    │ Viewer   │        │      │
│  └──────────┘    └──────────┘    └──────────┘        │      │
│                                                       │      │
│  ┌──────────────────────────────────────────────┐    │      │
│  │              Flask Web Server                 │    │      │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │    │      │
│  │  │Dashboard │ │Anomalies │ │  Admin/OTA   │  │◄───┘      │
│  │  │(score)   │ │(liste)   │ │  (update)    │  │           │
│  │  └──────────┘ └──────────┘ └──────────────┘  │           │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │           │
│  │  │Blacklist │ │Whitelist │ │Export CSV/JSON│  │           │
│  │  │(CRUD)    │ │(CRUD)    │ │(télécharge)  │  │           │
│  │  └──────────┘ └──────────┘ └──────────────┘  │           │
│  └──────────────────────────────────────────────┘           │
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  Infrastructure système                                   │ │
│  │  iptables + dnsmasq (captive portal) │ Gunicorn (WSGI)   │ │
│  │  ResourceMonitor (CPU/RAM)           │ GracefulDegradation│ │
│  └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                          │
                     Port 80
                          │
                    ┌─────▼─────┐
                    │ Navigateur │
                    │  (client)  │
                    └───────────┘
```

---

## SLIDE À ENRICHIR : Stack technologique avec justifications

| Composant | Technologie | Justification |
|-----------|------------|---------------|
| **Runtime** | Python 3.11+ | Écosystème réseau riche (Scapy, tcpdump), prototypage rapide, lisible |
| **Framework web** | Flask 3.x | Léger, adapté aux ressources contraintes du Pi Zero, flexible |
| **Serveur prod** | Gunicorn | Standard WSGI Python, multi-thread gthread pour le captive portal |
| **Capture réseau** | tcpdump | Très léger, headers-only, impact CPU minimal sur Pi Zero |
| **Inspection paquets** | Scapy | Dissection multicouche, scripting Python natif, standard industrie |
| **Monitoring** | psutil | Lecture CPU/RAM cross-platform, essentiel pour dégradation gracieuse |
| **Hot-reload** | watchdog | Rechargement blacklists sans redémarrage, expérience utilisateur fluide |
| **HTTP client** | requests | Simplicité pour API GitHub (vérification updates OTA) |
| **Config** | PyYAML | Format lisible humain, standard pour la configuration |
| **Frontend** | Vanilla JS/CSS | Zéro dépendance NPM, réduit la surface d'attaque, rapide sur Pi |
| **Tests** | pytest | Standard Python, fixtures puissantes, paramétrisation |
| **Linting** | ruff | Extrêmement rapide, remplace flake8+isort+black |

**Philosophie** : *boring technology* — choisir des outils éprouvés, stables, avec de la documentation. Pas de frameworks JavaScript modernes, pas d'ORM, pas de base de données relationnelle. Tout en mémoire + fichiers JSON/YAML pour la persistance.

---

## SLIDE : Image du produit final physique

*[À ajouter par l'équipe — photo du Raspberry Pi Zero 2 W avec boîtier, câble Ethernet/USB, et éventuellement l'écran du dashboard]*

---

## SLIDE À ENRICHIR : Axes d'amélioration

### Court terme (réalisable)

| Axe | Description | Bénéfice |
|-----|-------------|----------|
| **Flash rapide** | Développer un outil de flashage basé sur Pi Imager pour déploiement en un clic | Installation <2 min au lieu de ~5 min |
| **Vérification d'intégrité** | Hash SHA-256 des fichiers critiques au boot, alerte si modification détectée | Détection de compromission système |
| **Documentation développeur** | Générer la doc automatiquement depuis les docstrings Python via Sphinx | Onboarding développeur facilité |
| **Dissipateur thermique** | Ajouter un dissipateur passif sur le SoC du Pi Zero 2 W | Stabilité en capture longue durée |

### Moyen terme (évolution)

| Axe | Description | Bénéfice |
|-----|-------------|----------|
| **Inspection payload** | Affiner la logique de matching des termes dans les charges utiles (regex avancés, patterns signatures) | Réduction des faux positifs |
| **Efficacité des tests** | Audit et nettoyage des ~2000 tests, suppression des tests redondants | Build plus rapide, maintenance réduite |
| **Scalabilité** | Mode sampling adaptatif sur grosses infrastructures (analyser 1 paquet sur N) | Éviter les ralentissements réseau |

### Long terme (vision)

| Axe | Description | Bénéfice |
|-----|-------------|----------|
| **Multi-sonde** | Dashboard centralisé connecté à plusieurs sondes NETSCOPE | Couverture réseau complète |
| **Machine Learning** | Détection d'anomalies par apprentissage sur le trafic normal | Adaptabilité au réseau spécifique |
| **Rapport PDF** | Génération de rapports formatés pour audits de conformité | Livrable professionnel |
| **SIEM natif** | Intégration Syslog/CEF pour envoi en temps réel vers un SIEM | Écosystème SOC |
| **Alerting** | Notifications push (email, SMS, webhook) sur détection d'anomalie critique | Réactivité temps réel |
| **Pi 5 + PoE** | Support Power-over-Ethernet pour alimentation + réseau sur un seul câble | Déploiement simplifié |

---

## DONNÉES SUPPLÉMENTAIRES UTILES

### Chiffres clés mis à jour (pour enrichir slide 6)

| Métrique | Valeur |
|----------|--------|
| Commits | 92 |
| Stories livrées | 43 |
| Tests | ~2000 |
| Failles détectées/corrigées | 142+ / 96+ |
| Règles de code | 28 |
| Rétrospectives | 5 |
| Lignes de code Python (app/) | ~8000+ |
| Fichiers JavaScript | 12 |
| Templates HTML | 13 |
| Endpoints API | 8+ |
| Coût matériel | ~60 EUR |
| Durée dev | 4 mois (jan-mai 2026) |

### Problèmes rencontrés (enrichir slide 36)

Ajouter aux problèmes existants :
- **Rollback OTA non-atomique** — découvert en code review (CRITICAL), corrigé par swap via rename
- **Tests fantômes** — tests qui passaient au vert sans vérifier les vraies transitions d'état
- **Limitation de contexte IA** — le développeur ne voit que la story en cours, pas la suivante, causant des incohérences inter-stories
- **CRLF Windows** — `git diff` muet sur certains fichiers à cause des fins de ligne
- **Version hardcodée** — 4+ occurrences de `v0.1.0` dispersées, centralisé vers fichier VERSION unique

### Timeline du projet (enrichir slide 21)

```
Jan 12 ─── Epic 1 : Fondation
Jan 16 ─── Epic 2 : Détection & Scoring
Jan 29 ─── ★ Rétro Epic 2
Jan 29 ─── Epic 3 : Santé Réseau
Fév 08 ─── ★ Rétro Epic 3
Fév 08 ─── Epic 4 : Inspection Paquets
Fév 24 ─── ⚡ Pivot : re-parsing pcap
Mar 21 ─── Refonte visuelle cinématique
Mar 22 ─── ★ Rétro Epic 4 — Découverte : retours terrain
Mar 23 ─── Epic 4b : Stabilisation
Mar 23 ─── Captive portal + bootstrap.sh
Avr 01 ─── Beacon UDP + abandon USB Gadget
Avr 13 ─── Fin Epic 4b
Avr 28 ─── Epic 5 : Export & OTA
Mai 09 ─── OTA complet livré
Mai 10 ─── ★ Rétro Epic 5 — Documentation finale
Mai 14 ─── 🎯 SOUTENANCE YDAYS
```

---

## SUGGESTIONS DE SLIDES SUPPLÉMENTAIRES

### 1. Slide "Sécurité by design"
Montrer comment le processus de code review adversariale intègre la sécurité dans le cycle de développement. Graphique : failles trouvées vs corrigées par epic.

### 2. Slide "Avant / Après"
Comparaison visuelle du dashboard entre Epic 1 (design "Douane Brutaliste") et version finale (cinématique avec glassmorphism). Montre l'évolution du design.

### 3. Slide "Dégradation gracieuse"
Schéma NORMAL → DEGRADED → CRITICAL avec les seuils CPU/RAM. Montre que NETSCOPE s'adapte automatiquement aux ressources du Pi.

### 4. Slide "OTA Update — Architecture"
Schéma du flux : Vérification GitHub → Backup → Download → Swap atomique → Health check → Rollback si échec. C'est un différenciateur technique fort.

### 5. Slide "Leçons apprises"
3-5 enseignements clés du projet :
- La stabilité avant les features (Epic 4b)
- L'IA comme multiplicateur mais pas remplacement de l'équipe
- Proportionner la sécurité au contexte (Pi jetable)
- Les tests quantitatifs ne garantissent pas la qualité
- Les retours terrain changent tout (pivot 4b)

---

*Document généré le 2026-05-10 — À intégrer dans NETSCOPE Présentation V2.odp*
