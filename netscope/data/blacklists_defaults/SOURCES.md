# Sources des blacklists par défaut NETSCOPE

Ce document liste les sources publiques évaluées pour l'enrichissement des
blacklists par défaut livrées avec NETSCOPE. Il sert de référence à la Task 1
de la story 4b.9 et de base au script CLI `refresh_blacklists.py`.

> **Principe offline-first** : les entrées sont figées dans les fichiers `.txt`
> commitées au dépôt. Le script CLI fournit un chemin optionnel pour rafraîchir
> ces fichiers à partir de sources publiques, sur action manuelle uniquement.

## Méthodologie d'évaluation

Chaque source candidate est évaluée selon les critères suivants :

| Critère | Description |
|---------|-------------|
| **Licence** | Compatible open-source (CC0, MIT, GPL-3.0, Apache 2.0, domaine public). Les licences restrictives, no-redistribution ou usage commercial non-libre sont écartées. |
| **Fréquence** | Mise à jour régulière (quotidienne/hebdomadaire). |
| **Format** | Plain text (1 entrée par ligne) privilégié. CSV/JSON acceptés. |
| **Fiabilité** | Source communautaire reconnue, maintenance active, faible taux de faux positifs documenté. |
| **Volume** | Capacité à fournir au moins 50–200 entrées par catégorie. |
| **Accès** | HTTPS gratuit, sans clé API ou enregistrement obligatoire. |

## Tableau comparatif

| # | Source | Type | Licence | Fréquence | Volume typique | URL | Statut |
|---|--------|------|---------|-----------|---------------|-----|--------|
| 1 | **IPsum (stamparm)** | IPs malware / scanners | Public domain / Unlicense | Quotidien | 80k–120k IPs (level 3+) | https://github.com/stamparm/ipsum | ✅ **Retenue** |
| 2 | **Feodo Tracker (abuse.ch)** | IPs C2 (Emotet, Dridex, TrickBot) | CC0 | Quotidien | 200–500 IPs actives | https://feodotracker.abuse.ch/downloads/ipblocklist.txt | ✅ **Retenue** |
| 3 | **URLhaus (abuse.ch)** | Domaines/URLs malware | CC0 | Temps réel | 3k–10k URLs actives | https://urlhaus.abuse.ch/downloads/text/ | ✅ **Retenue** |
| 4 | **Hagezi DNS Blocklists** | Domaines malware / phishing | GPL-3.0 | Quotidien | 100k+ domaines (multi) | https://github.com/hagezi/dns-blocklists | ✅ **Retenue** |
| 5 | **Phishing Army (blocklist)** | Domaines phishing | CC0 | Quotidien | 40k+ domaines | https://phishing.army/download/phishing_army_blocklist.txt | ✅ **Retenue** |
| 6 | **FireHOL Level 1** | IPs/CIDRs connus malicieux | CC-BY-SA-4.0 | Quotidien | 10k+ entrées | https://iplists.firehol.org/files/firehol_level1.netset | ✅ **Retenue** (IPs seulement, pas de CIDR pour NETSCOPE) |
| 7 | **OpenPhish Community** | URLs phishing (conversion domaines) | Gratuit non-commercial | Horaire | 500–2000 URLs | https://openphish.com/feed.txt | ⚠️ **Écartée** — restriction non-commerciale |
| 8 | **Project Honeypot** | IPs spammers | Propriétaire | - | - | https://www.projecthoneypot.org | ❌ **Écartée** — licence restrictive |
| 9 | **Elastic Security Detection Rules** | Termes / patterns suspects | Elastic License 2.0 | - | - | https://github.com/elastic/detection-rules | ⚠️ **Référence** — pas d'import automatisé (code YAML), termes extraits manuellement |
| 10 | **MITRE ATT&CK** | TTPs / commandes | Apache 2.0 | Trimestriel | - | https://attack.mitre.org | ⚠️ **Référence** — termes extraits manuellement depuis les procédures documentées |
| 11 | **LOLBAS** | Binaires Windows détournés | MIT | Continu | ~200 binaires | https://lolbas-project.github.io | ✅ **Retenue** — extraction termes manuelle |

## Sources retenues par catégorie (≥ 2 par catégorie)

### IPs malware (fichier `ips_malware.txt`)

1. **IPsum** (stamparm) — Public domain — agrégateur de scanners et IPs malveillantes
2. **FireHOL Level 1** — CC-BY-SA-4.0 — IPs à haut risque (extraction IPs simples uniquement, pas de plages CIDR)

### IPs C2 (fichier `ips_c2.txt`)

1. **Feodo Tracker** (abuse.ch) — CC0 — C2 Emotet/Dridex/TrickBot/QakBot
2. **IPsum** (stamparm) — Public domain — sous-ensemble classé C2

### Domaines malware (fichier `domains_malware.txt`)

1. **Hagezi DNS Blocklists** — GPL-3.0 — fichiers `wildcard/malware.txt` et `wildcard/threat-intelligence-feeds.txt`
2. **URLhaus** (abuse.ch) — CC0 — domaines extraits des URLs malware actives

### Domaines phishing (fichier `domains_phishing.txt`)

1. **Phishing Army** — CC0 — liste consolidée des domaines phishing actifs
2. **Hagezi DNS Blocklists** — GPL-3.0 — fichier `wildcard/phishing.txt`

### Termes suspects (fichier `terms_suspect.txt`)

1. **MITRE ATT&CK** — Apache 2.0 — termes issus des procédures documentées (reverse shells, LOLBAS, encodage)
2. **LOLBAS project** — MIT — nom des binaires Windows couramment détournés pour execution/download

## Compatibilité des licences

| Licence | Compatibilité projet NETSCOPE | Notes |
|---------|------------------------------|-------|
| Public Domain / CC0 / Unlicense | ✅ Totale | Aucune obligation |
| MIT / BSD / Apache 2.0 | ✅ Totale | Attribution simple |
| GPL-3.0 | ✅ Compatible (NETSCOPE distribué sous licence compatible open source) | Conserver notice dans SOURCES.md et README.md |
| CC-BY-SA-4.0 | ✅ Compatible | Attribution + share-alike du fichier dérivé |
| Elastic License 2.0 | ⚠️ Non-free selon FSF | Pas d'import automatisé, extraction manuelle de termes génériques acceptable |
| Propriétaire / no-redistribution | ❌ Écartée | - |

**Conformité** : Toutes les sources embarquées dans le dépôt NETSCOPE ont une
licence permettant la redistribution et l'usage en projet open-source. Les
sources "Référence" (Elastic, MITRE) ne sont pas redistribuées — seuls des
termes génériques extraits manuellement y figurent, ce qui ne constitue pas
une œuvre dérivée.

## Notes de sélection

- **FireHOL Level 1** contient des plages CIDR (`x.x.x.x/24`). La fonction
  `validate_value(IP)` de NETSCOPE accepte uniquement des IPs unitaires. Le
  script CLI extrait donc la première IP de chaque plage `/32` et ignore les
  plages plus larges pour éviter les faux positifs.
- **Hagezi** est une source massive (>100k domaines). Le script CLI limite
  l'extraction à un échantillon représentatif (1000 premiers après
  dédoublonnage) pour maintenir la taille du dépôt < 1 MB par fichier.
- **URLhaus** fournit des URLs complètes. Le script CLI extrait uniquement la
  composante `host` (domaine) après parsing.
- Les sources "Référence" (MITRE, LOLBAS) ne sont **pas** consommées par le
  script CLI — les entrées correspondantes sont figées manuellement dans
  `terms_suspect.txt`.

## Rafraîchissement manuel

Pour mettre à jour les fichiers `.txt` à partir des sources actives, exécuter
depuis la racine du projet :

```bash
python -m app.tools.refresh_blacklists           # Toutes les sources
python -m app.tools.refresh_blacklists --dry-run # Aperçu sans écriture
python -m app.tools.refresh_blacklists --source ipsum
```

Voir `data/blacklists_defaults/README.md` pour plus de détails sur le format
et la procédure.

## Historique

| Date | Changement |
|------|------------|
| 2026-04-08 | Création initiale (story 4b.9) — 6 sources retenues, ~5 catégories |
