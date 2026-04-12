# Dossier `blacklists_defaults`

Ce dossier contient les **blacklists par défaut** embarquées avec NETSCOPE :
adresses IP, domaines et termes réputés malveillants, utilisés comme
"starter pack" pour la détection dès la première capture, **sans nécessité
d'accès réseau**.

> Story 4b.9 — Enrichissement Blacklists Sources.
> Voir également [`SOURCES.md`](SOURCES.md) pour la méthodologie de
> sélection et les licences des sources externes.

## Structure du dossier

```
blacklists_defaults/
├── SOURCES.md                 # Documentation des sources publiques évaluées
├── README.md                  # Ce fichier
├── manifest.yaml              # Manifest consommé par le script CLI refresh
│
├── ips_malware.txt            # IPs : scanners, Tor exit abusifs, malware
├── ips_malware.meta.yaml      # Métadonnées du fichier ci-dessus
├── ips_c2.txt                 # IPs : serveurs C2 (Emotet, Dridex, Cobalt Strike…)
├── ips_c2.meta.yaml
├── domains_malware.txt        # Domaines : fake updates, cryptominers, exploit kits
├── domains_malware.meta.yaml
├── domains_phishing.txt       # Domaines : typosquatting, fake login
├── domains_phishing.meta.yaml
├── terms_suspect.txt          # Patterns : reverse shells, LOLBAS, webshells
└── terms_suspect.meta.yaml
```

## Format des fichiers `.txt`

- **Une entrée par ligne**
- Les lignes commençant par `#` sont des commentaires
- Les lignes vides sont ignorées
- Les espaces en fin de ligne sont nettoyés
- Les IPs doivent être en notation décimale pointée (ex: `8.8.8.8`)
  — les plages CIDR ne sont pas acceptées par le modèle `BlacklistType`
- Les domaines sont normalisés en **lowercase** au chargement
- Les termes sont conservés tels quels (case-insensitive au match)

Exemple (`ips_c2.txt`) :

```
# NETSCOPE Starter Pack - IPs C2
# Sources: Feodo Tracker (feodotracker.abuse.ch), IPsum C2 subset
# Licence: CC0-1.0 / Unlicense

185.141.27.34
194.147.78.155
```

## Format des fichiers `.meta.yaml`

Chaque fichier `.txt` est accompagné d'un fichier compagnon
`<nom>.meta.yaml` décrivant sa catégorie, ses sources et leurs licences.

```yaml
name: ips_malware              # ID court (égal au stem du .txt)
category: ip                   # ip | domain | term
description: >-                # Texte affiché dans le panneau UI
  IPs connues pour héberger ou distribuer du malware...
sources:                       # Liste des sources utilisées pour ce fichier
  - name: IPsum                # Nom court de la source
    url: https://github.com/stamparm/ipsum
    license: Unlicense         # SPDX ou libellé court
  - name: FireHOL Level 1
    url: https://iplists.firehol.org/...
    license: CC-BY-SA-4.0
last_updated: "2026-04-08T00:00:00+00:00"
entries_count: 112             # Recompté dynamiquement depuis le .txt au runtime
```

**Rétrocompatibilité** : l'absence d'un fichier `.meta.yaml` ne bloque pas
le chargement — `BlacklistManager.get_defaults_metadata()` émet simplement
un warning et omet l'entrée de la réponse API.

## Ajouter une nouvelle source

Pour intégrer une nouvelle source publique :

1. **Évaluer la source** dans [`SOURCES.md`](SOURCES.md) — licence,
   fréquence, volume, fiabilité. Licences compatibles : Public domain, CC0,
   MIT, BSD, Apache 2.0, GPL-3.0, CC-BY-SA-4.0.
2. **Ajouter l'entrée au [`manifest.yaml`](manifest.yaml)** avec le parser
   adéquat (`plain_text_ip` ou `plain_text_domain`) et un `max_entries`
   raisonnable pour maîtriser la taille du dépôt.
3. **Lancer le script CLI** (voir section suivante) pour rafraîchir les
   fichiers `.txt` et `.meta.yaml` à partir des sources du manifest.
4. **Vérifier la qualité du dataset** :
   ```bash
   python -m pytest tests/unit/test_defaults_dataset_quality.py
   ```
5. **Commiter** les fichiers `.txt`, `.meta.yaml`, et mettre à jour
   `SOURCES.md` si nécessaire.

## Script CLI de rafraîchissement

Le module `app.tools.refresh_blacklists` permet de rafraîchir les
fichiers `.txt` à partir des sources définies dans `manifest.yaml`.

```bash
# Rafraîchir toutes les sources (écrase les .txt actuels en préservant les entrées)
python -m app.tools.refresh_blacklists

# Aperçu sans écriture
python -m app.tools.refresh_blacklists --dry-run

# Ne traiter qu'une source spécifique
python -m app.tools.refresh_blacklists --source feodo_tracker

# Logs DEBUG
python -m app.tools.refresh_blacklists --verbose
```

**Garanties du script :**

- HTTPS uniquement, timeout 30s
- User-Agent `NETSCOPE-blacklist-refresher/1.0`
- Aucune dépendance nouvelle : uniquement `urllib` (stdlib) + `PyYAML`
- Écriture atomique (`tempfile` + `os.replace`) : aucun risque de corruption
- Exit code ≠ 0 si au moins une source a échoué
- Exclusion automatique : IPs privées/réservées, TLDs réservés
  (`.local`, `.example`, `.invalid`, `.test`, `.localhost`)

**Important** : ce script **n'est pas** invoqué automatiquement par
l'application Flask. C'est un outil manuel pour l'opérateur. Il ne doit
**pas** être importé depuis `app/__init__.py` ni depuis les blueprints
(règle #22 : pas de dépendance runtime cachée).

## Philosophie offline-first

La sonde NETSCOPE peut tourner **sans accès internet** (cf. story 1.2 —
connectivité réseau captive). Les blacklists embarquées constituent le
dataset minimal exploitable dès la première capture. Les mises à jour
sont un **acte volontaire** de l'opérateur (exécution du script CLI),
jamais une opération automatique au démarrage ou planifiée en cron.

## Licences

Toutes les sources embarquées ont une licence permettant la redistribution
et l'usage en projet open-source. Voir [`SOURCES.md`](SOURCES.md) §
« Compatibilité des licences ».
