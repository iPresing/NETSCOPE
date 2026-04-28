# Export CSV — Story 5.1

Première fonctionnalité d'Epic 5 (Export, Reporting & Administration).
Permet d'exporter les anomalies détectées lors de la dernière capture (ou d'une
capture ciblée par `capture_id`) au format CSV, pour analyse dans Excel,
Google Sheets, LibreOffice Calc ou tout outil BI.

## Parcours utilisateur

1. Lancer une capture depuis le Dashboard.
2. Ouvrir la page **Anomalies**.
3. Cliquer sur le bouton **Export CSV** dans la toolbar.
4. Le navigateur télécharge un fichier nommé
   `netscope-anomalies-{capture_id}-{YYYYMMDD-HHmmss}.csv`.

Le bouton est désactivé (grisé) tant qu'aucune capture n'a été réalisée.

## Endpoint API

`GET /api/exports/csv`

| Query Param  | Type | Défaut           | Description                              |
|--------------|------|------------------|------------------------------------------|
| `capture_id` | str  | dernière capture | ID de capture ciblé (optionnel).         |

### Réponses

- `200 OK` — `Content-Type: text/csv; charset=utf-8`, `Content-Disposition:
  attachment; filename="…csv"`, corps streamé ligne par ligne (BOM UTF-8 puis
  header puis lignes d'anomalies).
- `404 Not Found` — JSON `{code: "CAPTURE_NOT_FOUND"}` si `capture_id` fourni
  mais inconnu.

## Format CSV produit

- Encodage : **UTF-8 avec BOM** (`\ufeff`) — requis pour Excel Windows.
- Séparateur : virgule `,` — RFC 4180.
- Retour ligne : `\r\n` (CRLF) — RFC 4180.
- Champs contenant virgule, guillemet ou CRLF : entourés de `"…"` ; les `"`
  internes sont doublés (`""`).

### Colonnes (ordre imposé)

| # | Colonne             | Exemple                                |
|---|---------------------|----------------------------------------|
| 1 | Timestamp           | `2026-04-18T09:15:23+00:00` (ISO 8601) |
| 2 | IP source           | `192.168.1.10`                         |
| 3 | IP destination      | `1.2.3.4`                              |
| 4 | Port source         | `54321` ou cellule vide si non TCP/UDP |
| 5 | Port destination    | `443` ou cellule vide si non TCP/UDP   |
| 6 | Protocole           | `TCP`, `UDP`, `ICMP`, …                |
| 7 | Score               | `0`–`100`                              |
| 8 | Blacklist match     | `oui` (MatchType.IP / DOMAIN) / `non`  |
| 9 | Raison/Contexte     | `HumanContext.short_message` prioritaire, sinon `BlacklistMatch.context` |

## Performance

- Génération **streaming** : le module `csv` écrit ligne par ligne, pas de
  concaténation en mémoire. Confortable jusqu'à 10 000+ anomalies sur Pi Zero.
- Objectif `<10s` de génération serveur pour ≤10 000 entrées (NFR8).
- Durée mesurée et loggée (`duration_ms`, format clé=valeur, Règle #9).

## Scope explicite

- **5.1 (cette story)** : export des anomalies uniquement.
- **5.2 (backlog)** : même pattern appliqué au format JSON.
- **5.3 (backlog)** : toggle « anomalies / toutes les données capturées ».
