# Export CSV — Stories 5.1 & 5.3

Fonctionnalité d'Epic 5 (Export, Reporting & Administration).
Permet d'exporter les anomalies détectées ou tous les paquets d'une capture
au format CSV, pour analyse dans Excel, Google Sheets, LibreOffice Calc ou
tout outil BI.

## Parcours utilisateur

1. Lancer une capture depuis le Dashboard.
2. Ouvrir la page **Anomalies**.
3. Choisir le mode d'export via le sélecteur :
   - **Anomalies uniquement** (défaut) — seules les anomalies détectées.
   - **Toutes les données** — tous les paquets du pcap, enrichis avec les anomalies.
4. Cliquer sur le bouton **Export CSV** dans la toolbar.
5. Le navigateur télécharge un fichier nommé :
   - `netscope-anomalies-{capture_id}-{YYYYMMDD-HHmmss}.csv` (mode anomalies)
   - `netscope-all-data-{capture_id}-{YYYYMMDD-HHmmss}.csv` (mode toutes données)

Le sélecteur et les boutons sont désactivés (grisés) tant qu'aucune capture
n'a été réalisée.

## Endpoint API

`GET /api/exports/csv`

| Query Param      | Type | Défaut           | Description                              |
|------------------|------|------------------|------------------------------------------|
| `capture_id`     | str  | dernière capture | ID de capture ciblé (optionnel).         |
| `anomalies_only` | str  | `"true"`         | `"true"` = anomalies seules, `"false"` = tous les paquets. |

### Réponses

- `200 OK` — `Content-Type: text/csv; charset=utf-8`, `Content-Disposition:
  attachment; filename="…csv"`, corps streamé ligne par ligne (BOM UTF-8 puis
  header puis lignes d'anomalies ou paquets).
- `404 Not Found` — JSON `{code: "CAPTURE_NOT_FOUND"}` si `capture_id` fourni
  mais inconnu, ou `{code: "PCAP_NOT_FOUND"}` si mode all-data et fichier pcap
  introuvable.

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

## Mode « Toutes les donn��es » (Story 5.3)

En mode `anomalies_only=false`, le service parse le fichier pcap complet
et produit une ligne par paquet. Les paquets correspondant à une anomalie
sont enrichis avec score, blacklist match et raison. Les paquets normaux
ont `Score=0`, `Blacklist match=non`, `Raison/Contexte=""`.

### Exemples d'URL

```
GET /api/exports/csv?capture_id=cap_001&anomalies_only=true
GET /api/exports/csv?capture_id=cap_001&anomalies_only=false
```
