# Export JSON — NETSCOPE

## Endpoint

```
GET /api/exports/json
```

### Paramètres

| Paramètre        | Type   | Requis | Description                                            |
|------------------|--------|--------|--------------------------------------------------------|
| `capture_id`     | string | Non    | ID de la capture. Défaut : dernière capture             |
| `anomalies_only` | string | Non    | `"true"` (défaut) = anomalies seules, `"false"` = tous les paquets |

### Réponses

| Code | Description                                                    |
|------|----------------------------------------------------------------|
| 200  | Fichier JSON téléchargé                                        |
| 404  | `capture_id` introuvable, ou pcap introuvable en mode all-data |

### Headers de réponse

- `Content-Type: application/json; charset=utf-8`
- `Content-Disposition: attachment; filename="netscope-{label}-{capture_id}-{YYYYMMDD-HHmmss}.json"`
  - `label` = `anomalies` (mode défaut) ou `all-data` (mode toutes données)
- `X-Anomaly-Count: <int>`

### Exemples d'URL

```
GET /api/exports/json?capture_id=cap_001&anomalies_only=true
GET /api/exports/json?capture_id=cap_001&anomalies_only=false
```

## Structure JSON

```json
{
  "metadata": {
    "format": "netscope-anomalies-export",
    "version": "1.0",
    "exported_at": "2026-04-28T14:30:22+00:00",
    "capture_id": "capture_20260428_143000",
    "analyzed_at": "2026-04-28T14:30:05+00:00",
    "anomaly_count": 3,
    "by_criticality": {
      "critical": 1,
      "warning": 1,
      "normal": 1
    }
  },
  "anomalies": [
    {
      "id": "anomaly_abc12345",
      "timestamp": "2026-04-28T14:30:01+00:00",
      "ip_src": "192.168.1.10",
      "ip_dst": "45.33.32.156",
      "port_src": 54321,
      "port_dst": 4444,
      "protocol": "TCP",
      "score": 85,
      "criticality": "critical",
      "blacklist_match": true,
      "match_type": "ip",
      "matched_value": "45.33.32.156",
      "source_file": "ips_malware.txt",
      "reason": "IP connue pour activite malveillante",
      "human_context": {
        "short_message": "IP blacklistee - activite malware connue",
        "explanation": "Cette IP est repertoriee dans les bases de menaces",
        "action_hint": "Bloquer cette IP au niveau du pare-feu"
      }
    }
  ]
}
```

## Champs anomalie

| Champ             | Type           | Description                                       |
|-------------------|----------------|---------------------------------------------------|
| `id`              | string         | Identifiant unique de l'anomalie                  |
| `timestamp`       | string (ISO 8601) | Horodatage du paquet                           |
| `ip_src`          | string         | Adresse IP source                                 |
| `ip_dst`          | string         | Adresse IP destination                            |
| `port_src`        | int \| null    | Port source (`null` si absent, ex: ICMP)          |
| `port_dst`        | int \| null    | Port destination (`null` si absent)               |
| `protocol`        | string         | Protocole reseau (TCP, UDP, ICMP, etc.)           |
| `score`           | int            | Score d'anomalie (0-100)                          |
| `criticality`     | string         | `"critical"`, `"warning"`, ou `"normal"`          |
| `blacklist_match` | boolean        | `true` si match IP ou domaine blackliste          |
| `match_type`      | string         | `"ip"`, `"domain"`, ou `"term"`                   |
| `matched_value`   | string         | Valeur ayant declenche la detection               |
| `source_file`     | string         | Fichier blacklist source                          |
| `reason`          | string         | Contexte humain accessible                        |
| `human_context`   | object \| null | Contexte enrichi (si disponible)                  |

## Utilisation

### Python (pandas)

```python
import json
import pandas as pd

with open("netscope-anomalies-cap001-20260428-143022.json") as f:
    data = json.load(f)

df = pd.DataFrame(data["anomalies"])
print(df[["ip_src", "ip_dst", "score", "criticality"]])
```

### Node.js

```javascript
const data = JSON.parse(fs.readFileSync("export.json", "utf-8"));
console.log(`${data.metadata.anomaly_count} anomalies exportees`);
data.anomalies.forEach(a => console.log(`${a.ip_src} -> ${a.ip_dst} (score: ${a.score})`));
```

### jq

```bash
# Lister les anomalies critiques
jq '.anomalies[] | select(.criticality == "critical") | {ip_src, ip_dst, score}' export.json
```

## Mode « Toutes les données » (Story 5.3)

En mode `anomalies_only=false`, la structure change :

```json
{
  "metadata": {
    "format": "netscope-anomalies-export",
    "version": "1.0",
    "exported_at": "2026-05-03T12:00:00+00:00",
    "capture_id": "capture_20260503_120000",
    "export_mode": "all",
    "total_packets": 150,
    "anomaly_count": 3
  },
  "packets": [
    {
      "timestamp": "2026-05-03T12:00:01+00:00",
      "ip_src": "192.168.1.10",
      "ip_dst": "10.0.0.1",
      "port_src": 54321,
      "port_dst": 80,
      "protocol": "TCP",
      "score": 0,
      "blacklist_match": false,
      "reason": ""
    },
    {
      "timestamp": "2026-05-03T12:00:02+00:00",
      "ip_src": "192.168.1.10",
      "ip_dst": "45.33.32.156",
      "port_src": 54322,
      "port_dst": 4444,
      "protocol": "TCP",
      "score": 85,
      "blacklist_match": true,
      "reason": "IP blacklistee - activite malware connue"
    }
  ]
}
```

Les paquets normaux ont `score=0`, `blacklist_match=false`, `reason=""`.
Les paquets correspondant à une anomalie sont enrichis.

## Conformite

- RFC 8259 (JSON)
- Encodage UTF-8 sans BOM
- Cles en `snake_case`
- Valeurs absentes : `null` (pas de string `"None"`)
- Indentation : 2 espaces
