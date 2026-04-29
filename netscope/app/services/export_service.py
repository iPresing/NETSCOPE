"""Service d'export des anomalies détectées (CSV et JSON).

Story 5.1: Export CSV (FR45, FR47, NFR8, NFR46).
Story 5.2: Export JSON (FR46, FR47, NFR8, NFR47).

CSV : flux RFC 4180 + UTF-8 avec BOM, streaming ligne par ligne.
JSON : document complet RFC 8259, UTF-8 sans BOM, indenté 2 espaces.

Lessons Learned Epic 1-4 appliquées :
- Module-level logger (pas current_app.logger)
- Enums pour comparaisons (Règle #15) — MatchType.IP / MatchType.DOMAIN
- Pas de cache d'état calculé sur objet partagé (Règle #14) — méthodes sans
  état pour thread-safety implicite
- Type hints Python 3.10+ (X | None)
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterator

from app.models.anomaly import Anomaly, AnomalyCollection, MatchType

logger = logging.getLogger(__name__)

UTF8_BOM = "\ufeff"

CSV_HEADERS: list[str] = [
    "Timestamp",
    "IP source",
    "IP destination",
    "Port source",
    "Port destination",
    "Protocole",
    "Score",
    "Blacklist match",
    "Raison/Contexte",
]

BLACKLIST_MATCH_TYPES: frozenset[MatchType] = frozenset({MatchType.IP, MatchType.DOMAIN})


class CsvExporter:
    """Générateur de flux CSV pour `AnomalyCollection`.

    Produit un itérateur de chaînes de caractères (streaming) conforme RFC 4180,
    préfixé par le BOM UTF-8 pour compatibilité Excel Windows.

    Implémentation stateless — les conversions se font à la sérialisation,
    rien n'est caché sur la collection passée en paramètre.
    """

    def generate_anomalies_csv(self, collection: AnomalyCollection | None) -> Iterator[str]:
        """Streame le CSV des anomalies, ligne par ligne.

        Args:
            collection: Collection à exporter. `None` ou vide → header seul.

        Yields:
            Chaînes de caractères UTF-8 : BOM, puis header, puis une ligne
            par anomalie. CRLF comme terminateur de ligne (RFC 4180).
        """
        yield UTF8_BOM + self._format_row(CSV_HEADERS)

        if collection is None or collection.total == 0:
            return

        for anomaly in collection.get_sorted():
            row = self._anomaly_to_row(anomaly)
            yield self._format_row(row)

    @staticmethod
    def _format_row(values: list[str]) -> str:
        """Encode une ligne de valeurs en CSV (quoting minimal, CRLF)."""
        buffer = io.StringIO()
        writer = csv.writer(
            buffer,
            dialect="excel",
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\r\n",
        )
        writer.writerow(values)
        return buffer.getvalue()

    @staticmethod
    def _anomaly_to_row(anomaly: Anomaly) -> list[str]:
        """Convertit une `Anomaly` en liste de cellules CSV (toutes `str`)."""
        packet_info = anomaly.packet_info or {}
        match = anomaly.match

        timestamp = packet_info.get("timestamp", "") or ""
        ip_src = packet_info.get("ip_src", "") or ""
        ip_dst = packet_info.get("ip_dst", "") or ""

        port_src_raw = packet_info.get("port_src")
        port_dst_raw = packet_info.get("port_dst")
        port_src = "" if port_src_raw is None else str(port_src_raw)
        port_dst = "" if port_dst_raw is None else str(port_dst_raw)

        protocol = packet_info.get("protocol", "") or ""

        blacklist_match = "oui" if match.match_type in BLACKLIST_MATCH_TYPES else "non"

        reason = _resolve_reason(anomaly)

        return [
            str(timestamp),
            str(ip_src),
            str(ip_dst),
            port_src,
            port_dst,
            str(protocol),
            str(anomaly.score),
            blacklist_match,
            reason,
        ]


def _resolve_reason(anomaly: Anomaly) -> str:
    """Priorité au contexte humain accessible (Story 2.5), sinon contexte brut.

    Story 5.1 Dev Notes référencent `human_context.title`, champ qui n'existe
    pas sur `HumanContext` (Story 2.5) — les champs réels sont `short_message`
    / `explanation`. On privilégie `short_message` (libellé 1-2 phrases pensé
    pour les non-experts) avec fallback sur `explanation` si absent.
    """
    human_context = anomaly.human_context
    if human_context is not None:
        if human_context.short_message:
            return human_context.short_message
        if human_context.explanation:
            return human_context.explanation
    return anomaly.match.context or ""


class JsonExporter:
    """Générateur de document JSON pour `AnomalyCollection`.

    Produit un document JSON complet (pas de streaming) conforme RFC 8259,
    UTF-8 sans BOM, indenté 2 espaces. Structure : `metadata` + `anomalies`.

    Implémentation stateless — les conversions se font à la sérialisation,
    rien n'est caché sur la collection passée en paramètre.
    """

    EXPORT_FORMAT = "netscope-anomalies-export"
    EXPORT_VERSION = "1.0"

    def generate_anomalies_json(self, collection: AnomalyCollection | None) -> str:
        """Produit le document JSON complet des anomalies.

        Args:
            collection: Collection à exporter. `None` ou vide → anomalies vides.

        Returns:
            Chaîne JSON UTF-8, indentée 2 espaces, sans BOM.
        """
        now = datetime.now(timezone.utc)

        capture_id = collection.capture_id if collection else None
        analyzed_at_dt = collection.analyzed_at if collection else None
        if analyzed_at_dt is not None and analyzed_at_dt.tzinfo is None:
            analyzed_at_dt = analyzed_at_dt.replace(tzinfo=timezone.utc)
        analyzed_at = analyzed_at_dt.isoformat() if analyzed_at_dt else None
        anomaly_count = collection.total if collection else 0
        by_crit = collection.by_criticality if collection else {"critical": 0, "warning": 0, "normal": 0}

        anomalies_list: list[dict[str, Any]] = []
        if collection and collection.total > 0:
            for anomaly in collection.get_sorted():
                anomalies_list.append(self._anomaly_to_export_dict(anomaly))

        data = {
            "metadata": {
                "format": self.EXPORT_FORMAT,
                "version": self.EXPORT_VERSION,
                "exported_at": now.isoformat(),
                "capture_id": capture_id,
                "analyzed_at": analyzed_at,
                "anomaly_count": anomaly_count,
                "by_criticality": by_crit,
            },
            "anomalies": anomalies_list,
        }

        return json.dumps(data, ensure_ascii=False, indent=2)

    @staticmethod
    def _anomaly_to_export_dict(anomaly: Anomaly) -> dict[str, Any]:
        """Convertit une `Anomaly` en dict d'export JSON enrichi (FR47)."""
        packet_info = anomaly.packet_info or {}
        match = anomaly.match

        port_src_raw = packet_info.get("port_src")
        port_dst_raw = packet_info.get("port_dst")
        try:
            port_src = int(port_src_raw) if port_src_raw is not None else None
        except (ValueError, TypeError):
            port_src = None
        try:
            port_dst = int(port_dst_raw) if port_dst_raw is not None else None
        except (ValueError, TypeError):
            port_dst = None

        human_ctx = None
        if anomaly.human_context is not None:
            human_ctx = {
                "short_message": anomaly.human_context.short_message,
                "explanation": anomaly.human_context.explanation,
                "action_hint": anomaly.human_context.action_hint,
            }

        return {
            "id": anomaly.id,
            "timestamp": packet_info.get("timestamp"),
            "ip_src": packet_info.get("ip_src"),
            "ip_dst": packet_info.get("ip_dst"),
            "port_src": port_src,
            "port_dst": port_dst,
            "protocol": packet_info.get("protocol"),
            "score": anomaly.score,
            "criticality": anomaly.criticality_level.value,
            "blacklist_match": match.match_type in BLACKLIST_MATCH_TYPES,
            "match_type": match.match_type.value,
            "matched_value": match.matched_value,
            "source_file": match.source_file,
            "reason": _resolve_reason(anomaly),
            "human_context": human_ctx,
        }


_csv_exporter: CsvExporter | None = None


def get_csv_exporter() -> CsvExporter:
    """Renvoie l'instance singleton de `CsvExporter`."""
    global _csv_exporter
    if _csv_exporter is None:
        _csv_exporter = CsvExporter()
    return _csv_exporter


def reset_csv_exporter() -> None:
    """Réinitialise le singleton (réservé aux tests)."""
    global _csv_exporter
    _csv_exporter = None


_json_exporter: JsonExporter | None = None


def get_json_exporter() -> JsonExporter:
    """Renvoie l'instance singleton de `JsonExporter`."""
    global _json_exporter
    if _json_exporter is None:
        _json_exporter = JsonExporter()
    return _json_exporter


def reset_json_exporter() -> None:
    """Réinitialise le singleton (réservé aux tests)."""
    global _json_exporter
    _json_exporter = None
