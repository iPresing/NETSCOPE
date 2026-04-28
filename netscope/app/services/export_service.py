"""Service d'export CSV pour les anomalies détectées.

Story 5.1: Export CSV (FR45, FR47, NFR8, NFR46).

Produit un flux CSV RFC 4180 + UTF-8 avec BOM, compatible Excel / Google Sheets
/ LibreOffice. Le générateur `generate_anomalies_csv` streame ligne par ligne
pour éviter toute accumulation en mémoire (cible RAM Raspberry Pi Zero).

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
import logging
from typing import Iterator

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
