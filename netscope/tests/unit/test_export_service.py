"""Tests unitaires du service `CsvExporter` (Story 5.1).

Couvre :
- Header exact + ordre des colonnes (AC2)
- BOM UTF-8 en tête de flux (AC3)
- CRLF + échappement RFC 4180 (AC3)
- Caractères UTF-8 / accents préservés (AC3)
- Collection vide → header seul (AC6)
- Ports None → cellules vides (AC2)
- Détermination `Blacklist match` via enum MatchType (Règle #15)
- Préférence `HumanContext.short_message` sur `BlacklistMatch.context`
"""

from __future__ import annotations

import csv
import io
from datetime import datetime

import pytest

from app.core.detection.human_context import HumanContext, RiskLevel
from app.models.anomaly import (
    Anomaly,
    AnomalyCollection,
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
)
from app.services.export_service import (
    CSV_HEADERS,
    UTF8_BOM,
    CsvExporter,
    get_csv_exporter,
    reset_csv_exporter,
)


def _build_anomaly(
    *,
    match_type: MatchType = MatchType.IP,
    matched_value: str = "1.2.3.4",
    context: str = "Contexte brut",
    score: int = 85,
    criticality: CriticalityLevel = CriticalityLevel.CRITICAL,
    packet_info: dict | None = None,
    human_context: HumanContext | None = None,
) -> Anomaly:
    """Construit une Anomaly minimale pour les tests."""
    if packet_info is None:
        packet_info = {
            "timestamp": "2026-04-18T09:15:23+00:00",
            "ip_src": "192.168.1.10",
            "ip_dst": "1.2.3.4",
            "port_src": 54321,
            "port_dst": 443,
            "protocol": "TCP",
        }
    match = BlacklistMatch(
        match_type=match_type,
        matched_value=matched_value,
        source_file="test.txt",
        context=context,
        criticality=criticality,
        timestamp=datetime(2026, 4, 18, 9, 15, 23),
    )
    return Anomaly(
        id="anomaly_test01",
        match=match,
        score=score,
        packet_info=packet_info,
        criticality_level=criticality,
        capture_id="cap_test_001",
        human_context=human_context,
    )


def _collect(exporter: CsvExporter, collection: AnomalyCollection | None) -> str:
    return "".join(exporter.generate_anomalies_csv(collection))


class TestCsvExporterHeader:
    """AC2 — Header exact et ordre des colonnes."""

    def test_header_contains_nine_columns_in_exact_order(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly()
        collection = AnomalyCollection(anomalies=[anomaly], capture_id="cap_test_001")

        output = _collect(exporter, collection)

        # Retirer BOM pour parser proprement
        assert output.startswith(UTF8_BOM)
        csv_text = output[len(UTF8_BOM):]
        reader = csv.reader(io.StringIO(csv_text))
        header = next(reader)

        assert header == CSV_HEADERS
        assert len(header) == 9
        assert header[0] == "Timestamp"
        assert header[7] == "Blacklist match"
        assert header[8] == "Raison/Contexte"

    def test_empty_collection_returns_header_only(self):
        exporter = CsvExporter()
        output = _collect(exporter, AnomalyCollection(anomalies=[], capture_id="cap_test"))

        assert output.startswith(UTF8_BOM)
        csv_text = output[len(UTF8_BOM):]
        lines = [line for line in csv_text.splitlines() if line]
        assert len(lines) == 1  # header seul

    def test_none_collection_returns_header_only(self):
        exporter = CsvExporter()
        output = _collect(exporter, None)

        csv_text = output[len(UTF8_BOM):]
        lines = [line for line in csv_text.splitlines() if line]
        assert len(lines) == 1


class TestCsvExporterRfc4180:
    """AC3 — Conformité RFC 4180 + UTF-8 avec BOM."""

    def test_bom_utf8_present_at_start(self):
        exporter = CsvExporter()
        output = _collect(exporter, AnomalyCollection(anomalies=[], capture_id="c"))
        assert output[0] == "\ufeff"

    def test_line_terminator_is_crlf(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly()
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )
        # Au moins 2 occurrences de CRLF (header + ligne)
        assert output.count("\r\n") >= 2
        # Aucun LF isolé (pas de '\n' qui ne soit pas précédé de '\r')
        assert "\n" not in output.replace("\r\n", "")

    def test_field_with_comma_is_quoted(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(context="Ligne, avec virgule")
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )

        # Le contenu doit être quoté
        assert '"Ligne, avec virgule"' in output

        # Parser le CSV pour vérifier l'intégrité de la cellule
        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][-1] == "Ligne, avec virgule"

    def test_field_with_double_quote_is_escaped(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(context='Phrase "citée" ici')
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )

        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][-1] == 'Phrase "citée" ici'

    def test_field_with_crlf_is_quoted(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(context="Ligne1\r\nLigne2")
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )

        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][-1] == "Ligne1\r\nLigne2"

    def test_utf8_accents_preserved(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(context="Détection naïve — accès élevé")
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )

        encoded = output.encode("utf-8")
        # BOM codé en UTF-8 : EF BB BF
        assert encoded.startswith(b"\xef\xbb\xbf")
        # Retour à un str correctement décodé → accents intacts
        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert "Détection naïve — accès élevé" == rows[1][-1]


class TestCsvExporterCells:
    """AC2 + règles métier — mapping cellules."""

    def test_ports_none_produce_empty_cells(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(
            packet_info={
                "timestamp": "2026-04-18T09:15:23+00:00",
                "ip_src": "192.168.1.10",
                "ip_dst": "10.0.0.1",
                "port_src": None,
                "port_dst": None,
                "protocol": "ICMP",
            }
        )
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )

        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        # Ports source et destination = cellules vides, pas "None"
        assert rows[1][3] == ""
        assert rows[1][4] == ""
        assert "None" not in rows[1]

    def test_blacklist_match_oui_for_ip(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(match_type=MatchType.IP)
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )
        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][7] == "oui"

    def test_blacklist_match_oui_for_domain(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(match_type=MatchType.DOMAIN, matched_value="evil.example")
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )
        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][7] == "oui"

    def test_blacklist_match_non_for_term(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(
            match_type=MatchType.TERM,
            matched_value="suspicious-term",
            criticality=CriticalityLevel.WARNING,
            score=65,
        )
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )
        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][7] == "non"

    def test_reason_prefers_human_context_short_message(self):
        exporter = CsvExporter()
        hc = HumanContext(
            short_message="IP malveillante connue",
            explanation="Cette IP apparaît sur une blacklist...",
            risk_level=RiskLevel.HIGH,
            indicator="🚨",
        )
        anomaly = _build_anomaly(context="Contexte technique brut", human_context=hc)
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )
        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][-1] == "IP malveillante connue"

    def test_reason_falls_back_to_match_context_without_human_context(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(
            context="Match brut fallback", human_context=None
        )
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )
        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][-1] == "Match brut fallback"

    def test_score_serialized_as_string(self):
        exporter = CsvExporter()
        anomaly = _build_anomaly(score=92)
        output = _collect(
            exporter, AnomalyCollection(anomalies=[anomaly], capture_id="c")
        )
        rows = list(csv.reader(io.StringIO(output[len(UTF8_BOM):])))
        assert rows[1][6] == "92"


class TestCsvExporterStreaming:
    """AC4 — Génération streaming (pas d'accumulation mémoire)."""

    def test_generator_yields_lines_progressively(self):
        exporter = CsvExporter()
        anomalies = [_build_anomaly(score=i) for i in range(1, 6)]
        collection = AnomalyCollection(anomalies=anomalies, capture_id="c")

        chunks = list(exporter.generate_anomalies_csv(collection))

        # BOM+header dans le premier chunk, puis 1 chunk par anomalie (5)
        assert len(chunks) == 1 + 5
        assert chunks[0].startswith(UTF8_BOM)


class TestCsvExporterSingleton:
    def test_get_csv_exporter_returns_same_instance(self):
        reset_csv_exporter()
        instance_1 = get_csv_exporter()
        instance_2 = get_csv_exporter()
        assert instance_1 is instance_2

    def test_reset_creates_new_instance(self):
        instance_1 = get_csv_exporter()
        reset_csv_exporter()
        instance_2 = get_csv_exporter()
        assert instance_1 is not instance_2


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Isole les tests du singleton global."""
    reset_csv_exporter()
    yield
    reset_csv_exporter()
