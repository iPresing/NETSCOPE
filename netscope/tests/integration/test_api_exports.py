"""Tests d'intégration des endpoints export (CSV + JSON).

Story 5.1 — CSV :
- 200 + Content-Type `text/csv; charset=utf-8` + Content-Disposition attachment
- Pattern de nom de fichier `netscope-anomalies-{capture_id}-{YYYYMMDD-HHmmss}.csv`
- Contenu CSV parsable (header correct, lignes cohérentes)
- 404 JSON si `capture_id` inexistant
- Capture sans anomalies ou aucune capture → 200 avec header seul

Story 5.2 — JSON :
- 200 + Content-Type `application/json; charset=utf-8` + Content-Disposition attachment
- Pattern de nom de fichier `.json`
- Contenu JSON parsable, structure `metadata` + `anomalies`
- 404 si `capture_id` invalide
- Capture sans anomalies → 200 avec `anomalies: []`

Story 5.3 — anomalies_only param :
- anomalies_only=true → comportement identique (régression)
- anomalies_only=false → all-data content + filename all-data
- anomalies_only=false + pcap introuvable → 404
- export_mode dans metadata JSON
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime

import pytest

from app.core.detection.anomaly_store import get_anomaly_store, reset_anomaly_store
from app.models.anomaly import (
    Anomaly,
    AnomalyCollection,
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
)

from app.models.capture import PacketInfo

FILENAME_PATTERN_CSV = re.compile(
    r'^netscope-anomalies-(?P<cap>[A-Za-z0-9_\-]+)-\d{8}-\d{6}\.csv$'
)
FILENAME_PATTERN_JSON = re.compile(
    r'^netscope-anomalies-(?P<cap>[A-Za-z0-9_\-]+)-\d{8}-\d{6}\.json$'
)
FILENAME_PATTERN_ALL_DATA_CSV = re.compile(
    r'^netscope-all-data-(?P<cap>[A-Za-z0-9_\-]+)-\d{8}-\d{6}\.csv$'
)
FILENAME_PATTERN_ALL_DATA_JSON = re.compile(
    r'^netscope-all-data-(?P<cap>[A-Za-z0-9_\-]+)-\d{8}-\d{6}\.json$'
)


@pytest.fixture(autouse=True)
def _reset_store():
    reset_anomaly_store()
    yield
    reset_anomaly_store()


def _make_collection(capture_id: str, count: int = 2) -> AnomalyCollection:
    anomalies = []
    for i in range(count):
        match = BlacklistMatch(
            match_type=MatchType.IP,
            matched_value=f"1.2.3.{i+10}",
            source_file="unit.txt",
            context=f"Contexte anomalie {i}",
            criticality=CriticalityLevel.CRITICAL,
            timestamp=datetime(2026, 4, 18, 9, 15, i),
        )
        anomalies.append(
            Anomaly(
                id=f"anomaly_{i:03d}",
                match=match,
                score=80 + i,
                packet_info={
                    "timestamp": f"2026-04-18T09:15:{i:02d}+00:00",
                    "ip_src": "192.168.1.10",
                    "ip_dst": f"1.2.3.{i+10}",
                    "port_src": 54000 + i,
                    "port_dst": 443,
                    "protocol": "TCP",
                },
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id=capture_id,
            )
        )
    return AnomalyCollection(anomalies=anomalies, capture_id=capture_id)


class TestExportsCsvSuccess:
    """AC1 / AC2 / AC3 / AC4 — chemin nominal."""

    def test_returns_200_with_csv_mimetype(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_test_abc"))

        response = client.get("/api/exports/csv?capture_id=cap_test_abc")

        assert response.status_code == 200
        assert response.mimetype == "text/csv"
        assert "charset=utf-8" in response.headers["Content-Type"].lower()

    def test_content_disposition_attachment_filename_pattern(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_test_abc"))

        response = client.get("/api/exports/csv?capture_id=cap_test_abc")

        disposition = response.headers.get("Content-Disposition", "")
        assert "attachment" in disposition
        match = re.search(r'filename="([^"]+)"', disposition)
        assert match is not None
        filename = match.group(1)
        assert FILENAME_PATTERN_CSV.match(filename), f"filename invalide: {filename}"
        assert "cap_test_abc" in filename

    def test_csv_body_parsable_with_expected_header(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_test_abc", count=2))

        response = client.get("/api/exports/csv?capture_id=cap_test_abc")

        body = response.data.decode("utf-8")
        assert body.startswith("\ufeff")
        # Parse complet
        reader = csv.reader(io.StringIO(body[1:]))
        rows = list(reader)
        assert rows[0] == [
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
        assert len(rows) == 1 + 2

    def test_x_anomaly_count_header(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_test_abc", count=3))

        response = client.get("/api/exports/csv?capture_id=cap_test_abc")

        assert response.headers.get("X-Anomaly-Count") == "3"

    def test_latest_used_when_capture_id_absent(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_first"))
        store.store(_make_collection("cap_latest"))

        response = client.get("/api/exports/csv")

        assert response.status_code == 200
        disposition = response.headers.get("Content-Disposition", "")
        assert "cap_latest" in disposition


class TestExportsCsvEmptyStates:
    """AC6 — États vides gracieux."""

    def test_empty_collection_returns_200_with_header_only(self, client):
        store = get_anomaly_store()
        store.store(
            AnomalyCollection(anomalies=[], capture_id="cap_empty_xyz")
        )

        response = client.get("/api/exports/csv?capture_id=cap_empty_xyz")

        assert response.status_code == 200
        body = response.data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(body[1:])))
        assert len(rows) == 1  # header seul
        assert response.headers.get("X-Anomaly-Count") == "0"

    def test_no_capture_ever_returns_200_with_header_only(self, client):
        # Store vide, pas de capture_id → get_latest() = None
        response = client.get("/api/exports/csv")

        assert response.status_code == 200
        body = response.data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(body[1:])))
        assert len(rows) == 1
        assert response.headers.get("X-Anomaly-Count") == "0"


class TestExportsCsvErrorCases:
    """AC6 — erreurs gracieuses."""

    def test_unknown_capture_id_returns_404_json(self, client):
        response = client.get("/api/exports/csv?capture_id=cap_missing_999")

        assert response.status_code == 404
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "CAPTURE_NOT_FOUND"


class TestExportsCsvContentCorrectness:
    """AC2 / AC3 — vérifications fines du contenu."""

    def test_special_characters_roundtrip(self, client):
        store = get_anomaly_store()
        match = BlacklistMatch(
            match_type=MatchType.IP,
            matched_value="1.2.3.4",
            source_file="unit.txt",
            context='Détection naïve, "guillemets" — accès élevé',
            criticality=CriticalityLevel.CRITICAL,
            timestamp=datetime(2026, 4, 18, 9, 15, 0),
        )
        anomaly = Anomaly(
            id="anomaly_001",
            match=match,
            score=90,
            packet_info={
                "timestamp": "2026-04-18T09:15:00+00:00",
                "ip_src": "192.168.1.10",
                "ip_dst": "1.2.3.4",
                "port_src": None,
                "port_dst": None,
                "protocol": "ICMP",
            },
            criticality_level=CriticalityLevel.CRITICAL,
            capture_id="cap_special",
        )
        store.store(
            AnomalyCollection(anomalies=[anomaly], capture_id="cap_special")
        )

        response = client.get("/api/exports/csv?capture_id=cap_special")

        assert response.status_code == 200
        # Bytes pour vérifier BOM UTF-8
        assert response.data[:3] == b"\xef\xbb\xbf"
        body = response.data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(body[1:])))
        # Ports None → cellules vides, pas "None"
        assert rows[1][3] == ""
        assert rows[1][4] == ""
        # Contexte avec virgule + guillemets restauré à l'identique
        assert rows[1][-1] == 'Détection naïve, "guillemets" — accès élevé'


class TestExportsJsonSuccess:
    """AC1 / AC2 / AC3 — chemin nominal JSON."""

    def test_returns_200_with_json_mimetype(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_json_abc"))

        response = client.get("/api/exports/json?capture_id=cap_json_abc")

        assert response.status_code == 200
        assert response.mimetype == "application/json"
        assert "charset=utf-8" in response.headers["Content-Type"].lower()

    def test_content_disposition_attachment_json_filename(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_json_abc"))

        response = client.get("/api/exports/json?capture_id=cap_json_abc")

        disposition = response.headers.get("Content-Disposition", "")
        assert "attachment" in disposition
        match = re.search(r'filename="([^"]+)"', disposition)
        assert match is not None
        filename = match.group(1)
        assert FILENAME_PATTERN_JSON.match(filename), f"filename invalide: {filename}"
        assert "cap_json_abc" in filename

    def test_json_body_parsable_with_structure(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_json_abc", count=2))

        response = client.get("/api/exports/json?capture_id=cap_json_abc")

        data = json.loads(response.data.decode("utf-8"))
        assert "metadata" in data
        assert "anomalies" in data
        assert data["metadata"]["anomaly_count"] == 2
        assert len(data["anomalies"]) == 2

    def test_x_anomaly_count_header(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_json_abc", count=3))

        response = client.get("/api/exports/json?capture_id=cap_json_abc")

        assert response.headers.get("X-Anomaly-Count") == "3"

    def test_latest_used_when_capture_id_absent(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_first"))
        store.store(_make_collection("cap_latest"))

        response = client.get("/api/exports/json")

        assert response.status_code == 200
        data = json.loads(response.data.decode("utf-8"))
        assert data["metadata"]["capture_id"] == "cap_latest"


class TestExportsJsonEmptyStates:
    """AC6 — États vides gracieux JSON."""

    def test_empty_collection_returns_200_with_empty_anomalies(self, client):
        store = get_anomaly_store()
        store.store(
            AnomalyCollection(anomalies=[], capture_id="cap_empty_json")
        )

        response = client.get("/api/exports/json?capture_id=cap_empty_json")

        assert response.status_code == 200
        data = json.loads(response.data.decode("utf-8"))
        assert data["anomalies"] == []
        assert data["metadata"]["anomaly_count"] == 0
        assert response.headers.get("X-Anomaly-Count") == "0"

    def test_no_capture_ever_returns_200_with_empty_anomalies(self, client):
        response = client.get("/api/exports/json")

        assert response.status_code == 200
        data = json.loads(response.data.decode("utf-8"))
        assert data["anomalies"] == []
        assert data["metadata"]["anomaly_count"] == 0


class TestExportsJsonContentCorrectness:
    """AC2 / AC3 — vérifications fines du contenu JSON."""

    def test_special_characters_roundtrip(self, client):
        store = get_anomaly_store()
        match = BlacklistMatch(
            match_type=MatchType.IP,
            matched_value="1.2.3.4",
            source_file="unit.txt",
            context='Détection naïve, "guillemets" — accès élevé',
            criticality=CriticalityLevel.CRITICAL,
            timestamp=datetime(2026, 4, 18, 9, 15, 0),
        )
        anomaly = Anomaly(
            id="anomaly_001",
            match=match,
            score=90,
            packet_info={
                "timestamp": "2026-04-18T09:15:00+00:00",
                "ip_src": "192.168.1.10",
                "ip_dst": "1.2.3.4",
                "port_src": None,
                "port_dst": None,
                "protocol": "ICMP",
            },
            criticality_level=CriticalityLevel.CRITICAL,
            capture_id="cap_special_json",
        )
        store.store(
            AnomalyCollection(anomalies=[anomaly], capture_id="cap_special_json")
        )

        response = client.get("/api/exports/json?capture_id=cap_special_json")

        assert response.status_code == 200
        data = json.loads(response.data.decode("utf-8"))
        entry = data["anomalies"][0]
        assert entry["port_src"] is None
        assert entry["port_dst"] is None
        assert entry["reason"] == 'Détection naïve, "guillemets" — accès élevé'
        raw = response.data.decode("utf-8")
        assert "Détection" in raw
        assert "élevé" in raw


class TestExportsJsonErrorCases:
    """AC6 — erreurs gracieuses JSON."""

    def test_unknown_capture_id_returns_404_json(self, client):
        response = client.get("/api/exports/json?capture_id=cap_missing_999")

        assert response.status_code == 404
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "CAPTURE_NOT_FOUND"


def _mock_packets():
    """Quelques PacketInfo pour tests all-data."""
    return [
        PacketInfo(
            timestamp=datetime(2026, 5, 3, 12, 0, 0),
            ip_src="192.168.1.10", ip_dst="10.0.0.1",
            port_src=54321, port_dst=80, protocol="TCP", length=100,
        ),
        PacketInfo(
            timestamp=datetime(2026, 5, 3, 12, 0, 1),
            ip_src="192.168.1.10", ip_dst="1.2.3.10",
            port_src=54322, port_dst=443, protocol="TCP", length=200,
        ),
    ]


class TestExportsCsvAnomaliesOnlyRegression:
    """Story 5.3 — anomalies_only=true doit être identique au comportement existant."""

    def test_anomalies_only_true_same_as_default(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_reg", count=2))

        resp_default = client.get("/api/exports/csv?capture_id=cap_reg")
        body_default = resp_default.data.decode("utf-8")
        resp_default.close()

        resp_explicit = client.get("/api/exports/csv?capture_id=cap_reg&anomalies_only=true")
        body_explicit = resp_explicit.data.decode("utf-8")
        resp_explicit.close()

        assert resp_default.status_code == 200
        assert resp_explicit.status_code == 200
        assert body_default == body_explicit


class TestExportsCsvAllData:
    """Story 5.3 — anomalies_only=false pour CSV."""

    def test_all_data_returns_200_with_all_packets(self, client, monkeypatch):
        store = get_anomaly_store()
        store.store(_make_collection("cap_all", count=1))

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: "fake.pcap",
        )
        monkeypatch.setattr(
            "app.core.capture.packet_parser.parse_capture_file",
            lambda path: (_mock_packets(), None),
        )

        response = client.get("/api/exports/csv?capture_id=cap_all&anomalies_only=false")

        assert response.status_code == 200
        body = response.data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(body[1:])))
        assert len(rows) == 3  # header + 2 packets

    def test_all_data_filename_contains_all_data(self, client, monkeypatch):
        store = get_anomaly_store()
        store.store(_make_collection("cap_fn", count=1))

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: "fake.pcap",
        )
        monkeypatch.setattr(
            "app.core.capture.packet_parser.parse_capture_file",
            lambda path: (_mock_packets(), None),
        )

        response = client.get("/api/exports/csv?capture_id=cap_fn&anomalies_only=false")
        disposition = response.headers.get("Content-Disposition", "")
        match = re.search(r'filename="([^"]+)"', disposition)
        assert match is not None
        assert FILENAME_PATTERN_ALL_DATA_CSV.match(match.group(1))

    def test_all_data_pcap_not_found_returns_404(self, client, monkeypatch):
        store = get_anomaly_store()
        store.store(_make_collection("cap_nopcap", count=1))

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: None,
        )

        response = client.get("/api/exports/csv?capture_id=cap_nopcap&anomalies_only=false")
        assert response.status_code == 404
        data = response.get_json()
        assert data["error"]["code"] == "PCAP_NOT_FOUND"

    def test_x_anomaly_count_correct_in_all_data_mode(self, client, monkeypatch):
        store = get_anomaly_store()
        store.store(_make_collection("cap_xac", count=3))

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: "fake.pcap",
        )
        monkeypatch.setattr(
            "app.core.capture.packet_parser.parse_capture_file",
            lambda path: (_mock_packets(), None),
        )

        response = client.get("/api/exports/csv?capture_id=cap_xac&anomalies_only=false")
        assert response.headers.get("X-Anomaly-Count") == "3"


class TestExportsJsonAnomaliesOnlyRegression:
    """Story 5.3 — anomalies_only=true JSON identique au défaut."""

    def test_anomalies_only_true_same_as_default(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_jreg", count=2))

        resp_default = client.get("/api/exports/json?capture_id=cap_jreg")
        resp_explicit = client.get("/api/exports/json?capture_id=cap_jreg&anomalies_only=true")

        data_default = json.loads(resp_default.data)
        data_explicit = json.loads(resp_explicit.data)
        assert data_default["anomalies"] == data_explicit["anomalies"]
        assert data_default["metadata"]["anomaly_count"] == data_explicit["metadata"]["anomaly_count"]


class TestExportsJsonAnomaliesOnlyExportMode:
    """Story 5.3 — export_mode présent en mode anomalies-only."""

    def test_anomalies_only_has_export_mode_in_metadata(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_jmode_ao", count=1))

        response = client.get("/api/exports/json?capture_id=cap_jmode_ao&anomalies_only=true")
        data = json.loads(response.data)
        assert data["metadata"]["export_mode"] == "anomalies_only"

    def test_default_mode_has_export_mode_anomalies_only(self, client):
        store = get_anomaly_store()
        store.store(_make_collection("cap_jmode_def", count=1))

        response = client.get("/api/exports/json?capture_id=cap_jmode_def")
        data = json.loads(response.data)
        assert data["metadata"]["export_mode"] == "anomalies_only"


class TestExportsJsonAllData:
    """Story 5.3 — anomalies_only=false pour JSON."""

    def test_all_data_returns_200_with_packets_structure(self, client, monkeypatch):
        store = get_anomaly_store()
        store.store(_make_collection("cap_jall", count=1))

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: "fake.pcap",
        )
        monkeypatch.setattr(
            "app.core.capture.packet_parser.parse_capture_file",
            lambda path: (_mock_packets(), None),
        )

        response = client.get("/api/exports/json?capture_id=cap_jall&anomalies_only=false")

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "packets" in data
        assert data["metadata"]["export_mode"] == "all"
        assert data["metadata"]["total_packets"] == 2
        assert len(data["packets"]) == 2

    def test_all_data_filename_contains_all_data(self, client, monkeypatch):
        store = get_anomaly_store()
        store.store(_make_collection("cap_jfn", count=1))

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: "fake.pcap",
        )
        monkeypatch.setattr(
            "app.core.capture.packet_parser.parse_capture_file",
            lambda path: (_mock_packets(), None),
        )

        response = client.get("/api/exports/json?capture_id=cap_jfn&anomalies_only=false")
        disposition = response.headers.get("Content-Disposition", "")
        match = re.search(r'filename="([^"]+)"', disposition)
        assert match is not None
        assert FILENAME_PATTERN_ALL_DATA_JSON.match(match.group(1))

    def test_all_data_pcap_not_found_returns_404(self, client, monkeypatch):
        store = get_anomaly_store()
        store.store(_make_collection("cap_jnopcap", count=1))

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: None,
        )

        response = client.get("/api/exports/json?capture_id=cap_jnopcap&anomalies_only=false")
        assert response.status_code == 404
        data = response.get_json()
        assert data["error"]["code"] == "PCAP_NOT_FOUND"

    def test_export_mode_in_metadata(self, client, monkeypatch):
        store = get_anomaly_store()
        store.store(_make_collection("cap_jmode", count=1))

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: "fake.pcap",
        )
        monkeypatch.setattr(
            "app.core.capture.packet_parser.parse_capture_file",
            lambda path: (_mock_packets(), None),
        )

        response = client.get("/api/exports/json?capture_id=cap_jmode&anomalies_only=false")
        data = json.loads(response.data)
        assert data["metadata"]["export_mode"] == "all"
