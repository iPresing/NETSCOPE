"""Tests E2E — Story 5.3 : Filtre Export Anomalies.

Scénarios bout-en-bout :
1. Export CSV anomalies-only → seules les anomalies dans le fichier
2. Export CSV all-data → paquets normaux + anomalies
3. Export JSON all-data → metadata.export_mode, total_packets, structure
4. Sélecteur désactivé sans capture (AC7)
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime

import pytest
from bs4 import BeautifulSoup

from app.core.detection.anomaly_store import get_anomaly_store, reset_anomaly_store
from app.models.anomaly import (
    Anomaly,
    AnomalyCollection,
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
)
from app.models.capture import PacketInfo


@pytest.fixture(autouse=True)
def _reset_store():
    reset_anomaly_store()
    yield
    reset_anomaly_store()


def _seed_anomalies(capture_id: str = "cap_e2e_filter", count: int = 2) -> None:
    store = get_anomaly_store()
    anomalies = []
    for i in range(count):
        match = BlacklistMatch(
            match_type=MatchType.IP,
            matched_value=f"1.2.3.{i + 10}",
            source_file="e2e.txt",
            context=f"Contexte E2E {i}",
            criticality=CriticalityLevel.CRITICAL,
            timestamp=datetime(2026, 5, 3, 12, 0, i),
        )
        anomalies.append(
            Anomaly(
                id=f"anomaly_filt_{i:03d}",
                match=match,
                score=80 + i,
                packet_info={
                    "timestamp": f"2026-05-03T12:00:{i:02d}+00:00",
                    "ip_src": "192.168.1.42",
                    "ip_dst": f"1.2.3.{i + 10}",
                    "port_src": 55000 + i,
                    "port_dst": 443,
                    "protocol": "TCP",
                },
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id=capture_id,
            )
        )
    store.store(AnomalyCollection(anomalies=anomalies, capture_id=capture_id))


def _mock_packets():
    return [
        PacketInfo(
            timestamp=datetime(2026, 5, 3, 12, 0, 0),
            ip_src="192.168.1.42", ip_dst="10.0.0.1",
            port_src=55500, port_dst=80, protocol="TCP", length=100,
        ),
        PacketInfo(
            timestamp=datetime(2026, 5, 3, 12, 0, 1),
            ip_src="192.168.1.42", ip_dst="1.2.3.10",
            port_src=55000, port_dst=443, protocol="TCP", length=200,
        ),
        PacketInfo(
            timestamp=datetime(2026, 5, 3, 12, 0, 2),
            ip_src="192.168.1.42", ip_dst="10.0.0.2",
            port_src=55501, port_dst=8080, protocol="TCP", length=150,
        ),
    ]


class TestExportFilterSelectDisabled:
    """AC7 — Sélecteur désactivé sans capture."""

    def test_export_mode_select_present_and_disabled(self, client):
        response = client.get("/anomalies")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")
        select = soup.find(id="export-mode")
        assert select is not None, "Le sélecteur export-mode doit être dans la page"
        assert select.has_attr("disabled")
        assert select.get("aria-disabled") == "true"

    def test_export_mode_has_two_options(self, client):
        response = client.get("/anomalies")
        soup = BeautifulSoup(response.data, "html.parser")
        select = soup.find(id="export-mode")
        options = select.find_all("option")
        assert len(options) == 2
        assert options[0]["value"] == "anomalies_only"
        assert options[1]["value"] == "all"
        assert options[0].has_attr("selected")


class TestExportCsvAnomaliesOnlyE2E:
    """Scénario 1 : export CSV anomalies-only."""

    def test_csv_anomalies_only_contains_only_anomalies(self, client):
        _seed_anomalies(count=2)

        response = client.get(
            "/api/exports/csv?capture_id=cap_e2e_filter&anomalies_only=true"
        )
        assert response.status_code == 200

        body = response.data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(body[1:])))
        assert len(rows) == 3  # header + 2 anomalies
        for row in rows[1:]:
            assert int(row[6]) > 0  # score > 0


class TestExportCsvAllDataE2E:
    """Scénario 2 : export CSV all-data."""

    def test_csv_all_data_contains_normal_and_anomaly_packets(self, client, monkeypatch):
        _seed_anomalies(count=1)

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: "fake.pcap",
        )
        monkeypatch.setattr(
            "app.core.capture.packet_parser.parse_capture_file",
            lambda path: (_mock_packets(), None),
        )

        response = client.get(
            "/api/exports/csv?capture_id=cap_e2e_filter&anomalies_only=false"
        )
        assert response.status_code == 200

        body = response.data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(body[1:])))
        assert len(rows) == 4  # header + 3 packets

        scores = [row[6] for row in rows[1:]]
        assert "0" in scores  # au moins un paquet normal
        assert any(int(s) > 0 for s in scores)  # au moins un paquet anomalie

        disposition = response.headers.get("Content-Disposition", "")
        assert "all-data" in disposition


class TestExportAllDataRealPcapE2E:
    """Scénario 5 : export all-data avec vrai pcap parser (règle retro Epic 4)."""

    def test_csv_all_data_with_real_pcap_parser(self, client, tmp_path, monkeypatch):
        scapy_all = pytest.importorskip("scapy.all")
        wrpcap = scapy_all.wrpcap
        Ether = scapy_all.Ether
        IP = scapy_all.IP
        TCP = scapy_all.TCP

        pkts = [
            Ether() / IP(src="192.168.1.42", dst="10.0.0.1") / TCP(sport=55500, dport=80),
            Ether() / IP(src="192.168.1.42", dst="1.2.3.10") / TCP(sport=55000, dport=443),
            Ether() / IP(src="192.168.1.42", dst="10.0.0.2") / TCP(sport=55501, dport=8080),
        ]
        pcap_file = tmp_path / "cap_e2e_real.pcap"
        wrpcap(str(pcap_file), pkts)

        _seed_anomalies(capture_id="cap_e2e_real", count=1)

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: pcap_file,
        )

        response = client.get(
            "/api/exports/csv?capture_id=cap_e2e_real&anomalies_only=false"
        )
        assert response.status_code == 200

        body = response.data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(body[1:])))
        assert len(rows) >= 4  # header + 3 packets minimum

        scores = [row[6] for row in rows[1:]]
        assert "0" in scores
        assert any(int(s) > 0 for s in scores)


class TestExportJsonAllDataE2E:
    """Scénario 3 : export JSON all-data."""

    def test_json_all_data_metadata_and_structure(self, client, monkeypatch):
        _seed_anomalies(count=1)

        monkeypatch.setattr(
            "app.blueprints.api.exports.find_pcap_by_capture_id",
            lambda cid: "fake.pcap",
        )
        monkeypatch.setattr(
            "app.core.capture.packet_parser.parse_capture_file",
            lambda path: (_mock_packets(), None),
        )

        response = client.get(
            "/api/exports/json?capture_id=cap_e2e_filter&anomalies_only=false"
        )
        assert response.status_code == 200

        data = json.loads(response.data.decode("utf-8"))
        assert data["metadata"]["export_mode"] == "all"
        assert data["metadata"]["total_packets"] == 3
        assert data["metadata"]["anomaly_count"] >= 1
        assert len(data["packets"]) == 3

        normal_pkts = [p for p in data["packets"] if p["score"] == 0]
        anomaly_pkts = [p for p in data["packets"] if p["score"] > 0]
        assert len(normal_pkts) >= 1
        assert len(anomaly_pkts) >= 1

        disposition = response.headers.get("Content-Disposition", "")
        assert "all-data" in disposition
