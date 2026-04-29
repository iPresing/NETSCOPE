"""Tests E2E — Story 5.2 : Export JSON des anomalies.

Scénario bout-en-bout sans mock : l'utilisateur charge la page Anomalies,
déclenche l'export JSON, et récupère un fichier téléchargeable nommé
conformément au pattern spécifié, dont le contenu est un JSON valide.

Parcours utilisateur :
1. GET /anomalies → 200 + bouton JSON présent et désactivé par défaut (AC7)
2. Seed store → simule capture complète
3. GET /api/exports/json → téléchargement simulé, vérifications (AC1, AC5)
"""

from __future__ import annotations

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

FILENAME_PATTERN_JSON = re.compile(
    r'^netscope-anomalies-(?P<cap>[A-Za-z0-9_\-]+)-\d{8}-\d{6}\.json$'
)


@pytest.fixture(autouse=True)
def _reset_store():
    reset_anomaly_store()
    yield
    reset_anomaly_store()


def _seed_anomalies(capture_id: str = "cap_e2e_json", count: int = 3) -> None:
    store = get_anomaly_store()
    anomalies = []
    for i in range(count):
        match = BlacklistMatch(
            match_type=MatchType.IP if i % 2 == 0 else MatchType.DOMAIN,
            matched_value=("1.2.3." + str(i + 10)) if i % 2 == 0 else f"evil{i}.example",
            source_file="e2e.txt",
            context=f"Contexte E2E anomalie {i}",
            criticality=CriticalityLevel.CRITICAL,
            timestamp=datetime(2026, 4, 18, 9, 15, i),
        )
        anomalies.append(
            Anomaly(
                id=f"anomaly_e2e_{i:03d}",
                match=match,
                score=80 + i,
                packet_info={
                    "timestamp": f"2026-04-18T09:15:{i:02d}+00:00",
                    "ip_src": "192.168.1.42",
                    "ip_dst": f"10.0.0.{i + 1}",
                    "port_src": 55000 + i,
                    "port_dst": 443,
                    "protocol": "TCP",
                },
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id=capture_id,
            )
        )
    store.store(AnomalyCollection(anomalies=anomalies, capture_id=capture_id))


class TestExportJsonE2E:
    """Parcours utilisateur bout-en-bout JSON."""

    def test_anomalies_page_exposes_json_export_button(self, client):
        """AC7 — Le bouton JSON est présent et désactivé par défaut."""
        response = client.get("/anomalies")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")
        btn = soup.find(id="export-json-btn")
        assert btn is not None, "Le bouton Export JSON doit être dans la page Anomalies"
        assert btn.has_attr("disabled")
        assert btn.get("aria-disabled") == "true"
        assert "capture" in (btn.get("title") or "").lower()

    def test_end_to_end_capture_then_export_downloads_json(self, client):
        """AC1 + AC5 : après capture, l'export produit un JSON téléchargeable."""
        _seed_anomalies(capture_id="cap_e2e_json", count=3)

        response = client.get("/api/exports/json?capture_id=cap_e2e_json")

        assert response.status_code == 200
        assert response.mimetype == "application/json"

        disposition = response.headers.get("Content-Disposition", "")
        match = re.search(r'filename="([^"]+)"', disposition)
        assert match is not None, f"Content-Disposition invalide: {disposition}"
        filename = match.group(1)
        assert FILENAME_PATTERN_JSON.match(filename), f"filename invalide: {filename}"

        data = json.loads(response.data.decode("utf-8"))
        assert "metadata" in data
        assert "anomalies" in data
        assert data["metadata"]["anomaly_count"] == 3
        assert len(data["anomalies"]) == 3

        for entry in data["anomalies"]:
            assert "id" in entry
            assert "timestamp" in entry
            assert "ip_src" in entry
            assert "ip_dst" in entry
            assert "score" in entry
            assert "blacklist_match" in entry
            assert "reason" in entry
            assert isinstance(entry["port_src"], int)
            assert isinstance(entry["port_dst"], int)

    def test_bi_compatibility_anomalies_list_of_homogeneous_dicts(self, client):
        """AC5 — anomalies est une liste de dicts avec clés cohérentes."""
        _seed_anomalies(capture_id="cap_bi", count=5)

        response = client.get("/api/exports/json?capture_id=cap_bi")
        data = json.loads(response.data.decode("utf-8"))
        anomalies = data["anomalies"]

        assert len(anomalies) == 5
        keys_ref = set(anomalies[0].keys())
        for entry in anomalies[1:]:
            assert set(entry.keys()) == keys_ref

    def test_export_without_capture_returns_empty_json(self, client):
        """AC6 — État vide : anomalies vides, pas de 500."""
        response = client.get("/api/exports/json")

        assert response.status_code == 200
        data = json.loads(response.data.decode("utf-8"))
        assert data["anomalies"] == []
        assert data["metadata"]["anomaly_count"] == 0
        assert response.headers.get("X-Anomaly-Count") == "0"
