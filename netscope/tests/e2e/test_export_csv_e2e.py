"""Tests E2E — Story 5.1 : Export CSV des anomalies.

Scénario bout-en-bout sans mock : l'utilisateur charge la page Anomalies,
déclenche l'export CSV, et récupère un fichier téléchargeable nommé
conformément au pattern spécifié, dont le contenu est un CSV valide.

Le harness du projet utilise le test client Flask (cf. conftest.py + autres
tests e2e — pas de Playwright). On reproduit ici le parcours utilisateur :
1. GET /anomalies → 200 + bouton présent et désactivé par défaut (AC7)
2. Seed store → simule capture complète
3. GET /api/exports/csv → téléchargement simulé, vérifications (AC1, AC5)
"""

from __future__ import annotations

import csv
import io
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

FILENAME_PATTERN = re.compile(
    r'^netscope-anomalies-(?P<cap>[A-Za-z0-9_\-]+)-\d{8}-\d{6}\.csv$'
)


@pytest.fixture(autouse=True)
def _reset_store():
    reset_anomaly_store()
    yield
    reset_anomaly_store()


def _seed_anomalies(capture_id: str = "cap_e2e_001", count: int = 3) -> None:
    """Remplit l'anomaly_store comme si une capture venait d'aboutir."""
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


class TestExportCsvE2E:
    """Parcours utilisateur bout-en-bout."""

    def test_anomalies_page_exposes_export_button(self, client):
        """AC7 — Le bouton est présent et désactivé par défaut."""
        response = client.get("/anomalies")
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, "html.parser")
        btn = soup.find(id="export-csv-btn")
        assert btn is not None, "Le bouton Export CSV doit être dans la page Anomalies"
        # État initial : désactivé, aria-disabled, tooltip explicatif
        assert btn.has_attr("disabled")
        assert btn.get("aria-disabled") == "true"
        assert "capture" in (btn.get("title") or "").lower()

    def test_end_to_end_capture_then_export_downloads_csv(self, client):
        """AC1 + AC5 : après capture, l'export produit un CSV téléchargeable."""
        _seed_anomalies(capture_id="cap_e2e_001", count=3)

        # Déclenchement de l'export comme le ferait le navigateur après clic.
        response = client.get("/api/exports/csv?capture_id=cap_e2e_001")

        assert response.status_code == 200
        assert response.mimetype == "text/csv"

        # Nom de fichier conforme au pattern (AC1)
        disposition = response.headers.get("Content-Disposition", "")
        match = re.search(r'filename="([^"]+)"', disposition)
        assert match is not None, f"Content-Disposition invalide: {disposition}"
        filename = match.group(1)
        assert FILENAME_PATTERN.match(filename), f"filename invalide: {filename}"

        # Contenu CSV parsable (AC5) — simule le parcours Google Sheets / Excel
        body = response.data.decode("utf-8")
        assert body.startswith("\ufeff"), "BOM UTF-8 obligatoire pour Excel"
        rows = list(csv.reader(io.StringIO(body[1:])))
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
        # Toutes les lignes ont le bon nombre de colonnes (aucun décalage tableur)
        for row in rows[1:]:
            assert len(row) == 9
        # 3 lignes de données
        assert len(rows) == 1 + 3

    def test_export_without_capture_returns_header_only_csv(self, client):
        """AC6 — État vide : header seul, pas de 500."""
        response = client.get("/api/exports/csv")

        assert response.status_code == 200
        body = response.data.decode("utf-8")
        rows = list(csv.reader(io.StringIO(body[1:])))
        assert len(rows) == 1  # header seul
        assert response.headers.get("X-Anomaly-Count") == "0"
