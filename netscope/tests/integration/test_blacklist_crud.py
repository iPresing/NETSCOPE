"""Tests intégration API CRUD blacklist user (Story 4b.6)."""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.services.blacklist_user_manager import (
    BlacklistUserManager,
    reset_blacklist_user_manager,
)


@pytest.fixture(autouse=True)
def _reset():
    yield
    reset_blacklist_user_manager()


@pytest.fixture
def bl_manager(app, tmp_path):
    """Fournit un BlacklistUserManager avec fichier temporaire."""
    filepath = tmp_path / "user_blacklist.json"
    mgr = BlacklistUserManager(filepath)

    with patch(
        "app.blueprints.api.blacklists.get_blacklist_user_manager",
        return_value=mgr,
    ), patch(
        "app.core.detection.blacklist_manager.get_blacklist_manager",
    ) as mock_bl:
        mock_bl.return_value = MagicMock(
            check_ip=MagicMock(return_value=False),
            check_domain=MagicMock(return_value=False),
            terms=frozenset(),
            merge_user_entries=MagicMock(),
        )
        yield mgr


# =========================================================================
# GET /api/blacklists/user
# =========================================================================

class TestListUserBlacklists:
    """Tests GET /api/blacklists/user."""

    def test_list_empty(self, client, bl_manager):
        resp = client.get("/api/blacklists/user")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["result"]["entries"] == []
        assert data["result"]["count"] == 0

    def test_list_with_entries(self, client, bl_manager):
        bl_manager.add("1.2.3.4", reason="Test")
        resp = client.get("/api/blacklists/user")
        data = resp.get_json()
        assert data["result"]["count"] == 1
        assert data["result"]["entries"][0]["value"] == "1.2.3.4"


# =========================================================================
# POST /api/blacklists
# =========================================================================

class TestAddUserBlacklist:
    """Tests POST /api/blacklists."""

    def test_add_ip_success(self, client, bl_manager):
        resp = client.post(
            "/api/blacklists",
            json={"value": "192.168.1.100", "type": "ip", "reason": "Suspect"},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["success"] is True
        assert data["result"]["value"] == "192.168.1.100"
        assert data["result"]["entry_type"] == "ip"
        assert data["result"]["reason"] == "Suspect"
        assert data["result"]["id"].startswith("bl_")

    def test_add_domain_success(self, client, bl_manager):
        resp = client.post(
            "/api/blacklists",
            json={"value": "evil.com", "type": "domain"},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["result"]["entry_type"] == "domain"

    def test_add_term_success(self, client, bl_manager):
        resp = client.post(
            "/api/blacklists",
            json={"value": "malware payload", "type": "term"},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["result"]["entry_type"] == "term"

    def test_add_auto_detect_type(self, client, bl_manager):
        resp = client.post(
            "/api/blacklists",
            json={"value": "10.0.0.1"},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["result"]["entry_type"] == "ip"

    def test_add_empty_value_rejected(self, client, bl_manager):
        resp = client.post("/api/blacklists", json={"value": ""})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "BLACKLIST_INVALID_VALUE"

    def test_add_no_body_rejected(self, client, bl_manager):
        resp = client.post(
            "/api/blacklists",
            content_type="application/json",
            data="not json",
        )
        assert resp.status_code == 400

    def test_add_invalid_type_rejected(self, client, bl_manager):
        resp = client.post(
            "/api/blacklists",
            json={"value": "1.2.3.4", "type": "invalid_type"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"]["code"] == "BLACKLIST_INVALID_TYPE"

    def test_add_invalid_ip_rejected(self, client, bl_manager):
        resp = client.post(
            "/api/blacklists",
            json={"value": "999.999.999.999", "type": "ip"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"]["code"] == "BLACKLIST_INVALID_VALUE"

    def test_add_duplicate_rejected(self, client, bl_manager):
        client.post("/api/blacklists", json={"value": "1.2.3.4", "type": "ip"})
        resp = client.post("/api/blacklists", json={"value": "1.2.3.4", "type": "ip"})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"]["code"] == "BLACKLIST_DUPLICATE"

    def test_add_with_reason(self, client, bl_manager):
        resp = client.post(
            "/api/blacklists",
            json={"value": "evil.com", "type": "domain", "reason": "Phishing"},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["result"]["reason"] == "Phishing"


# =========================================================================
# DELETE /api/blacklists/<entry_id>
# =========================================================================

class TestDeleteUserBlacklist:
    """Tests DELETE /api/blacklists/<entry_id>."""

    def test_delete_success(self, client, bl_manager):
        entry = bl_manager.add("1.2.3.4")
        resp = client.delete(f"/api/blacklists/{entry.id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["result"]["value"] == "1.2.3.4"

    def test_delete_not_found(self, client, bl_manager):
        resp = client.delete("/api/blacklists/bl_nonexist")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error"]["code"] == "BLACKLIST_NOT_FOUND"

    def test_delete_default_entry_rejected(self, client, bl_manager):
        resp = client.delete("/api/blacklists/default_entry_123")
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"]["code"] == "BLACKLIST_DEFAULT_READONLY"

    def test_delete_then_list_empty(self, client, bl_manager):
        entry = bl_manager.add("1.2.3.4")
        client.delete(f"/api/blacklists/{entry.id}")
        resp = client.get("/api/blacklists/user")
        data = resp.get_json()
        assert data["result"]["count"] == 0


# =========================================================================
# Existing endpoints still work (regression)
# =========================================================================

class TestBlacklistStatsRegression:
    """Tests régression des endpoints existants."""

    def test_stats_endpoint_still_works(self, client):
        resp = client.get("/api/blacklists/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "result" in data

    def test_active_endpoint_still_works(self, client):
        resp = client.get("/api/blacklists/active")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True


# =========================================================================
# Route /blacklist accessible (AC1)
# =========================================================================

class TestBlacklistRoute:
    """Tests intégration route /blacklist (Story 4b.6, AC1)."""

    def test_blacklist_page_accessible(self, client):
        resp = client.get("/blacklist")
        assert resp.status_code == 200

    def test_blacklist_page_has_form(self, client):
        resp = client.get("/blacklist")
        html = resp.data.decode()
        assert 'id="blacklist-add-form"' in html
        assert 'id="bl-value"' in html
        assert 'id="bl-type"' in html

    def test_blacklist_page_has_table(self, client):
        resp = client.get("/blacklist")
        html = resp.data.decode()
        assert 'id="blacklist-table"' in html
        assert 'id="blacklist-tbody"' in html

    def test_blacklist_page_loads_js(self, client):
        resp = client.get("/blacklist")
        html = resp.data.decode()
        assert "blacklist.js" in html

    def test_blacklist_page_has_title(self, client):
        resp = client.get("/blacklist")
        html = resp.data.decode()
        assert "Gestion Blacklists" in html


# =========================================================================
# Navigation includes blacklist link (AC1)
# =========================================================================

class TestBlacklistNavigation:
    """Tests lien Blacklists dans la navigation."""

    def test_nav_blacklist_link_on_dashboard(self, client):
        resp = client.get("/")
        html = resp.data.decode()
        assert "/blacklist" in html
        assert "Blacklists" in html

    def test_nav_blacklist_link_on_anomalies(self, client):
        resp = client.get("/anomalies")
        html = resp.data.decode()
        assert "/blacklist" in html

    def test_nav_blacklist_link_on_jobs(self, client):
        resp = client.get("/jobs")
        html = resp.data.decode()
        assert "/blacklist" in html


# =========================================================================
# Parcours complet E2E : ajout → vérification → suppression (AC3, AC4)
# =========================================================================

class TestBlacklistFullCycle:
    """Tests parcours complet CRUD sans mocks sur le manager."""

    def test_full_cycle_add_list_delete(self, client, bl_manager):
        # 1. Ajouter une entrée IP
        resp = client.post(
            "/api/blacklists",
            json={"value": "10.20.30.40", "type": "ip", "reason": "C2 server"},
        )
        assert resp.status_code == 201
        entry_id = resp.get_json()["result"]["id"]

        # 2. Vérifier qu'elle apparaît dans la liste
        resp = client.get("/api/blacklists/user")
        data = resp.get_json()
        assert data["result"]["count"] == 1
        assert data["result"]["entries"][0]["value"] == "10.20.30.40"
        assert data["result"]["entries"][0]["reason"] == "C2 server"

        # 3. Supprimer l'entrée
        resp = client.delete(f"/api/blacklists/{entry_id}")
        assert resp.status_code == 200

        # 4. Vérifier la liste est vide
        resp = client.get("/api/blacklists/user")
        assert resp.get_json()["result"]["count"] == 0

    def test_full_cycle_multiple_types(self, client, bl_manager):
        # Ajouter IP + Domain + Term
        client.post("/api/blacklists", json={"value": "1.2.3.4", "type": "ip"})
        client.post("/api/blacklists", json={"value": "evil.org", "type": "domain"})
        client.post("/api/blacklists", json={"value": "ransomware", "type": "term"})

        resp = client.get("/api/blacklists/user")
        data = resp.get_json()
        assert data["result"]["count"] == 3

        types = {e["entry_type"] for e in data["result"]["entries"]}
        assert types == {"ip", "domain", "term"}


# =========================================================================
# Edge cases (AC3, AC4, AC6)
# =========================================================================

class TestBlacklistEdgeCases:
    """Tests edge cases."""

    def test_term_min_length(self, client, bl_manager):
        resp = client.post("/api/blacklists", json={"value": "ab", "type": "term"})
        assert resp.status_code == 201

    def test_term_max_length(self, client, bl_manager):
        resp = client.post("/api/blacklists", json={"value": "x" * 200, "type": "term"})
        assert resp.status_code == 201

    def test_term_too_short_rejected(self, client, bl_manager):
        resp = client.post("/api/blacklists", json={"value": "a", "type": "term"})
        assert resp.status_code == 400

    def test_term_too_long_rejected(self, client, bl_manager):
        resp = client.post("/api/blacklists", json={"value": "x" * 201, "type": "term"})
        assert resp.status_code == 400

    def test_whitespace_value_trimmed(self, client, bl_manager):
        resp = client.post("/api/blacklists", json={"value": "  10.0.0.1  ", "type": "ip"})
        assert resp.status_code == 201
        assert resp.get_json()["result"]["value"] == "10.0.0.1"

    def test_missing_value_key(self, client, bl_manager):
        resp = client.post("/api/blacklists", json={"type": "ip"})
        assert resp.status_code == 400


# =========================================================================
# AC5: Rechargement détection après CRUD — intégration sans mock manager
# =========================================================================

@pytest.fixture
def real_detection_setup(app, tmp_path):
    """Setup avec BlacklistUserManager et BlacklistManager réels (sans mock merge)."""
    from app.core.detection.blacklist_manager import (
        BlacklistManager,
        reset_blacklist_manager,
    )
    reset_blacklist_manager()

    bl_mgr = BlacklistManager()
    bl_mgr.load_blacklists({"defaults": {}})

    filepath = tmp_path / "user_blacklist_ac5.json"
    user_mgr = BlacklistUserManager(filepath)

    with patch(
        "app.blueprints.api.blacklists.get_blacklist_user_manager",
        return_value=user_mgr,
    ), patch(
        "app.core.detection.blacklist_manager.get_blacklist_manager",
        return_value=bl_mgr,
    ):
        yield {"user_mgr": user_mgr, "bl_mgr": bl_mgr}

    reset_blacklist_manager()


class TestBlacklistDetectionIntegration:
    """M2: Tests E2E AC5 — vérification que le BlacklistManager est mis à jour après CRUD."""

    def test_add_entry_activates_detection(self, client, real_detection_setup):
        """Après POST /api/blacklists, check_ip() doit retourner True."""
        bl_mgr = real_detection_setup["bl_mgr"]

        assert not bl_mgr.check_ip("11.22.33.44")

        resp = client.post("/api/blacklists", json={"value": "11.22.33.44", "type": "ip"})
        assert resp.status_code == 201

        assert bl_mgr.check_ip("11.22.33.44"), "Détection doit être active après ajout"

    def test_remove_entry_deactivates_detection(self, client, real_detection_setup):
        """Après DELETE, check_ip() doit retourner False — AC5 régression suppression."""
        bl_mgr = real_detection_setup["bl_mgr"]
        user_mgr = real_detection_setup["user_mgr"]

        entry = user_mgr.add("55.66.77.88", reason="test ac5")
        assert bl_mgr.check_ip("55.66.77.88"), "Détection activée après ajout"

        resp = client.delete(f"/api/blacklists/{entry.id}")
        assert resp.status_code == 200

        assert not bl_mgr.check_ip("55.66.77.88"), "Détection doit être désactivée après suppression (AC5)"

    def test_add_domain_activates_detection(self, client, real_detection_setup):
        """Après POST domaine, check_domain() doit retourner True."""
        bl_mgr = real_detection_setup["bl_mgr"]

        resp = client.post("/api/blacklists", json={"value": "ac5-evil.org", "type": "domain"})
        assert resp.status_code == 201

        assert bl_mgr.check_domain("ac5-evil.org"), "Détection domaine active après ajout"
