"""Integration tests for Whitelist API (Story 3.6, Task 3 + Task 10).

Tests cover:
- AC1: POST /api/whitelist adds IP, Port, IP:Port
- AC2: GET /api/whitelist lists entries
- AC3: DELETE /api/whitelist/<id> removes entry
- AC5: Score recalculation after whitelist change
- Error codes: WHITELIST_DUPLICATE, WHITELIST_INVALID_VALUE, WHITELIST_NOT_FOUND
"""

import json
from unittest.mock import patch

import pytest

from app.services.whitelist_manager import WhitelistManager, reset_whitelist_manager


@pytest.fixture(autouse=True)
def reset_wl():
    """Reset whitelist singleton before/after each test."""
    reset_whitelist_manager()
    yield
    reset_whitelist_manager()


@pytest.fixture
def wl_manager(tmp_path):
    """Create a WhitelistManager with temp file."""
    wl_file = tmp_path / "whitelist.json"
    wl_file.write_text(
        json.dumps({"entries": [], "version": "1.0", "last_updated": None}),
        encoding="utf-8",
    )
    return WhitelistManager(wl_file)


@pytest.fixture
def wl_client(client, wl_manager):
    """Client with patched whitelist manager."""
    with patch(
        'app.blueprints.api.whitelist.get_whitelist_manager',
        return_value=wl_manager,
    ):
        yield client


class TestWhitelistAPIGet:
    """Tests for GET /api/whitelist."""

    def test_list_empty(self, wl_client):
        """AC2: Returns empty list initially."""
        response = wl_client.get('/api/whitelist')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['entries'] == []
        assert data['result']['count'] == 0

    def test_list_with_entries(self, wl_client, wl_manager):
        """AC2: Returns all entries."""
        wl_manager.add("192.168.1.100", "Test IP")
        wl_manager.add("8080", "Test Port")

        response = wl_client.get('/api/whitelist')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['count'] == 2
        assert len(data['result']['entries']) == 2


class TestWhitelistAPIPost:
    """Tests for POST /api/whitelist."""

    def test_add_valid_ip(self, wl_client):
        """AC1: Adds valid IP."""
        response = wl_client.post(
            '/api/whitelist',
            json={"value": "192.168.1.100", "reason": "Serveur local"},
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['value'] == "192.168.1.100"
        assert data['result']['entry_type'] == "ip"
        assert data['result']['reason'] == "Serveur local"

    def test_add_valid_port(self, wl_client):
        """AC1: Adds valid port."""
        response = wl_client.post(
            '/api/whitelist',
            json={"value": "8080"},
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['entry_type'] == "port"

    def test_add_valid_ip_port(self, wl_client):
        """AC1: Adds valid IP:Port."""
        response = wl_client.post(
            '/api/whitelist',
            json={"value": "192.168.1.100:8080"},
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['entry_type'] == "ip_port"

    def test_add_invalid_value_returns_400(self, wl_client):
        """Rejects invalid value with 400."""
        response = wl_client.post(
            '/api/whitelist',
            json={"value": "not-valid"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert data['error']['code'] == "WHITELIST_INVALID_VALUE"

    def test_add_duplicate_returns_409(self, wl_client):
        """Rejects duplicate with 409."""
        wl_client.post('/api/whitelist', json={"value": "192.168.1.100"})
        response = wl_client.post(
            '/api/whitelist',
            json={"value": "192.168.1.100"},
        )
        assert response.status_code == 409
        data = response.get_json()
        assert data['success'] is False
        assert data['error']['code'] == "WHITELIST_DUPLICATE"

    def test_add_missing_value_returns_400(self, wl_client):
        """Rejects request without value field."""
        response = wl_client.post(
            '/api/whitelist',
            json={"reason": "Missing value"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data['error']['code'] == "WHITELIST_INVALID_VALUE"

    def test_add_no_body_returns_400(self, wl_client):
        """Rejects request without body."""
        response = wl_client.post('/api/whitelist')
        assert response.status_code == 400


class TestWhitelistAPIDelete:
    """Tests for DELETE /api/whitelist/<id>."""

    def test_delete_existing_entry(self, wl_client, wl_manager):
        """AC3: Deletes existing entry."""
        entry = wl_manager.add("192.168.1.100")

        response = wl_client.delete(f'/api/whitelist/{entry.id}')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['value'] == "192.168.1.100"

    def test_delete_nonexistent_returns_404(self, wl_client):
        """Returns 404 for unknown ID."""
        response = wl_client.delete('/api/whitelist/wl_nonexistent')
        assert response.status_code == 404
        data = response.get_json()
        assert data['success'] is False
        assert data['error']['code'] == "WHITELIST_NOT_FOUND"

    def test_delete_then_list_is_empty(self, wl_client, wl_manager):
        """After delete, entry no longer in list."""
        entry = wl_manager.add("192.168.1.100")

        wl_client.delete(f'/api/whitelist/{entry.id}')

        response = wl_client.get('/api/whitelist')
        data = response.get_json()
        assert data['result']['count'] == 0


class TestWhitelistHealthScoreIntegration:
    """Tests for health score recalculation with whitelist (AC5)."""

    def test_score_recalculated_after_whitelist_add(self, client):
        """AC5: Health score recalculated after adding to whitelist."""
        from unittest.mock import Mock, patch
        from app.models.anomaly import (
            AnomalyCollection, Anomaly, BlacklistMatch,
            MatchType, CriticalityLevel,
        )

        mock_session = Mock()
        mock_session.id = 'test_capture_wl'
        mock_result = Mock()
        mock_result.session = mock_session

        # Create anomaly with known IP
        anomalies = [
            Anomaly(
                id='anomaly_wl_1',
                match=BlacklistMatch(
                    match_type=MatchType.IP,
                    matched_value='10.0.0.99',
                    source_file='test.txt',
                    context='Test',
                    criticality=CriticalityLevel.CRITICAL,
                ),
                score=90,
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id='test_capture_wl',
                packet_info={'ip_src': '10.0.0.99', 'port_dst': 80},
            ),
        ]
        anomaly_collection = AnomalyCollection(
            capture_id='test_capture_wl',
            anomalies=anomalies,
        )

        import json
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            wl_file = Path(tmp) / "whitelist.json"
            wl_file.write_text(
                json.dumps({"entries": [], "version": "1.0", "last_updated": None}),
                encoding="utf-8",
            )

            from app.services.whitelist_manager import WhitelistManager
            manager = WhitelistManager(wl_file)

            with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_mgr, \
                 patch('app.blueprints.api.health.get_anomaly_store') as mock_store, \
                 patch('app.blueprints.api.health.get_whitelist_manager', return_value=manager):

                mock_mgr.return_value.get_latest_result.return_value = mock_result
                mock_store.return_value.get_by_capture.return_value = anomaly_collection

                # Score without whitelist: 1 critical = 100-15 = 85
                response = client.get('/api/health/score')
                data = response.get_json()
                assert data['data']['displayed_score'] == 85
                assert data['data']['whitelist_hits'] == 0

                # Add IP to whitelist
                manager.add('10.0.0.99')

                # Score with whitelist: anomaly excluded = 100
                response2 = client.get('/api/health/score')
                data2 = response2.get_json()
                assert data2['data']['displayed_score'] == 100
                assert data2['data']['whitelist_hits'] == 1

                # Remove from whitelist
                entries = manager.get_all()
                assert len(entries) == 1
                manager.remove(entries[0].id)

                # Score after removal: anomaly included again = 85
                response3 = client.get('/api/health/score')
                data3 = response3.get_json()
                assert data3['data']['displayed_score'] == 85
                assert data3['data']['whitelist_hits'] == 0
