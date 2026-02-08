"""E2E tests for Whitelist Management (Story 3.6, Task 11).

Tests cover:
- AC1-AC3: Page whitelist accessible, add/list/delete workflow
- AC5: Quick-whitelist button functionality (API level)
- AC4: Persistence after reload
"""

import json
from pathlib import Path
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
    """Create WhitelistManager with temp file."""
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


class TestWhitelistPageAccess:
    """Tests for whitelist page access."""

    def test_whitelist_page_accessible(self, client):
        """Page /whitelist renders correctly."""
        response = client.get('/whitelist')
        assert response.status_code == 200
        html = response.data.decode('utf-8')
        assert 'Gestion Whitelist' in html
        assert 'whitelist-add-form' in html
        assert 'whitelist-table' in html

    def test_whitelist_page_shows_empty_table(self, client):
        """Page shows table structure even when empty."""
        response = client.get('/whitelist')
        html = response.data.decode('utf-8')
        assert 'whitelist-tbody' in html
        assert 'wl-value' in html


class TestWhitelistFullWorkflow:
    """Tests for full CRUD workflow via API."""

    def test_add_then_list_then_delete(self, wl_client):
        """Full workflow: add -> verify in list -> delete -> verify removed."""
        # Add an IP
        add_response = wl_client.post(
            '/api/whitelist',
            json={"value": "192.168.1.100", "reason": "Test E2E"},
        )
        assert add_response.status_code == 201
        entry_id = add_response.get_json()['result']['id']

        # Verify in list
        list_response = wl_client.get('/api/whitelist')
        data = list_response.get_json()
        assert data['result']['count'] == 1
        assert data['result']['entries'][0]['value'] == "192.168.1.100"
        assert data['result']['entries'][0]['reason'] == "Test E2E"

        # Delete
        del_response = wl_client.delete(f'/api/whitelist/{entry_id}')
        assert del_response.status_code == 200

        # Verify removed
        list_response2 = wl_client.get('/api/whitelist')
        data2 = list_response2.get_json()
        assert data2['result']['count'] == 0

    def test_add_ip_shows_in_table(self, wl_client):
        """Adding IP via API shows correct type and value."""
        response = wl_client.post(
            '/api/whitelist',
            json={"value": "10.0.0.1"},
        )
        data = response.get_json()
        assert data['result']['entry_type'] == 'ip'
        assert data['result']['value'] == '10.0.0.1'

    def test_add_port_shows_in_table(self, wl_client):
        """Adding port via API shows correct type."""
        response = wl_client.post(
            '/api/whitelist',
            json={"value": "443"},
        )
        data = response.get_json()
        assert data['result']['entry_type'] == 'port'

    def test_add_ip_port_shows_in_table(self, wl_client):
        """Adding IP:Port via API shows correct type."""
        response = wl_client.post(
            '/api/whitelist',
            json={"value": "10.0.0.1:8080"},
        )
        data = response.get_json()
        assert data['result']['entry_type'] == 'ip_port'


class TestQuickWhitelist:
    """Tests for quick-whitelist from anomaly (AC5)."""

    def test_quick_whitelist_adds_entry(self, wl_client):
        """Quick-whitelist adds entry with auto-generated reason."""
        response = wl_client.post(
            '/api/whitelist',
            json={
                "value": "10.0.0.99:443",
                "reason": "Quick-whitelist depuis anomalie",
            },
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data['result']['value'] == "10.0.0.99:443"
        assert data['result']['reason'] == "Quick-whitelist depuis anomalie"


class TestWhitelistPersistence:
    """Tests for persistence after reload (AC4)."""

    def test_persistence_after_reload(self, tmp_path):
        """Entries persist in JSON file across manager instances."""
        wl_file = tmp_path / "whitelist.json"
        wl_file.write_text(
            json.dumps({"entries": [], "version": "1.0", "last_updated": None}),
            encoding="utf-8",
        )

        # Add entries with first manager
        manager1 = WhitelistManager(wl_file)
        manager1.add("192.168.1.1", "Persistent test")
        manager1.add("8080")

        # Create new manager (simulates app restart)
        manager2 = WhitelistManager(wl_file)
        entries = manager2.get_all()
        assert len(entries) == 2
        assert entries[0].value == "192.168.1.1"
        assert entries[0].reason == "Persistent test"
        assert entries[1].value == "8080"
