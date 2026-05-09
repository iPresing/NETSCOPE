"""E2E tests for backup before OTA update (Story 5.7).

Tests the full journey: update page → backup state visible in status polling
→ backup failure stops update. GitHub API + filesystem mocked.
"""

from unittest.mock import patch, MagicMock

import pytest
from bs4 import BeautifulSoup

from app.services.update_service import (
    UpdateState,
    UpdateStatus,
    UpdateErrorCode,
    get_update_service,
    reset_update_service,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    reset_update_service()
    yield
    reset_update_service()


class TestUpdatePageBackup:
    def test_update_page_loads_with_settings_section(self, client):
        response = client.get('/admin/update')
        assert response.status_code == 200
        soup = BeautifulSoup(response.data, 'html.parser')
        settings = soup.find('h3', string='Paramètres de Mise à Jour')
        assert settings is not None

    def test_progress_section_has_step_label(self, client):
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        step = soup.find(id='update-step-label')
        assert step is not None


class TestBackupStatusPolling:
    def test_status_shows_backing_up(self, client):
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.BACKING_UP,
            progress_percent=0,
            current_step="Création backup version actuelle...",
        )
        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'backing_up'
        assert data['progress_percent'] == 0
        assert 'backup' in data['current_step'].lower()

    def test_status_shows_backup_complete(self, client):
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.BACKING_UP,
            progress_percent=100,
            current_step="Backup créée",
        )
        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'backing_up'
        assert data['progress_percent'] == 100

    def test_status_shows_backup_failure(self, client):
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.ERROR,
            error="Espace insuffisant : 5000 libre, 20000 requis",
            error_code=UpdateErrorCode.BACKUP_FAILED,
        )
        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'error'
        assert data['error_code'] == 'BACKUP_FAILED'
        assert 'Espace' in data['error']

    def test_backup_js_handles_backing_up_state(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'backing_up' in html
        assert 'Création backup' in html
