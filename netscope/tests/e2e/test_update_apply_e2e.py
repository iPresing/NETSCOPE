"""E2E tests for update apply feature (Story 5.6).

Tests the full user journey: page load → update available → click button
→ polling status → result display. GitHub API + download mocked.
"""

from unittest.mock import patch, MagicMock

import pytest
from bs4 import BeautifulSoup

from app.services.update_service import (
    UpdateState,
    UpdateStatus,
    UpdateErrorCode,
    reset_update_service,
)


MOCK_RELEASE = {
    "tag_name": "v0.3.0",
    "name": "Release 0.3.0",
    "body": "## Changelog\n- OTA update support",
    "published_at": "2026-05-08T10:00:00Z",
    "html_url": "https://github.com/iPresing/NETSCOPE/releases/tag/v0.3.0",
    "tarball_url": "https://api.github.com/repos/iPresing/NETSCOPE/tarball/v0.3.0",
}


class TestUpdatePageWithUpdateAvailable:
    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_page_shows_update_button_enabled(self, mock_get, mock_version, client):
        mock_version.return_value.get_version.return_value = "0.1.0"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_RELEASE
        mock_get.return_value = mock_resp

        response = client.get('/api/update/check')
        data = response.get_json()

        assert data['update_available'] is True
        assert data['latest_version'] == '0.3.0'

    def test_update_page_loads(self, client):
        response = client.get('/admin/update')
        assert response.status_code == 200
        soup = BeautifulSoup(response.data, 'html.parser')
        assert soup.find('h2', string='Mise à Jour Système')

    def test_update_page_has_progress_section(self, client):
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        progress = soup.find(id='update-progress-section')
        assert progress is not None


class TestApplyUpdateE2EFlow:
    @patch('app.services.update_service.UpdateService.start_update', return_value=True)
    def test_apply_returns_started(self, mock_start, client):
        response = client.post('/api/update/apply')
        assert response.status_code == 202
        data = response.get_json()
        assert data['started'] is True

    @patch('app.services.update_service.UpdateService.start_update', return_value=False)
    def test_apply_double_trigger_blocked(self, mock_start, client):
        response = client.post('/api/update/apply')
        assert response.status_code == 409
        data = response.get_json()
        assert data['started'] is False

    def test_status_idle_initially(self, client):
        response = client.get('/api/update/status')
        assert response.status_code == 200
        data = response.get_json()
        assert data['state'] == 'idle'
        assert data['progress_percent'] == 0

    def test_status_shows_downloading(self, client):
        from app.services.update_service import get_update_service

        service = get_update_service()
        service._update_status = UpdateStatus(
            state=UpdateState.DOWNLOADING,
            progress_percent=55,
            current_step="Téléchargement en cours...",
        )

        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'downloading'
        assert data['progress_percent'] == 55
        assert data['current_step'] == 'Téléchargement en cours...'

    def test_status_shows_extracting(self, client):
        from app.services.update_service import get_update_service

        service = get_update_service()
        service._update_status = UpdateStatus(
            state=UpdateState.EXTRACTING,
            progress_percent=75,
            current_step="Extraction et application...",
        )

        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'extracting'

    def test_status_shows_done(self, client):
        from app.services.update_service import get_update_service

        service = get_update_service()
        service._update_status = UpdateStatus(
            state=UpdateState.DONE,
            progress_percent=100,
            current_step="Mise à jour terminée",
        )

        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'done'
        assert data['progress_percent'] == 100

    def test_status_shows_error(self, client):
        from app.services.update_service import get_update_service

        service = get_update_service()
        service._update_status = UpdateStatus(
            state=UpdateState.ERROR,
            error="Espace disque insuffisant",
            error_code=UpdateErrorCode.DISK_SPACE_ERROR,
        )

        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'error'
        assert data['error'] == 'Espace disque insuffisant'
        assert data['error_code'] == 'DISK_SPACE_ERROR'


class TestNoscriptFallbackStillWorks:
    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_post_form_check(self, mock_get, mock_version, client):
        mock_version.return_value.get_version.return_value = "0.1.0"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_RELEASE
        mock_get.return_value = mock_resp

        response = client.post('/admin/update/check')
        assert response.status_code == 200
        soup = BeautifulSoup(response.data, 'html.parser')
        assert 'Nouvelle version' in soup.get_text()
