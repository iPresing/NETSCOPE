"""Integration tests for update API routes (Story 5.6)."""

import time
from unittest.mock import patch, MagicMock

import pytest

from app.services.update_service import (
    UpdateService,
    UpdateState,
    UpdateStatus,
    UpdateErrorCode,
    reset_update_service,
)


class TestUpdateStatusEndpoint:
    def test_get_status_idle(self, client):
        response = client.get('/api/update/status')
        assert response.status_code == 200
        data = response.get_json()
        assert data['state'] == 'idle'
        assert data['progress_percent'] == 0

    def test_get_status_returns_json(self, client):
        response = client.get('/api/update/status')
        assert response.content_type.startswith('application/json')


class TestApplyUpdateEndpoint:
    @patch.object(UpdateService, 'start_update', return_value=True)
    def test_apply_starts_update(self, mock_start, client):
        response = client.post('/api/update/apply')
        assert response.status_code == 202
        data = response.get_json()
        assert data['started'] is True
        mock_start.assert_called_once()

    @patch.object(UpdateService, 'start_update', return_value=False)
    def test_apply_already_running(self, mock_start, client):
        response = client.post('/api/update/apply')
        assert response.status_code == 409
        data = response.get_json()
        assert data['started'] is False

    def test_apply_get_method_not_allowed(self, client):
        response = client.get('/api/update/apply')
        assert response.status_code == 405

    @patch.object(UpdateService, 'start_update', return_value=True)
    def test_apply_then_check_status(self, mock_start, client):
        client.post('/api/update/apply')
        response = client.get('/api/update/status')
        assert response.status_code == 200


class TestCheckUpdateEndpointRegression:
    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_check_still_works(self, mock_get, mock_version, client):
        mock_version.return_value.get_version.return_value = "0.1.0"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "tag_name": "v0.3.0",
            "body": "changes",
            "published_at": "2026-05-01",
            "html_url": "https://github.com/test",
            "tarball_url": "https://api.github.com/repos/test/tarball/v0.3.0",
        }
        mock_get.return_value = mock_resp

        response = client.get('/api/update/check')
        assert response.status_code == 200
        data = response.get_json()
        assert data['update_available'] is True


class TestStatusDuringUpdate:
    def test_status_reflects_error(self, client):
        from app.services.update_service import get_update_service

        service = get_update_service()
        service._update_status = UpdateStatus(
            state=UpdateState.ERROR,
            error="Test error",
            error_code=UpdateErrorCode.DOWNLOAD_ERROR,
        )

        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'error'
        assert data['error'] == 'Test error'
        assert data['error_code'] == 'DOWNLOAD_ERROR'

    def test_status_reflects_downloading(self, client):
        from app.services.update_service import get_update_service

        service = get_update_service()
        service._update_status = UpdateStatus(
            state=UpdateState.DOWNLOADING,
            progress_percent=42,
            current_step="Téléchargement en cours...",
        )

        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'downloading'
        assert data['progress_percent'] == 42
