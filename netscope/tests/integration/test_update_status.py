"""Integration tests for update status and history API (Story 5.9).

Tests cover: /api/update/history endpoint, enriched /api/update/status,
error handling, auto-resume logic.
"""

import json
from unittest.mock import patch, MagicMock

import pytest

from app.services.update_service import (
    UpdateService,
    UpdateState,
    UpdateStatus,
    UpdateErrorCode,
    reset_update_service,
)


class TestHistoryEndpoint:
    def test_get_history_empty(self, client):
        with patch.object(UpdateService, 'get_update_history', return_value=[]):
            response = client.get('/api/update/history')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['history'] == []

    def test_get_history_with_entries(self, client):
        entries = [
            {
                "date": "2026-05-09T14:30:00Z",
                "from_version": "1.2.0",
                "to_version": "1.3.0",
                "status": "done",
                "error": None,
                "duration_seconds": 45,
            },
            {
                "date": "2026-05-08T10:00:00Z",
                "from_version": "1.1.0",
                "to_version": "1.2.0",
                "status": "error",
                "error": "Connexion perdue",
                "duration_seconds": 12,
            },
        ]
        with patch.object(UpdateService, 'get_update_history', return_value=entries):
            response = client.get('/api/update/history')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert len(data['history']) == 2
        assert data['history'][0]['status'] == 'done'

    def test_get_history_read_error(self, client):
        with patch.object(UpdateService, 'get_update_history', side_effect=OSError("disk error")):
            response = client.get('/api/update/history')
        assert response.status_code == 500
        data = response.get_json()
        assert data['success'] is False
        assert data['error_code'] == 'UPDATE_HISTORY_READ_ERROR'

    def test_get_history_returns_json(self, client):
        with patch.object(UpdateService, 'get_update_history', return_value=[]):
            response = client.get('/api/update/history')
        assert response.content_type.startswith('application/json')

    def test_get_history_post_not_allowed(self, client):
        response = client.post('/api/update/history')
        assert response.status_code == 405


class TestEnrichedStatusEndpoint:
    def test_status_idle_minimal_fields(self, client):
        response = client.get('/api/update/status')
        assert response.status_code == 200
        data = response.get_json()
        assert data['state'] == 'idle'
        assert 'target_version' not in data
        assert 'from_version' not in data

    def test_status_with_enriched_fields(self, client):
        enriched = UpdateStatus(
            state=UpdateState.DOWNLOADING,
            progress_percent=42,
            current_step="Téléchargement...",
            target_version="2.0.0",
            from_version="1.5.0",
            started_at="2026-05-09T14:00:00Z",
        )
        with patch.object(UpdateService, 'get_update_status', return_value=enriched):
            response = client.get('/api/update/status')
        data = response.get_json()
        assert data['target_version'] == '2.0.0'
        assert data['from_version'] == '1.5.0'
        assert data['started_at'] == '2026-05-09T14:00:00Z'
        assert 'duration_seconds' in data

    def test_status_done_shows_all_fields(self, client):
        done = UpdateStatus(
            state=UpdateState.DONE,
            progress_percent=100,
            current_step="Mise à jour réussie",
            target_version="2.0.0",
            from_version="1.5.0",
            started_at="2026-05-09T14:00:00Z",
        )
        with patch.object(UpdateService, 'get_update_status', return_value=done):
            response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'done'
        assert data['target_version'] == '2.0.0'

    def test_status_error_with_error_fields(self, client):
        error = UpdateStatus(
            state=UpdateState.ERROR,
            error="Timeout",
            error_code=UpdateErrorCode.DOWNLOAD_ERROR,
        )
        with patch.object(UpdateService, 'get_update_status', return_value=error):
            response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'error'
        assert data['error'] == 'Timeout'
        assert data['error_code'] == 'DOWNLOAD_ERROR'


class TestAutoResumeLogic:
    def test_status_active_update_returns_state(self, client):
        active = UpdateStatus(
            state=UpdateState.EXTRACTING,
            progress_percent=60,
            current_step="Extraction...",
            target_version="2.0.0",
            from_version="1.5.0",
            started_at="2026-05-09T14:00:00Z",
        )
        with patch.object(UpdateService, 'get_update_status', return_value=active):
            response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'extracting'
        assert data['progress_percent'] == 60
        assert data['target_version'] == '2.0.0'

    def test_status_terminal_rolled_back(self, client):
        rb = UpdateStatus(
            state=UpdateState.ROLLED_BACK,
            progress_percent=100,
            current_step="Version restaurée",
            from_version="1.5.0",
            target_version="2.0.0",
            error="Health check échoué",
        )
        with patch.object(UpdateService, 'get_update_status', return_value=rb):
            response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'rolled_back'
        assert data['error'] == 'Health check échoué'
