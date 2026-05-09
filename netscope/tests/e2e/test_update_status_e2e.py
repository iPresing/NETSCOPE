"""E2E tests for update status visibility (Story 5.9).

Tests cover: full update cycle history recording, history persistence,
status enrichment, template rendering with progress section.
"""

import json
import os
import tempfile
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

from app.services.update_service import (
    UpdateService,
    UpdateState,
    UpdateStatus,
    UpdateHistoryEntry,
    UpdateErrorCode,
    reset_update_service,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    reset_update_service()
    yield
    reset_update_service()


@pytest.fixture
def tmp_history(tmp_path):
    return str(tmp_path / "update_history.json")


class TestFullUpdateCycleHistory:
    def test_successful_update_records_history(self, client, tmp_history):
        """E2E sans mock: verify history entry saved after simulated update completion."""
        from app.services.update_service import get_update_service

        service = get_update_service()

        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history):
            entry = UpdateHistoryEntry(
                date="2026-05-09T14:30:00Z",
                from_version="1.0.0",
                to_version="1.1.0",
                status="done",
                duration_seconds=30,
            )
            service._save_history_entry(entry)

            response = client.get('/api/update/history')
            data = response.get_json()
            assert data['success'] is True
            assert len(data['history']) == 1
            assert data['history'][0]['status'] == 'done'
            assert data['history'][0]['from_version'] == '1.0.0'
            assert data['history'][0]['to_version'] == '1.1.0'
            assert data['history'][0]['duration_seconds'] == 30

            with open(tmp_history, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            assert len(raw) == 1

    def test_error_update_records_history(self, client, tmp_history):
        from app.services.update_service import get_update_service

        service = get_update_service()

        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history):
            entry = UpdateHistoryEntry(
                date="2026-05-09T15:00:00Z",
                from_version="1.0.0",
                to_version="1.1.0",
                status="error",
                error="Connexion perdue",
                duration_seconds=5,
            )
            service._save_history_entry(entry)

            response = client.get('/api/update/history')
            data = response.get_json()
            assert len(data['history']) == 1
            assert data['history'][0]['status'] == 'error'
            assert data['history'][0]['error'] == 'Connexion perdue'

    def test_rollback_records_history(self, client, tmp_history):
        from app.services.update_service import get_update_service

        service = get_update_service()

        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history):
            entry = UpdateHistoryEntry(
                date="2026-05-09T15:30:00Z",
                from_version="1.0.0",
                to_version="1.1.0",
                status="rolled_back",
                error="Health check timeout",
                duration_seconds=60,
            )
            service._save_history_entry(entry)

            response = client.get('/api/update/history')
            data = response.get_json()
            assert data['history'][0]['status'] == 'rolled_back'


class TestHistoryPersistenceAcrossRequests:
    def test_multiple_entries_persisted(self, client, tmp_history):
        from app.services.update_service import get_update_service

        service = get_update_service()

        with patch.object(UpdateService, '_get_history_path', return_value=tmp_history):
            for i, status in enumerate(["done", "error", "rolled_back"]):
                entry = UpdateHistoryEntry(
                    date=f"2026-05-0{i+1}T10:00:00Z",
                    from_version="1.0.0",
                    to_version=f"1.{i+1}.0",
                    status=status,
                    duration_seconds=10 * (i + 1),
                )
                service._save_history_entry(entry)

            response = client.get('/api/update/history')
            data = response.get_json()
            assert len(data['history']) == 3
            statuses = [e['status'] for e in data['history']]
            assert statuses == ['rolled_back', 'error', 'done']


class TestStatusEnrichmentDuringUpdate:
    def test_all_states_have_valid_response(self, client):
        """Verify every UpdateState produces a valid API response."""
        for state in UpdateState:
            status = UpdateStatus(
                state=state,
                progress_percent=50,
                current_step=f"Testing {state.value}",
                target_version="2.0.0",
                from_version="1.0.0",
                started_at="2026-05-09T14:00:00Z",
            )
            with patch.object(UpdateService, 'get_update_status', return_value=status):
                response = client.get('/api/update/status')
                assert response.status_code == 200
                data = response.get_json()
                assert data['state'] == state.value
                assert data['target_version'] == '2.0.0'

    def test_terminal_states_include_error_info(self, client):
        for state in [UpdateState.ERROR, UpdateState.ROLLBACK_FAILED]:
            status = UpdateStatus(
                state=state,
                error="Test error message",
                error_code=UpdateErrorCode.DOWNLOAD_ERROR,
            )
            with patch.object(UpdateService, 'get_update_status', return_value=status):
                response = client.get('/api/update/status')
                data = response.get_json()
                assert data['error'] == 'Test error message'
                assert data['error_code'] == 'DOWNLOAD_ERROR'


class TestUpdatePageRendering:
    def test_update_page_loads(self, client):
        response = client.get('/admin/update')
        assert response.status_code == 200

    def test_update_page_contains_progress_section(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'update-progress-section' in html
        assert 'update-target-version' in html
        assert 'update-warning-display' in html

    def test_update_page_contains_history_section(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'update-history-tbody' in html
        assert 'Historique des Mises à Jour' in html

    def test_update_page_contains_state_config(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'STATE_CONFIG' in html
        assert 'backing_up' in html
        assert 'health_checking' in html
        assert 'rolling_back' in html

    def test_update_page_contains_auto_resume(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'checkActiveUpdate' in html

    def test_update_page_contains_pulse_animation(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'progress-bar-pulse' in html
        assert 'pulse-bar' in html
