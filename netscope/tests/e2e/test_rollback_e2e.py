"""E2E tests for rollback & health check (Story 5.8).

Tests full user journey: POST /api/update/apply → polling status
→ health_checking → done (or rolling_back → rolled_back).
"""

from unittest.mock import patch, MagicMock

import pytest

from app.services.update_service import (
    UpdateState,
    UpdateStatus,
    UpdateErrorCode,
    reset_update_service,
    get_update_service,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    reset_update_service()
    yield
    reset_update_service()


class TestE2EHealthCheckSuccess:
    """Task 7.1 — POST /api/update/apply → polling → health_checking → done."""

    @patch('app.services.update_service.UpdateService.start_update', return_value=True)
    def test_apply_then_poll_health_checking_then_done(self, mock_start, client):
        resp = client.post('/api/update/apply')
        assert resp.status_code == 202
        data = resp.get_json()
        assert data['started'] is True

        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.HEALTH_CHECKING,
            progress_percent=92,
            current_step="Vérification santé post-update...",
        )

        resp = client.get('/api/update/status')
        data = resp.get_json()
        assert data['state'] == 'health_checking'
        assert data['progress_percent'] == 92
        assert 'santé' in data['current_step']

        svc._update_status = UpdateStatus(
            state=UpdateState.DONE,
            progress_percent=100,
            current_step="Mise à jour réussie",
        )

        resp = client.get('/api/update/status')
        data = resp.get_json()
        assert data['state'] == 'done'
        assert data['progress_percent'] == 100
        assert 'réussie' in data['current_step']

    @patch('app.services.update_service.UpdateService.start_update', return_value=True)
    def test_apply_poll_transitions_restarting_to_health_checking(self, mock_start, client):
        resp = client.post('/api/update/apply')
        assert resp.status_code == 202

        svc = get_update_service()

        svc._update_status = UpdateStatus(
            state=UpdateState.RESTARTING,
            progress_percent=90,
            current_step="Redémarrage du service...",
        )
        resp = client.get('/api/update/status')
        assert resp.get_json()['state'] == 'restarting'

        svc._update_status = UpdateStatus(
            state=UpdateState.HEALTH_CHECKING,
            progress_percent=92,
            current_step="Vérification santé post-update...",
        )
        resp = client.get('/api/update/status')
        assert resp.get_json()['state'] == 'health_checking'

        svc._update_status = UpdateStatus(
            state=UpdateState.DONE,
            progress_percent=100,
            current_step="Mise à jour réussie",
        )
        resp = client.get('/api/update/status')
        assert resp.get_json()['state'] == 'done'


class TestE2ERollback:
    """Task 7.2 — POST /api/update/apply → polling → health_checking → rolling_back → rolled_back."""

    @patch('app.services.update_service.UpdateService.start_update', return_value=True)
    def test_apply_then_poll_rollback_sequence(self, mock_start, client):
        resp = client.post('/api/update/apply')
        assert resp.status_code == 202

        svc = get_update_service()

        svc._update_status = UpdateStatus(
            state=UpdateState.HEALTH_CHECKING,
            progress_percent=92,
            current_step="Vérification santé post-update...",
        )
        resp = client.get('/api/update/status')
        data = resp.get_json()
        assert data['state'] == 'health_checking'

        svc._update_status = UpdateStatus(
            state=UpdateState.ROLLING_BACK,
            progress_percent=95,
            current_step="Restauration version précédente...",
        )
        resp = client.get('/api/update/status')
        data = resp.get_json()
        assert data['state'] == 'rolling_back'
        assert 'Restauration' in data['current_step']

        svc._update_status = UpdateStatus(
            state=UpdateState.ROLLED_BACK,
            progress_percent=100,
            current_step="Update échouée, version précédente restaurée",
        )
        resp = client.get('/api/update/status')
        data = resp.get_json()
        assert data['state'] == 'rolled_back'
        assert 'restaurée' in data['current_step']
        assert data['progress_percent'] == 100

    @patch('app.services.update_service.UpdateService.start_update', return_value=True)
    def test_apply_then_rollback_failed(self, mock_start, client):
        resp = client.post('/api/update/apply')
        assert resp.status_code == 202

        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.ROLLBACK_FAILED,
            error="Échec du rollback. Intervention manuelle requise.",
            error_code=UpdateErrorCode.ROLLBACK_FAILED,
        )

        resp = client.get('/api/update/status')
        data = resp.get_json()
        assert data['state'] == 'rollback_failed'
        assert data['error'] == "Échec du rollback. Intervention manuelle requise."
        assert data['error_code'] == 'ROLLBACK_FAILED'
