"""Integration tests for Health Score Evolution API (Story 3.5).

Tests the /api/health/evolution endpoint and history recording integration.

Story 3.5: Evolution Score Entre Captures (FR20)
- AC1: Affichage evolution (current, previous, delta)
- AC2: Indicateur positif (amelioration)
- AC3: Indicateur negatif (degradation)
- AC4: Premiere capture (pas d'historique)
- AC5: Reflection correcte apres correction
"""

import pytest
from unittest.mock import Mock, patch

from app.models.health_score import HealthScoreResult
from app.services.health_score_history import (
    get_health_score_history,
    reset_health_score_history,
)


@pytest.fixture(autouse=True)
def reset_history():
    """Reset history singleton before each test."""
    reset_health_score_history()
    yield
    reset_health_score_history()


class TestHealthScoreEvolutionAPI:
    """Tests for /api/health/evolution endpoint."""

    def test_evolution_no_history_returns_null(self, client):
        """AC4: Returns null when no capture history exists."""
        response = client.get('/api/health/evolution')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data'] is None
        assert 'message' in data

    def test_evolution_first_capture_null_previous(self, client):
        """AC4: First capture returns null for previous_score."""
        # Record a single capture in history
        history = get_health_score_history()
        history.record('cap_001', HealthScoreResult(
            displayed_score=85,
            real_score=85,
        ))

        response = client.get('/api/health/evolution')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data'] is not None
        assert data['data']['current_score'] == 85
        assert data['data']['previous_score'] is None
        assert data['data']['delta'] == 0
        assert data['data']['direction'] == 'stable'
        assert 'Premiere' in data['data']['message']

    def test_evolution_improvement_direction_up(self, client):
        """AC2: Returns direction 'up' when score improved."""
        history = get_health_score_history()
        history.record('cap_001', HealthScoreResult(
            displayed_score=60,
            real_score=60,
        ))
        history.record('cap_002', HealthScoreResult(
            displayed_score=85,
            real_score=85,
        ))

        response = client.get('/api/health/evolution')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['current_score'] == 85
        assert data['data']['previous_score'] == 60
        assert data['data']['delta'] == 25
        assert data['data']['direction'] == 'up'
        assert 'Amelioration' in data['data']['message']

    def test_evolution_degradation_direction_down(self, client):
        """AC3: Returns direction 'down' when score degraded."""
        history = get_health_score_history()
        history.record('cap_001', HealthScoreResult(
            displayed_score=90,
            real_score=90,
        ))
        history.record('cap_002', HealthScoreResult(
            displayed_score=65,
            real_score=65,
        ))

        response = client.get('/api/health/evolution')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['current_score'] == 65
        assert data['data']['previous_score'] == 90
        assert data['data']['delta'] == -25
        assert data['data']['direction'] == 'down'
        assert 'Degradation' in data['data']['message']

    def test_evolution_stable_direction(self, client):
        """Returns direction 'stable' when score unchanged."""
        history = get_health_score_history()
        history.record('cap_001', HealthScoreResult(
            displayed_score=80,
            real_score=80,
        ))
        history.record('cap_002', HealthScoreResult(
            displayed_score=80,
            real_score=80,
        ))

        response = client.get('/api/health/evolution')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['current_score'] == 80
        assert data['data']['previous_score'] == 80
        assert data['data']['delta'] == 0
        assert data['data']['direction'] == 'stable'

    def test_evolution_json_structure(self, client):
        """Verifies complete JSON response structure."""
        history = get_health_score_history()
        history.record('cap_001', HealthScoreResult(displayed_score=70, real_score=70))
        history.record('cap_002', HealthScoreResult(displayed_score=85, real_score=85))

        response = client.get('/api/health/evolution')

        assert response.status_code == 200
        data = response.get_json()

        # Verify structure
        assert 'success' in data
        assert 'data' in data
        assert 'current_score' in data['data']
        assert 'previous_score' in data['data']
        assert 'delta' in data['data']
        assert 'direction' in data['data']
        assert 'message' in data['data']


class TestHealthScoreAPIRecordsHistory:
    """Tests that /api/health/score records to history (Task 3)."""

    def test_health_score_api_records_to_history(self, client):
        """AC5: Health score API call records score in history."""
        from app.models.anomaly import AnomalyCollection

        mock_session = Mock()
        mock_session.id = 'test_capture_hist_1'

        mock_result = Mock()
        mock_result.session = mock_session

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = None

            # Call health score API
            response = client.get('/api/health/score')
            assert response.status_code == 200

            # Check history was recorded
            history = get_health_score_history()
            assert history.get_history_count() == 1
            latest = history.get_latest(1)
            assert latest[0].capture_id == 'test_capture_hist_1'
            assert latest[0].displayed_score == 100

    def test_multiple_captures_recorded_in_history(self, client):
        """Multiple health score API calls record multiple history entries."""
        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store:

            mock_store.return_value.get_by_capture.return_value = None

            # First capture
            mock_session1 = Mock()
            mock_session1.id = 'test_capture_multi_1'
            mock_result1 = Mock()
            mock_result1.session = mock_session1
            mock_manager.return_value.get_latest_result.return_value = mock_result1

            client.get('/api/health/score')

            # Second capture
            mock_session2 = Mock()
            mock_session2.id = 'test_capture_multi_2'
            mock_result2 = Mock()
            mock_result2.session = mock_session2
            mock_manager.return_value.get_latest_result.return_value = mock_result2

            client.get('/api/health/score')

            # Check both recorded
            history = get_health_score_history()
            assert history.get_history_count() == 2

    def test_evolution_reflects_api_recorded_history(self, client):
        """AC5: Evolution API reflects scores recorded by health score API."""
        from app.models.anomaly import (
            AnomalyCollection, Anomaly, BlacklistMatch,
            MatchType, CriticalityLevel
        )

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store:

            # First capture - no anomalies (score 100)
            mock_session1 = Mock()
            mock_session1.id = 'test_capture_evo_1'
            mock_result1 = Mock()
            mock_result1.session = mock_session1
            mock_manager.return_value.get_latest_result.return_value = mock_result1
            mock_store.return_value.get_by_capture.return_value = None

            response1 = client.get('/api/health/score')
            assert response1.status_code == 200
            assert response1.get_json()['data']['displayed_score'] == 100

            # Second capture - with anomalies (score lower)
            mock_session2 = Mock()
            mock_session2.id = 'test_capture_evo_2'
            mock_result2 = Mock()
            mock_result2.session = mock_session2
            mock_manager.return_value.get_latest_result.return_value = mock_result2

            anomaly_collection = AnomalyCollection(
                capture_id='test_capture_evo_2',
                anomalies=[
                    Anomaly(
                        id=Anomaly.generate_id(),
                        match=BlacklistMatch(
                            match_type=MatchType.IP,
                            matched_value='1.2.3.4',
                            source_file='test.txt',
                            context='Test',
                            criticality=CriticalityLevel.CRITICAL,
                        ),
                        score=90,
                        criticality_level=CriticalityLevel.CRITICAL,
                        capture_id='test_capture_evo_2',
                    ),
                ],
            )
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response2 = client.get('/api/health/score')
            assert response2.status_code == 200
            assert response2.get_json()['data']['displayed_score'] == 85  # 100 - 15

            # Check evolution shows degradation
            evolution_response = client.get('/api/health/evolution')
            assert evolution_response.status_code == 200
            evo_data = evolution_response.get_json()

            assert evo_data['data']['current_score'] == 85
            assert evo_data['data']['previous_score'] == 100
            assert evo_data['data']['delta'] == -15
            assert evo_data['data']['direction'] == 'down'


class TestHealthScoreEvolutionErrorHandling:
    """Tests for error handling in evolution API."""

    def test_evolution_api_error_handling(self, client):
        """API handles errors gracefully."""
        with patch('app.blueprints.api.health.get_health_score_history') as mock_history:
            mock_history.side_effect = Exception('Test error')

            response = client.get('/api/health/evolution')

            assert response.status_code == 500
            data = response.get_json()
            assert data['success'] is False
            assert 'error' in data
            assert data['error']['code'] == 'HEALTH_EVOLUTION_ERROR'


class TestHealthScoreEvolutionAC5Correction:
    """Tests for AC5: Reflection correcte apres correction."""

    def test_score_reflects_improvement_after_correction(self, client):
        """AC5: New capture correctly reflects improvement after user correction."""
        from app.models.anomaly import (
            AnomalyCollection, Anomaly, BlacklistMatch,
            MatchType, CriticalityLevel
        )

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store:

            # Initial capture with problems (3 critical = 100 - 45 = 55)
            mock_session1 = Mock()
            mock_session1.id = 'cap_before_fix'
            mock_result1 = Mock()
            mock_result1.session = mock_session1
            mock_manager.return_value.get_latest_result.return_value = mock_result1

            bad_anomalies = AnomalyCollection(
                capture_id='cap_before_fix',
                anomalies=[
                    Anomaly(
                        id=Anomaly.generate_id(),
                        match=BlacklistMatch(
                            match_type=MatchType.IP,
                            matched_value=f'1.2.3.{i}',
                            source_file='test.txt',
                            context='Test',
                            criticality=CriticalityLevel.CRITICAL,
                        ),
                        score=90,
                        criticality_level=CriticalityLevel.CRITICAL,
                        capture_id='cap_before_fix',
                    )
                    for i in range(3)
                ],
            )
            mock_store.return_value.get_by_capture.return_value = bad_anomalies

            response1 = client.get('/api/health/score')
            assert response1.get_json()['data']['displayed_score'] == 55

            # After user fixes problems - new capture with no anomalies
            mock_session2 = Mock()
            mock_session2.id = 'cap_after_fix'
            mock_result2 = Mock()
            mock_result2.session = mock_session2
            mock_manager.return_value.get_latest_result.return_value = mock_result2
            mock_store.return_value.get_by_capture.return_value = None

            response2 = client.get('/api/health/score')
            assert response2.get_json()['data']['displayed_score'] == 100

            # Evolution should show improvement
            evo_response = client.get('/api/health/evolution')
            evo_data = evo_response.get_json()

            assert evo_data['data']['current_score'] == 100
            assert evo_data['data']['previous_score'] == 55
            assert evo_data['data']['delta'] == 45
            assert evo_data['data']['direction'] == 'up'
            assert 'Amelioration' in evo_data['data']['message']
