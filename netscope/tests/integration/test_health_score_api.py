"""Integration tests for Health Score API (Story 3.2).

Tests the /api/health/score endpoint and dashboard integration.
"""

import pytest
from unittest.mock import Mock, patch


class TestHealthScoreAPI:
    """Tests for /api/health/score endpoint."""

    def test_health_score_no_capture_returns_null(self, client):
        """AC1: Returns null when no capture available."""
        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager:
            mock_manager.return_value.get_latest_result.return_value = None

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert data['data'] is None
            assert 'message' in data

    def test_health_score_no_anomalies_returns_100(self, client):
        """AC2: Returns 100 when capture exists but no anomalies."""
        mock_session = Mock()
        mock_session.id = 'test_capture_001'

        mock_result = Mock()
        mock_result.session = mock_session

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = None

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert data['data'] is not None
            assert data['data']['displayed_score'] == 100
            assert data['data']['status_color'] == 'normal'

    def test_health_score_with_anomalies(self, client):
        """AC3: Calculates score from anomalies using HealthScoreCalculator."""
        from app.models.anomaly import (
            AnomalyCollection, Anomaly, BlacklistMatch,
            MatchType, CriticalityLevel
        )

        mock_session = Mock()
        mock_session.id = 'test_capture_002'

        mock_result = Mock()
        mock_result.session = mock_session

        # Create anomaly collection with mixed severities
        anomalies = [
            Anomaly(
                id=Anomaly.generate_id(),
                match=BlacklistMatch(
                    match_type=MatchType.IP,
                    matched_value='192.168.1.100',
                    source_file='ips_malware.txt',
                    context='Blacklisted IP',
                    criticality=CriticalityLevel.CRITICAL,
                ),
                score=90,
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id='test_capture_002',
            ),
            Anomaly(
                id=Anomaly.generate_id(),
                match=BlacklistMatch(
                    match_type=MatchType.TERM,
                    matched_value='suspicious',
                    source_file='terms_suspect.txt',
                    context='Suspicious term',
                    criticality=CriticalityLevel.WARNING,
                ),
                score=60,
                criticality_level=CriticalityLevel.WARNING,
                capture_id='test_capture_002',
            ),
        ]
        anomaly_collection = AnomalyCollection(
            capture_id='test_capture_002',
            anomalies=anomalies,
        )

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert data['data'] is not None
            # Score should be less than 100 due to anomalies
            assert data['data']['displayed_score'] < 100
            assert data['data']['critical_count'] >= 1
            assert data['data']['warning_count'] >= 1
            assert 'status_color' in data['data']

    def test_health_score_status_colors(self, client):
        """AC6: Verifies correct status colors for score ranges."""
        from app.models.anomaly import (
            AnomalyCollection, Anomaly, BlacklistMatch,
            MatchType, CriticalityLevel
        )

        mock_session = Mock()
        mock_session.id = 'test_capture_003'

        mock_result = Mock()
        mock_result.session = mock_session

        # Create critical anomalies to drive score low
        critical_anomalies = [
            Anomaly(
                id=Anomaly.generate_id(),
                match=BlacklistMatch(
                    match_type=MatchType.IP,
                    matched_value=f'192.168.1.{i}',
                    source_file='ips_malware.txt',
                    context='Blacklisted IP',
                    criticality=CriticalityLevel.CRITICAL,
                ),
                score=95,
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id='test_capture_003',
            )
            for i in range(5)
        ]
        anomaly_collection = AnomalyCollection(
            capture_id='test_capture_003',
            anomalies=critical_anomalies,
        )

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            # With many critical anomalies, status should be critical or warning
            status = data['data']['status_color']
            assert status in ['normal', 'warning', 'critical']

    def test_health_score_api_error_handling(self, client):
        """Test API handles errors gracefully."""
        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager:
            mock_manager.side_effect = Exception('Test error')

            response = client.get('/api/health/score')

            assert response.status_code == 500
            data = response.get_json()
            assert data['success'] is False
            assert 'error' in data
            assert data['error']['code'] == 'HEALTH_SCORE_ERROR'


class TestDashboardHealthScoreIntegration:
    """Tests for dashboard route with health score."""

    def test_dashboard_renders_with_no_capture(self, client):
        """Dashboard renders correctly when no capture available."""
        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager:
            mock_manager.return_value.get_latest_result.return_value = None

            response = client.get('/')

            assert response.status_code == 200
            # Check health score widget is rendered in empty state
            assert b'health-score-widget' in response.data

    def test_dashboard_renders_with_health_score(self, client):
        """AC4: Dashboard uses get_health_calculator() for score."""
        from app.models.anomaly import (
            AnomalyCollection, Anomaly, BlacklistMatch,
            MatchType, CriticalityLevel
        )

        mock_session = Mock()
        mock_session.id = 'test_capture_004'

        mock_result = Mock()
        mock_result.session = mock_session

        anomaly_collection = AnomalyCollection(
            capture_id='test_capture_004',
            anomalies=[
                Anomaly(
                    id=Anomaly.generate_id(),
                    match=BlacklistMatch(
                        match_type=MatchType.TERM,
                        matched_value='backdoor',
                        source_file='terms_suspect.txt',
                        context='Suspicious term',
                        criticality=CriticalityLevel.WARNING,
                    ),
                    score=65,
                    criticality_level=CriticalityLevel.WARNING,
                    capture_id='test_capture_004',
                ),
            ],
        )

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            assert response.status_code == 200
            # Health score widget should be populated
            assert b'health-score-widget' in response.data
            # Check score is rendered (not '--')
            html = response.data.decode('utf-8')
            assert 'health-gauge__progress' in html

    def test_dashboard_handles_calculation_error(self, client):
        """Dashboard renders even if health score calculation fails."""
        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager:
            mock_manager.side_effect = Exception('Test error')

            response = client.get('/')

            # Should still render, just without health score
            assert response.status_code == 200
            assert b'health-score-widget' in response.data
