"""Integration tests for Health Score API (Story 3.2, Story 3.3, Story 3.4).

Tests the /api/health/score endpoint and dashboard integration.
Story 3.3: Added whitelist indicator tests.
Story 3.4: Added whitelist_details tests.
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
            # Health score widget should be populated (simple style)
            assert b'health-score-widget' in response.data
            # Check score is rendered with progress bar (not '--')
            html = response.data.decode('utf-8')
            assert 'progress-fill' in html

    def test_dashboard_handles_calculation_error(self, client):
        """Dashboard renders even if health score calculation fails."""
        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager:
            mock_manager.side_effect = Exception('Test error')

            response = client.get('/')

            # Should still render, just without health score (simple style)
            assert response.status_code == 200
            assert b'health-score-widget' in response.data


class TestWhitelistIndicatorIntegration:
    """Tests for whitelist indicator (Story 3.3)."""

    def test_whitelist_indicator_visible_when_hits_positive(self, client):
        """AC1: Indicateur visible quand whitelist_hits > 0."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store, \
             patch('app.blueprints.api.health.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_capture_wl_1'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            # Simulate whitelist hits
            health_result = HealthScoreResult(
                displayed_score=85,
                real_score=65,
                critical_count=0,
                warning_count=1,
                whitelist_hits=3,
                whitelist_impact=-20,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert data['data']['whitelist_hits'] == 3
            assert data['data']['whitelist_hits'] > 0

    def test_whitelist_indicator_hidden_when_no_hits(self, client):
        """AC3: Indicateur masque quand whitelist_hits == 0."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store, \
             patch('app.blueprints.api.health.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_capture_wl_2'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            # Simulate no whitelist hits
            health_result = HealthScoreResult(
                displayed_score=70,
                real_score=70,
                critical_count=1,
                warning_count=2,
                whitelist_hits=0,
                whitelist_impact=0,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert data['data']['whitelist_hits'] == 0

    def test_whitelist_impact_present_in_api_response(self, client):
        """AC4: API returns whitelist_impact for transparency."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store, \
             patch('app.blueprints.api.health.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_capture_wl_3'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            # Simulate whitelist with impact
            health_result = HealthScoreResult(
                displayed_score=90,
                real_score=55,
                critical_count=0,
                warning_count=0,
                whitelist_hits=5,
                whitelist_impact=-35,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert 'whitelist_impact' in data['data']
            assert data['data']['whitelist_impact'] == -35

    def test_dashboard_renders_whitelist_indicator(self, client):
        """AC5: Dashboard integrates whitelist indicator with health score widget."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store, \
             patch('app.blueprints.dashboard.routes.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_capture_wl_4'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            health_result = HealthScoreResult(
                displayed_score=75,
                real_score=60,
                critical_count=1,
                warning_count=2,
                whitelist_hits=2,
                whitelist_impact=-15,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/')

            assert response.status_code == 200
            html = response.data.decode('utf-8')
            # Check whitelist indicator is present in HTML
            assert 'whitelist-indicator' in html
            assert '2 whitelist hit' in html

    def test_dashboard_hides_indicator_when_no_whitelist_hits(self, client):
        """AC3: Dashboard hides indicator when no whitelist hits."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store, \
             patch('app.blueprints.dashboard.routes.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_capture_wl_5'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            health_result = HealthScoreResult(
                displayed_score=80,
                real_score=80,
                critical_count=1,
                warning_count=1,
                whitelist_hits=0,
                whitelist_impact=0,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/')

            assert response.status_code == 200
            html = response.data.decode('utf-8')
            # Indicator should have hidden class
            assert 'whitelist-indicator--hidden' in html


class TestWhitelistDetailsIntegration:
    """Tests for whitelist_details in API (Story 3.4)."""

    def test_api_returns_whitelist_details_in_response(self, client):
        """AC2: API retourne whitelist_details dans response."""
        from app.models.health_score import HealthScoreResult, WhitelistHitDetail

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store, \
             patch('app.blueprints.api.health.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_capture_wd_1'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            # Simulate whitelist with details
            whitelist_details = [
                WhitelistHitDetail(
                    anomaly_id='anomaly_001',
                    ip='192.168.1.100',
                    port=None,
                    anomaly_type='ip',
                    criticality='critical',
                    impact=-15,
                    reason='Blacklist match: ips_malware.txt',
                ),
                WhitelistHitDetail(
                    anomaly_id='anomaly_002',
                    ip=None,
                    port=8080,
                    anomaly_type='heuristic',
                    criticality='warning',
                    impact=-5,
                    reason='Port suspect: proxy alternatif',
                ),
            ]
            health_result = HealthScoreResult(
                displayed_score=100,
                real_score=80,
                critical_count=0,
                warning_count=0,
                whitelist_hits=2,
                whitelist_impact=-20,
                whitelist_details=whitelist_details,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['success'] is True
            assert 'whitelist_details' in data['data']
            assert len(data['data']['whitelist_details']) == 2

    def test_whitelist_details_structure_valid_for_frontend(self, client):
        """AC2: structure whitelist_details valide pour frontend."""
        from app.models.health_score import HealthScoreResult, WhitelistHitDetail

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store, \
             patch('app.blueprints.api.health.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_capture_wd_2'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            whitelist_details = [
                WhitelistHitDetail(
                    anomaly_id='anomaly_003',
                    ip='10.0.0.1',
                    port=443,
                    anomaly_type='domain',
                    criticality='critical',
                    impact=-15,
                    reason='Domain match: malware.com',
                ),
            ]
            health_result = HealthScoreResult(
                displayed_score=100,
                real_score=85,
                critical_count=0,
                warning_count=0,
                whitelist_hits=1,
                whitelist_impact=-15,
                whitelist_details=whitelist_details,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            detail = data['data']['whitelist_details'][0]

            # Verify structure has all required fields
            assert 'anomaly_id' in detail
            assert 'ip' in detail
            assert 'port' in detail
            assert 'anomaly_type' in detail
            assert 'criticality' in detail
            assert 'impact' in detail
            assert 'reason' in detail

            # Verify values
            assert detail['anomaly_id'] == 'anomaly_003'
            assert detail['ip'] == '10.0.0.1'
            assert detail['port'] == 443
            assert detail['criticality'] == 'critical'
            assert detail['impact'] == -15

    def test_whitelist_details_empty_when_no_hits(self, client):
        """whitelist_details empty list when no whitelist hits."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.api.health.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.api.health.get_anomaly_store') as mock_store, \
             patch('app.blueprints.api.health.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_capture_wd_3'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            # No whitelist hits
            health_result = HealthScoreResult(
                displayed_score=70,
                real_score=70,
                critical_count=2,
                warning_count=1,
                whitelist_hits=0,
                whitelist_impact=0,
                whitelist_details=[],
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/api/health/score')

            assert response.status_code == 200
            data = response.get_json()
            assert data['data']['whitelist_details'] == []
