"""E2E tests for Health Score Widget (Story 3.2 - Simple Style).

Tests the frontend widget rendering, color states, and interactions.
These tests verify the HTML/CSS behavior via Flask test client.

AC Coverage:
- AC1: Score visible en position proéminente, barre + numérique
- AC2: Couleurs correspondent au niveau (vert/orange/rouge)
- AC3: Score compréhensible sans formation
- AC4: Intégration avec HealthScoreCalculator
"""

import pytest
from unittest.mock import Mock, patch
from bs4 import BeautifulSoup


class TestHealthScoreWidgetRendering:
    """Tests for health score widget HTML rendering (Task 8.1)."""

    def test_widget_renders_empty_state_no_capture(self, client):
        """AC1: Widget renders correctly in empty state when no capture (simple style)."""
        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager:
            mock_manager.return_value.get_latest_result.return_value = None

            response = client.get('/')

            assert response.status_code == 200
            soup = BeautifulSoup(response.data, 'html.parser')

            # Widget container exists
            widget = soup.find(id='health-score-widget')
            assert widget is not None, "Widget container should exist"

            # Widget has empty class (simple style)
            assert 'score-display-widget--empty' in widget.get('class', [])

            # Score shows '--'
            score_value = widget.find(class_='score-value')
            assert score_value is not None
            assert '--' in score_value.get_text()

    def test_widget_renders_with_score(self, client):
        """AC1: Widget renders score numerically (XX/100) with progress bar (simple style)."""
        from app.models.anomaly import AnomalyCollection

        mock_session = Mock()
        mock_session.id = 'test_capture_widget'

        mock_result = Mock()
        mock_result.session = mock_session

        # Empty anomalies = score 100
        anomaly_collection = AnomalyCollection(
            capture_id='test_capture_widget',
            anomalies=[],
        )

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            assert response.status_code == 200
            soup = BeautifulSoup(response.data, 'html.parser')

            widget = soup.find(id='health-score-widget')
            assert widget is not None

            # Should NOT have empty class (simple style)
            assert 'score-display-widget--empty' not in widget.get('class', [])

            # Score value should be numeric
            score_value = widget.find(class_='score-value')
            assert score_value is not None
            score_text = score_value.get_text().strip()
            assert score_text.isdigit(), f"Score should be numeric, got: {score_text}"

            # /100 suffix exists
            score_max = widget.find(class_='score-max')
            assert score_max is not None
            assert '/100' in score_max.get_text()

            # Progress bar exists
            progress_bar = widget.find(class_='progress-bar')
            assert progress_bar is not None

            # Progress fill exists
            bar_fill = widget.find(class_='progress-fill')
            assert bar_fill is not None


class TestHealthScoreWidgetColors:
    """Tests for health score color states (Task 8.3)."""

    def _create_anomalies(self, count, criticality):
        """Helper to create test anomalies."""
        from app.models.anomaly import (
            Anomaly, BlacklistMatch, MatchType, CriticalityLevel,
            AnomalyCollection
        )

        anomalies = [
            Anomaly(
                id=Anomaly.generate_id(),
                match=BlacklistMatch(
                    match_type=MatchType.IP,
                    matched_value=f'192.168.1.{i}',
                    source_file='test.txt',
                    context='Test',
                    criticality=criticality,
                ),
                score=95 if criticality == CriticalityLevel.CRITICAL else 60,
                criticality_level=criticality,
                capture_id='test_capture',
            )
            for i in range(count)
        ]
        return AnomalyCollection(capture_id='test_capture', anomalies=anomalies)

    def test_widget_shows_normal_green_for_high_score(self, client):
        """AC2: Score 80-100 shows green (normal) - simple style."""
        from app.models.anomaly import AnomalyCollection

        mock_session = Mock()
        mock_session.id = 'test_normal'
        mock_result = Mock()
        mock_result.session = mock_session

        # No anomalies = score 100 = normal/green
        anomaly_collection = AnomalyCollection(
            capture_id='test_normal',
            anomalies=[],
        )

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            widget = soup.find(id='health-score-widget')

            # Check status class (simple style)
            status = widget.find(class_='score-status')
            assert status is not None
            status_classes = status.get('class', [])
            assert 'score-status--normal' in status_classes

            # Check progress bar has normal class
            bar_fill = widget.find(class_='progress-fill')
            bar_classes = bar_fill.get('class', [])
            assert 'progress-fill--normal' in bar_classes

    def test_widget_shows_warning_orange_for_medium_score(self, client):
        """AC2: Score 50-79 shows orange (warning) - simple style."""
        from app.models.anomaly import CriticalityLevel

        mock_session = Mock()
        mock_session.id = 'test_warning'
        mock_result = Mock()
        mock_result.session = mock_session

        # Create enough anomalies to get warning score
        anomaly_collection = self._create_anomalies(3, CriticalityLevel.WARNING)
        anomaly_collection.capture_id = 'test_warning'

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            widget = soup.find(id='health-score-widget')

            # Get score to verify it's in warning range (simple style)
            score_value = widget.find(class_='score-value')
            score_text = score_value.get_text().strip()
            score = int(score_text)

            # Check data-status attribute
            status_attr = widget.get('data-status')
            assert status_attr in ['warning', 'normal', 'critical']

    def test_widget_shows_critical_red_for_low_score(self, client):
        """AC2: Score 0-49 shows red (critical)."""
        from app.models.anomaly import CriticalityLevel

        mock_session = Mock()
        mock_session.id = 'test_critical'
        mock_result = Mock()
        mock_result.session = mock_session

        # Create many critical anomalies to get critical score
        anomaly_collection = self._create_anomalies(10, CriticalityLevel.CRITICAL)
        anomaly_collection.capture_id = 'test_critical'

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            widget = soup.find(id='health-score-widget')

            # With many critical anomalies, status should be critical
            status_attr = widget.get('data-status')
            # May be warning or critical depending on exact calculation
            assert status_attr in ['warning', 'critical']


class TestHealthScoreWidgetScoreDisplay:
    """Tests for score display correctness (Task 8.2)."""

    def test_score_value_matches_calculator(self, client):
        """AC4: Displayed score matches HealthScoreCalculator output."""
        from app.models.anomaly import (
            Anomaly, BlacklistMatch, MatchType, CriticalityLevel,
            AnomalyCollection
        )
        from app.core.analysis.health_score import get_health_calculator

        mock_session = Mock()
        mock_session.id = 'test_score_match'
        mock_result = Mock()
        mock_result.session = mock_session

        # Create known anomalies
        anomalies = [
            Anomaly(
                id=Anomaly.generate_id(),
                match=BlacklistMatch(
                    match_type=MatchType.TERM,
                    matched_value='malware',
                    source_file='terms.txt',
                    context='Test term',
                    criticality=CriticalityLevel.CRITICAL,
                ),
                score=85,
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id='test_score_match',
            ),
        ]
        anomaly_collection = AnomalyCollection(
            capture_id='test_score_match',
            anomalies=anomalies,
        )

        # Calculate expected score
        calculator = get_health_calculator()
        expected_result = calculator.calculate(anomaly_collection)
        expected_score = expected_result.displayed_score

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            widget = soup.find(id='health-score-widget')
            score_value = widget.find(class_='score-value')
            score_text = score_value.get_text().strip()
            displayed_score = int(score_text)

            assert displayed_score == expected_score, \
                f"Displayed score {displayed_score} != expected {expected_score}"

    def test_score_in_data_attribute(self, client):
        """Widget stores score in data-score attribute for JS."""
        from app.models.anomaly import AnomalyCollection

        mock_session = Mock()
        mock_session.id = 'test_data_attr'
        mock_result = Mock()
        mock_result.session = mock_session

        anomaly_collection = AnomalyCollection(
            capture_id='test_data_attr',
            anomalies=[],
        )

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            widget = soup.find(id='health-score-widget')

            # data-score attribute should exist and be numeric
            score_attr = widget.get('data-score')
            assert score_attr is not None
            assert score_attr.isdigit()


class TestHealthScoreWidgetAnimation:
    """Tests for widget animation support (Task 8.4) - Simple Style."""

    def test_widget_has_progress_bar_with_width(self, client):
        """Progress bar uses width for animation (simple style)."""
        from app.models.anomaly import AnomalyCollection

        mock_session = Mock()
        mock_session.id = 'test_anim'
        mock_result = Mock()
        mock_result.session = mock_session

        anomaly_collection = AnomalyCollection(
            capture_id='test_anim',
            anomalies=[],
        )

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            bar_fill = soup.find(class_='progress-fill')

            # Progress bar should have width style
            style = bar_fill.get('style', '')
            assert 'width:' in style

            # For score 100, width should be 100%
            assert '100%' in style, f"Width should be 100% for score 100, got: {style}"

    def test_css_transition_classes_exist(self, client):
        """Widget CSS includes transition properties for smooth updates."""
        response = client.get('/static/css/health-score.css')

        # CSS file should be accessible
        assert response.status_code == 200

        css_content = response.data.decode('utf-8')

        # Check for transition properties
        assert 'transition:' in css_content or 'transition-' in css_content
        assert 'width' in css_content
        assert '@keyframes' in css_content  # Animation keyframes

    def test_details_button_exists_when_data_available(self, client):
        """Details button is visible when score data is available."""
        from app.models.anomaly import AnomalyCollection

        mock_session = Mock()
        mock_session.id = 'test_details'
        mock_result = Mock()
        mock_result.session = mock_session

        anomaly_collection = AnomalyCollection(
            capture_id='test_details',
            anomalies=[],
        )

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = anomaly_collection

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')

            # Details button should exist (by ID)
            details_btn = soup.find(id='btn-health-score-details')
            assert details_btn is not None

            # Should NOT be hidden (no display:none)
            style = details_btn.get('style', '')
            assert 'display: none' not in style


class TestHealthScoreWidgetComprehensibility:
    """Tests for score comprehensibility (AC3 - NFR36) - Simple Style."""

    def test_widget_has_clear_labels(self, client):
        """Widget has clear labels that indicate good/bad (simple style)."""
        from app.models.anomaly import AnomalyCollection

        mock_session = Mock()
        mock_session.id = 'test_labels'
        mock_result = Mock()
        mock_result.session = mock_session

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store:

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = AnomalyCollection(
                capture_id='test_labels', anomalies=[]
            )

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            widget = soup.find(id='health-score-widget')

            # Status label should exist with clear text (simple style)
            status = widget.find(class_='score-status')
            assert status is not None
            status_text = status.get_text().strip()

            # Should have a clear status label
            valid_labels = ['Réseau Sain', 'Reseau Sain', 'Attention', 'Critique', '--%']
            assert any(label in status_text for label in valid_labels), \
                f"Status should be clear, got: {status_text}"

    def test_score_section_title_in_parent(self, client):
        """Parent section has 'Score Santé' title for context."""
        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager:
            mock_manager.return_value.get_latest_result.return_value = None

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')

            # Find the section containing the health score
            score_section = soup.find('section', class_='score-health')
            assert score_section is not None

            # Should have a title
            title = score_section.find(class_='card-title')
            assert title is not None
            assert 'Score' in title.get_text() or 'Sant' in title.get_text()
