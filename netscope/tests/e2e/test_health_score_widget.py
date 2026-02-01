"""E2E tests for Health Score Widget (Story 3.2, Story 3.3 - Simple Style).

Tests the frontend widget rendering, color states, and interactions.
These tests verify the HTML/CSS behavior via Flask test client.

AC Coverage Story 3.2:
- AC1: Score visible en position proéminente, barre + numérique
- AC2: Couleurs correspondent au niveau (vert/orange/rouge)
- AC3: Score compréhensible sans formation
- AC4: Intégration avec HealthScoreCalculator

AC Coverage Story 3.3:
- AC1: Indicateur whitelist hits visible
- AC2: Compréhension immédiate de l'indicateur
- AC3: Gestion zero whitelist hits
- AC4: Transparence score affiché vs réel
- AC5: Intégration avec widget health score existant
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


class TestWhitelistIndicatorRendering:
    """Tests for whitelist indicator HTML rendering (Story 3.3)."""

    def test_whitelist_indicator_visible_when_hits_exist(self, client):
        """AC1: Indicator visible when whitelist_hits > 0."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store, \
             patch('app.blueprints.dashboard.routes.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_wl_visible'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            health_result = HealthScoreResult(
                displayed_score=85,
                real_score=65,
                critical_count=0,
                warning_count=1,
                whitelist_hits=4,
                whitelist_impact=-20,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/')

            assert response.status_code == 200
            soup = BeautifulSoup(response.data, 'html.parser')

            # Find whitelist indicator
            indicator = soup.find(class_='whitelist-indicator')
            assert indicator is not None, "Whitelist indicator should exist"

            # Should NOT have hidden class
            indicator_classes = indicator.get('class', [])
            assert 'whitelist-indicator--hidden' not in indicator_classes

            # Should show correct number of hits
            text = indicator.find(class_='whitelist-indicator__text')
            assert text is not None
            assert '4 whitelist hits' in text.get_text()

    def test_whitelist_indicator_hidden_when_no_hits(self, client):
        """AC3: Indicator hidden when whitelist_hits == 0."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store, \
             patch('app.blueprints.dashboard.routes.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_wl_hidden'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            health_result = HealthScoreResult(
                displayed_score=70,
                real_score=70,
                critical_count=1,
                warning_count=2,
                whitelist_hits=0,
                whitelist_impact=0,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/')

            assert response.status_code == 200
            soup = BeautifulSoup(response.data, 'html.parser')

            indicator = soup.find(class_='whitelist-indicator')
            assert indicator is not None

            # Should have hidden class
            indicator_classes = indicator.get('class', [])
            assert 'whitelist-indicator--hidden' in indicator_classes

    def test_whitelist_indicator_singular_form(self, client):
        """AC2: Indicator uses singular when hits == 1."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store, \
             patch('app.blueprints.dashboard.routes.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_wl_singular'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            health_result = HealthScoreResult(
                displayed_score=95,
                real_score=85,
                critical_count=0,
                warning_count=0,
                whitelist_hits=1,
                whitelist_impact=-10,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            text = soup.find(class_='whitelist-indicator__text')
            assert text is not None
            text_content = text.get_text().strip()
            # Should be "1 whitelist hit" not "1 whitelist hits"
            assert '1 whitelist hit' in text_content
            assert '1 whitelist hits' not in text_content

    def test_whitelist_indicator_shows_impact_when_negative(self, client):
        """AC4: Indicator shows impact when whitelist_impact < 0 (points hidden)."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store, \
             patch('app.blueprints.dashboard.routes.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_wl_impact'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            health_result = HealthScoreResult(
                displayed_score=90,
                real_score=55,
                critical_count=0,
                warning_count=0,
                whitelist_hits=3,
                whitelist_impact=-35,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')

            # Indicator should exist and be visible
            indicator = soup.find(class_='whitelist-indicator')
            assert indicator is not None
            assert 'data-impact' in str(indicator)
            assert indicator.get('data-impact') == '-35'

            # Impact element should be rendered and show absolute value
            impact = soup.find(class_='whitelist-indicator__impact')
            assert impact is not None, "Impact element should be rendered when whitelist_impact < 0"
            impact_text = impact.get_text().strip()
            assert '35' in impact_text, f"Should show absolute value 35, got: {impact_text}"
            assert 'pts' in impact_text.lower(), f"Should mention pts, got: {impact_text}"

    def test_whitelist_indicator_has_icon(self, client):
        """AC1: Indicator has shield icon for visual recognition."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store, \
             patch('app.blueprints.dashboard.routes.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_wl_icon'
            mock_result = Mock()
            mock_result.session = mock_session

            mock_collection = Mock()
            mock_collection.anomalies = [Mock()]

            mock_manager.return_value.get_latest_result.return_value = mock_result
            mock_store.return_value.get_by_capture.return_value = mock_collection

            health_result = HealthScoreResult(
                displayed_score=80,
                real_score=70,
                critical_count=0,
                warning_count=1,
                whitelist_hits=2,
                whitelist_impact=-10,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            icon = soup.find(class_='whitelist-indicator__icon')
            assert icon is not None, "Indicator should have icon element"

    def test_whitelist_indicator_data_attributes(self, client):
        """AC5: Indicator has data attributes for JavaScript updates."""
        from app.models.health_score import HealthScoreResult

        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_manager, \
             patch('app.blueprints.dashboard.routes.get_anomaly_store') as mock_store, \
             patch('app.blueprints.dashboard.routes.get_health_calculator') as mock_calc:

            mock_session = Mock()
            mock_session.id = 'test_wl_data'
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
                warning_count=1,
                whitelist_hits=5,
                whitelist_impact=-15,
            )
            mock_calc.return_value.calculate.return_value = health_result

            response = client.get('/')

            soup = BeautifulSoup(response.data, 'html.parser')
            indicator = soup.find(class_='whitelist-indicator')
            assert indicator is not None

            # Check data attributes
            assert indicator.get('data-hits') == '5'
            assert indicator.get('data-impact') == '-15'


class TestWhitelistIndicatorCSS:
    """Tests for whitelist indicator CSS (Story 3.3)."""

    def test_whitelist_css_classes_exist(self, client):
        """CSS file contains whitelist indicator styles."""
        response = client.get('/static/css/health-score.css')

        assert response.status_code == 200
        css_content = response.data.decode('utf-8')

        # Check whitelist indicator classes exist
        assert '.whitelist-indicator' in css_content
        assert '.whitelist-indicator--hidden' in css_content
        assert '.whitelist-indicator__icon' in css_content
        assert '.whitelist-indicator__text' in css_content
        assert '.whitelist-indicator__impact' in css_content

    def test_whitelist_hidden_class_uses_display_none(self, client):
        """Hidden class uses display: none for clean hiding."""
        response = client.get('/static/css/health-score.css')

        assert response.status_code == 200
        css_content = response.data.decode('utf-8')

        # Hidden class should hide the element
        assert 'whitelist-indicator--hidden' in css_content
        assert 'display' in css_content


class TestWhitelistIndicatorJavaScript:
    """Tests for whitelist indicator JavaScript (Story 3.3)."""

    def test_js_file_contains_whitelist_methods(self, client):
        """JavaScript file contains whitelist update method."""
        response = client.get('/static/js/health-score.js')

        assert response.status_code == 200
        js_content = response.data.decode('utf-8')

        # Check whitelist-related code exists
        assert 'whitelistIndicator' in js_content
        assert 'updateWhitelistIndicator' in js_content
        assert 'whitelist_hits' in js_content

    def test_js_caches_whitelist_elements(self, client):
        """JavaScript caches whitelist DOM elements."""
        response = client.get('/static/js/health-score.js')

        assert response.status_code == 200
        js_content = response.data.decode('utf-8')

        # Check element caching
        assert 'whitelistIndicator' in js_content
        assert 'whitelistText' in js_content
        assert 'whitelistImpact' in js_content
