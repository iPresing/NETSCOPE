"""Tests unitaires CSS — Story 4b.2: Fix CSS Cards & Scroll Fluide.

Vérifie que le fichier style.css contient les règles CSS attendues
pour le scroll fluide, l'overflow des cards, et l'accessibilité.
"""

import os
import re

import pytest

CSS_PATH = os.path.join(
    os.path.dirname(__file__),
    '..', '..', 'app', 'static', 'css', 'style.css'
)


@pytest.fixture(scope='module')
def css_content():
    """Load the main CSS file content."""
    with open(CSS_PATH, 'r', encoding='utf-8') as f:
        return f.read()


def _find_rule_block(css, selector):
    """Extract the CSS rule block for a given selector.

    Returns the content between { } for the first match.
    """
    pattern = re.escape(selector) + r'\s*\{([^}]*)\}'
    match = re.search(pattern, css)
    if match:
        return match.group(1)
    return None


def _find_media_rule_block(css, media_query, selector):
    """Extract a CSS rule block within a specific @media query."""
    media_pattern = re.escape(media_query) + r'\s*\{(.*?)\n\}'
    media_match = re.search(media_pattern, css, re.DOTALL)
    if not media_match:
        return None
    media_content = media_match.group(1)
    rule_pattern = re.escape(selector) + r'\s*\{([^}]*)\}'
    rule_match = re.search(rule_pattern, media_content)
    if rule_match:
        return rule_match.group(1)
    return None


# ============================================================================
# Task 1 — Fix overflow .status-card-details (AC2)
# ============================================================================

class TestStatusCardDetailsOverflow:
    """AC2: le contenu de .status-card-details ne déborde pas."""

    def test_status_card_details_has_max_height(self, css_content):
        block = _find_rule_block(css_content, '.status-card-details')
        assert block is not None, '.status-card-details rule not found'
        assert 'max-height' in block, '.status-card-details should have max-height'
        assert '4.5rem' in block, '.status-card-details max-height should be 4.5rem'

    def test_status_card_details_has_overflow_hidden(self, css_content):
        block = _find_rule_block(css_content, '.status-card-details')
        assert block is not None
        assert 'overflow' in block, '.status-card-details should have overflow property'

    def test_status_card_details_no_min_height_constraint(self, css_content):
        block = _find_rule_block(css_content, '.status-card-details')
        assert block is not None
        assert 'min-height' not in block, '.status-card-details should not have min-height (was 1.2rem too small)'

    def test_detail_item_has_ellipsis(self, css_content):
        block = _find_rule_block(css_content, '.status-card-details .detail-item')
        assert block is not None, '.status-card-details .detail-item rule not found'
        assert 'text-overflow' in block
        assert 'ellipsis' in block


# ============================================================================
# Task 2 — Conteneur scroll anomalies dashboard (AC1, AC4)
# ============================================================================

class TestAnomaliesListDashboardScroll:
    """AC1/AC4: scroll fluide sur .anomalies-list (dashboard)."""

    def test_anomalies_list_has_max_height(self, css_content):
        block = _find_rule_block(css_content, '.anomalies-list')
        assert block is not None, '.anomalies-list rule not found'
        assert 'max-height' in block, '.anomalies-list should have max-height'
        assert '60vh' in block, '.anomalies-list max-height should be 60vh'

    def test_anomalies_list_has_overflow_y_auto(self, css_content):
        block = _find_rule_block(css_content, '.anomalies-list')
        assert block is not None
        assert 'overflow-y' in block
        assert 'auto' in block

    def test_anomalies_list_has_smooth_scroll(self, css_content):
        block = _find_rule_block(css_content, '.anomalies-list')
        assert block is not None
        assert 'scroll-behavior' in block
        assert 'smooth' in block


# ============================================================================
# Task 3 — Conteneur scroll anomalies page (AC1, AC4)
# ============================================================================

class TestAnomalyListPageScroll:
    """AC1/AC4: scroll fluide sur .anomaly-list (page anomalies)."""

    def test_anomaly_list_has_max_height(self, css_content):
        block = _find_rule_block(css_content, '.anomaly-list')
        assert block is not None, '.anomaly-list rule not found'
        assert 'max-height' in block, '.anomaly-list should have max-height'
        assert '70vh' in block, '.anomaly-list max-height should be 70vh'

    def test_anomaly_list_has_overflow_y_auto(self, css_content):
        block = _find_rule_block(css_content, '.anomaly-list')
        assert block is not None
        assert 'overflow-y' in block

    def test_anomaly_list_has_smooth_scroll(self, css_content):
        block = _find_rule_block(css_content, '.anomaly-list')
        assert block is not None
        assert 'scroll-behavior' in block
        assert 'smooth' in block


# ============================================================================
# Task 4 — Fix responsive grid status cards (AC3)
# ============================================================================

class TestResponsiveGridStatusCards:
    """AC3: grid 1 colonne à 768px."""

    def test_status_cards_768px_single_column(self, css_content):
        """At 768px breakpoint, .status-cards should use 1fr grid."""
        block = _find_media_rule_block(
            css_content, '@media (max-width: 768px)', '.status-cards'
        )
        assert block is not None, '.status-cards rule in 768px media query not found'
        assert '1fr 1fr' not in block, '.status-cards at 768px should be 1fr, not 1fr 1fr'
        assert '1fr' in block

    def test_status_cards_480px_single_column(self, css_content):
        """At 480px breakpoint, .status-cards should use 1fr grid."""
        block = _find_media_rule_block(
            css_content, '@media (max-width: 480px)', '.status-cards'
        )
        assert block is not None, '.status-cards rule in 480px media query not found'
        assert '1fr' in block

    def test_admin_cards_768px_single_column(self, css_content):
        """At 768px breakpoint, .admin-cards should use 1fr grid."""
        block = _find_media_rule_block(
            css_content, '@media (max-width: 768px)', '.admin-cards'
        )
        assert block is not None, '.admin-cards rule in 768px media query not found'
        assert '1fr 1fr' not in block, '.admin-cards at 768px should be 1fr, not 1fr 1fr'
        assert '1fr' in block

    def test_admin_cards_480px_single_column(self, css_content):
        """At 480px breakpoint, .admin-cards should use 1fr grid."""
        block = _find_media_rule_block(
            css_content, '@media (max-width: 480px)', '.admin-cards'
        )
        assert block is not None, '.admin-cards rule in 480px media query not found'
        assert '1fr' in block


# ============================================================================
# Bonus — .essentials-modal-body scroll (Dev Notes MEDIUM bug)
# ============================================================================

class TestEssentialsModalBodyScroll:
    """Bonus: .essentials-modal-body a un scroll fonctionnel."""

    def test_essentials_modal_body_has_max_height(self, css_content):
        block = _find_rule_block(css_content, '.essentials-modal-body')
        assert block is not None, '.essentials-modal-body rule not found'
        assert 'max-height' in block, '.essentials-modal-body should have max-height'
        assert '60vh' in block, '.essentials-modal-body max-height should be 60vh'

    def test_essentials_modal_body_has_overflow_y_auto(self, css_content):
        block = _find_rule_block(css_content, '.essentials-modal-body')
        assert block is not None
        assert 'overflow-y' in block
        assert 'auto' in block

    def test_essentials_modal_body_has_smooth_scroll(self, css_content):
        block = _find_rule_block(css_content, '.essentials-modal-body')
        assert block is not None
        assert 'scroll-behavior' in block
        assert 'smooth' in block


# ============================================================================
# Task 5 — Scrollbar custom glassmorphism (AC1, AC6)
# ============================================================================

class TestScrollbarCustomStyles:
    """AC1: scrollbar stylisée cohérente avec le thème glassmorphism."""

    def test_webkit_scrollbar_exists(self, css_content):
        assert '::-webkit-scrollbar' in css_content, 'Missing ::-webkit-scrollbar styles'

    def test_webkit_scrollbar_track_exists(self, css_content):
        assert '::-webkit-scrollbar-track' in css_content, 'Missing ::-webkit-scrollbar-track styles'

    def test_webkit_scrollbar_thumb_exists(self, css_content):
        assert '::-webkit-scrollbar-thumb' in css_content, 'Missing ::-webkit-scrollbar-thumb styles'

    def test_firefox_scrollbar_thin(self, css_content):
        assert 'scrollbar-width' in css_content, 'Missing scrollbar-width for Firefox'
        assert 'thin' in css_content

    def test_firefox_scrollbar_color(self, css_content):
        assert 'scrollbar-color' in css_content, 'Missing scrollbar-color for Firefox'


# ============================================================================
# Task 6 — prefers-reduced-motion (AC5)
# ============================================================================

class TestPrefersReducedMotion:
    """AC5: toutes animations désactivées quand prefers-reduced-motion: reduce."""

    def test_reduced_motion_media_query_exists(self, css_content):
        assert '@media (prefers-reduced-motion: reduce)' in css_content

    def test_reduced_motion_disables_scroll_behavior(self, css_content):
        """scroll-behavior should be auto when reduced-motion is active."""
        # Find the reduced-motion media query block
        pattern = r'@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{(.*?)\n\}'
        match = re.search(pattern, css_content, re.DOTALL)
        assert match is not None, 'prefers-reduced-motion media query not found'
        block = match.group(1)
        assert 'scroll-behavior' in block, 'scroll-behavior should be overridden in reduced-motion'
        assert 'auto' in block

    def test_reduced_motion_disables_transitions(self, css_content):
        """Transitions should be none when reduced-motion is active."""
        pattern = r'@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{(.*?)\n\}'
        match = re.search(pattern, css_content, re.DOTALL)
        assert match is not None
        block = match.group(1)
        assert 'transition' in block, 'transitions should be disabled in reduced-motion'

    def test_reduced_motion_disables_animations(self, css_content):
        """Animations should be none when reduced-motion is active."""
        pattern = r'@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{(.*?)\n\}'
        match = re.search(pattern, css_content, re.DOTALL)
        assert match is not None
        block = match.group(1)
        assert 'animation' in block, 'animations should be disabled in reduced-motion'
