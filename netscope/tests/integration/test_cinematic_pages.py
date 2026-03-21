"""Integration tests for cinematic background on all pages (Story 4.8).

Tests that video background, overlays, and glassmorphism elements
are present and consistent across all application pages (AC4, AC6).
"""

import time
import pytest


class TestCinematicConsistencyAllPages:
    """Tests that cinematic elements are present on every page (AC4)."""

    PAGES = [
        ('/', 'dashboard'),
        ('/anomalies', 'anomalies'),
        ('/packets', 'packets'),
        ('/jobs', 'jobs'),
        ('/whitelist', 'whitelist'),
        ('/admin/', 'admin'),
    ]

    @pytest.mark.parametrize("route,name", PAGES)
    def test_page_returns_200(self, client, route, name):
        """Test that {name} page loads without HTTP error (AC6)."""
        response = client.get(route)
        assert response.status_code == 200, f"{name} returned {response.status_code}"

    @pytest.mark.parametrize("route,name", PAGES)
    def test_page_has_video_bg(self, client, route, name):
        """Test that {name} page contains video background (AC4)."""
        response = client.get(route)
        html = response.data.decode('utf-8')
        assert 'video-bg' in html, f"video-bg missing on {name}"

    @pytest.mark.parametrize("route,name", PAGES)
    def test_page_has_overlays(self, client, route, name):
        """Test that {name} page contains all three overlays (AC4)."""
        response = client.get(route)
        html = response.data.decode('utf-8')
        assert 'overlay-dark' in html, f"overlay-dark missing on {name}"
        assert 'overlay-vignette' in html, f"overlay-vignette missing on {name}"
        assert 'overlay-gradient' in html, f"overlay-gradient missing on {name}"

    @pytest.mark.parametrize("route,name", PAGES)
    def test_page_has_glassmorphism_header(self, client, route, name):
        """Test that {name} page has header with site-header class (AC3, AC4)."""
        response = client.get(route)
        html = response.data.decode('utf-8')
        assert 'site-header' in html, f"site-header missing on {name}"

    @pytest.mark.parametrize("route,name", PAGES)
    def test_page_has_glassmorphism_footer(self, client, route, name):
        """Test that {name} page has footer with site-footer class (AC3, AC4)."""
        response = client.get(route)
        html = response.data.decode('utf-8')
        assert 'site-footer' in html, f"site-footer missing on {name}"


class TestCinematicPerformance:
    """Tests that cinematic changes don't degrade page load time (AC5)."""

    PAGES = ['/', '/anomalies', '/packets', '/jobs', '/whitelist', '/admin/']

    @pytest.mark.parametrize("route", PAGES)
    def test_page_loads_under_2_seconds(self, client, route):
        """Test that page loads in under 2 seconds with cinematic bg (AC5)."""
        start = time.time()
        response = client.get(route)
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 2.0, f"{route} took {elapsed:.2f}s, expected <2s"


class TestNoRegressionExistingElements:
    """Tests that existing functional elements are preserved (AC6)."""

    def test_dashboard_still_has_toast_container(self, client):
        """Test that toast container is still present (AC6)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'toast-container' in html

    def test_dashboard_still_has_navigation(self, client):
        """Test that navigation links are still present (AC6)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'Dashboard' in html
        assert 'Anomalies' in html
        assert 'Jobs' in html
        assert 'Admin' in html

    def test_dashboard_still_loads_js_files(self, client):
        """Test that JS files are still loaded with defer (AC6)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'js/api.js' in html
        assert 'js/toasts.js' in html
        assert 'js/main.js' in html
        assert 'defer' in html

    def test_degradation_banner_still_present(self, client):
        """Test that degradation banner element is still in DOM (AC6)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'degradation-banner' in html
