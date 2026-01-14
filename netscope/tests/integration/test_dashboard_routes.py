"""Integration tests for dashboard routes.

Tests all dashboard routes including navigation, performance requirements,
and template inheritance.
"""

import time
import pytest


class TestDashboardRoutes:
    """Tests for main dashboard routes."""

    def test_dashboard_root_returns_200(self, client):
        """Test that / returns 200 status code (AC1)."""
        response = client.get('/')
        assert response.status_code == 200

    def test_dashboard_root_contains_netscope(self, client):
        """Test that / contains NETSCOPE in response (AC1)."""
        response = client.get('/')
        assert b'NETSCOPE' in response.data

    def test_dashboard_root_has_navigation(self, client):
        """Test that dashboard has navigation links (AC2)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'Dashboard' in html
        assert 'Anomalies' in html
        assert 'Jobs' in html
        assert 'Admin' in html

    def test_anomalies_route_returns_200(self, client):
        """Test that /anomalies returns 200 (AC2)."""
        response = client.get('/anomalies')
        assert response.status_code == 200

    def test_jobs_route_returns_200(self, client):
        """Test that /jobs returns 200 (AC2)."""
        response = client.get('/jobs')
        assert response.status_code == 200

    def test_dashboard_inherits_base_template(self, client):
        """Test that dashboard inherits from base.html (AC5)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        # base.html should include these elements
        assert '<!DOCTYPE html>' in html
        assert '<html lang="fr">' in html
        assert 'style.css' in html

    def test_anomalies_inherits_base_template(self, client):
        """Test that anomalies page inherits from base.html (AC5)."""
        response = client.get('/anomalies')
        html = response.data.decode('utf-8')
        assert '<!DOCTYPE html>' in html
        assert '<html lang="fr">' in html

    def test_jobs_inherits_base_template(self, client):
        """Test that jobs page inherits from base.html (AC5)."""
        response = client.get('/jobs')
        html = response.data.decode('utf-8')
        assert '<!DOCTYPE html>' in html
        assert '<html lang="fr">' in html


class TestAdminRoutes:
    """Tests for admin routes."""

    def test_admin_root_returns_200(self, client):
        """Test that /admin/ returns 200 (AC2)."""
        response = client.get('/admin/')
        assert response.status_code == 200

    def test_admin_update_returns_200(self, client):
        """Test that /admin/update returns 200 (AC2)."""
        response = client.get('/admin/update')
        assert response.status_code == 200

    def test_admin_config_returns_200(self, client):
        """Test that /admin/config returns 200 (AC2)."""
        response = client.get('/admin/config')
        assert response.status_code == 200

    def test_admin_inherits_base_template(self, client):
        """Test that admin pages inherit from base.html (AC5)."""
        response = client.get('/admin/')
        html = response.data.decode('utf-8')
        assert '<!DOCTYPE html>' in html
        assert '<html lang="fr">' in html

    def test_admin_shows_version(self, client):
        """Test that admin page shows NETSCOPE version (Task 4.5)."""
        response = client.get('/admin/')
        html = response.data.decode('utf-8')
        assert 'NETSCOPE' in html
        # Version should be displayed
        assert 'v0.1.0' in html or 'Version' in html


class TestDashboardPerformance:
    """Tests for dashboard performance requirements (NFR5)."""

    def test_dashboard_response_under_2_seconds(self, client):
        """Test that dashboard loads in under 2 seconds (AC3)."""
        start = time.time()
        response = client.get('/')
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 2.0, f"Dashboard took {elapsed:.2f}s, expected <2s"

    def test_anomalies_response_under_2_seconds(self, client):
        """Test that anomalies page loads in under 2 seconds."""
        start = time.time()
        response = client.get('/anomalies')
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 2.0, f"Anomalies took {elapsed:.2f}s, expected <2s"

    def test_jobs_response_under_2_seconds(self, client):
        """Test that jobs page loads in under 2 seconds."""
        start = time.time()
        response = client.get('/jobs')
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 2.0, f"Jobs took {elapsed:.2f}s, expected <2s"

    def test_admin_response_under_2_seconds(self, client):
        """Test that admin pages load in under 2 seconds."""
        routes = ['/admin/', '/admin/update', '/admin/config']

        for route in routes:
            start = time.time()
            response = client.get(route)
            elapsed = time.time() - start

            assert response.status_code == 200
            assert elapsed < 2.0, f"{route} took {elapsed:.2f}s, expected <2s"


class TestNavigationConsistency:
    """Tests for navigation consistency across pages (AC2)."""

    def test_navigation_present_on_all_pages(self, client):
        """Test that navigation is present on all pages."""
        routes = ['/', '/anomalies', '/jobs', '/admin/']

        for route in routes:
            response = client.get(route)
            html = response.data.decode('utf-8')
            assert 'Dashboard' in html, f"Navigation missing on {route}"
            assert 'Anomalies' in html, f"Navigation missing on {route}"
            assert 'Jobs' in html, f"Navigation missing on {route}"
            assert 'Admin' in html, f"Navigation missing on {route}"

    def test_active_page_indicator(self, client):
        """Test that active page has indicator class."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        # Navigation should have an active indicator mechanism
        assert 'is-active' in html or 'active' in html


class TestJavaScriptLoading:
    """Tests for JavaScript file loading (AC3, Task 7)."""

    def test_main_js_loaded(self, client):
        """Test that main.js is loaded in templates."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'js/main.js' in html

    def test_api_js_loaded(self, client):
        """Test that api.js is loaded in templates (Task 7.2)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'js/api.js' in html

    def test_toasts_js_loaded(self, client):
        """Test that toasts.js is loaded in templates (Task 7.3)."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'js/toasts.js' in html

    def test_js_defer_attribute(self, client):
        """Test that JS files use defer attribute for performance."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        # All script tags should have defer for performance
        assert 'defer' in html


class TestComponentIntegration:
    """Tests for Jinja2 component integration (AC5)."""

    def test_toast_container_present(self, client):
        """Test that toast container is included in page."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'toast-container' in html

    def test_footer_component_rendered(self, client):
        """Test that footer component is rendered with version."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'footer-content' in html or 'site-footer' in html

    def test_navigation_component_rendered(self, client):
        """Test that navigation component is included."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'main-nav' in html or 'nav-links' in html
