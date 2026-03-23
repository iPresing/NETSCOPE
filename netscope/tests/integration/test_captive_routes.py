"""Integration tests for captive portal routes and API endpoints."""

import pytest
from unittest.mock import patch

from app.blueprints.captive.captive_manager import (
    get_captive_manager,
    reset_captive_manager,
)


@pytest.fixture(autouse=True)
def reset_manager():
    """Reset captive manager before each test."""
    reset_captive_manager()
    yield
    reset_captive_manager()


class TestCaptivePortalPage:
    """Tests for GET /captive/portal."""

    def test_portal_returns_200(self, client):
        """Portal page returns 200 for unreleased client."""
        manager = get_captive_manager()
        # Captive is active, but localhost is skipped by before_app_request
        # Direct access to /captive/portal should work
        response = client.get('/captive/portal')
        assert response.status_code == 200

    def test_portal_contains_netscope_branding(self, client):
        """Portal page contains NETSCOPE branding."""
        response = client.get('/captive/portal')
        html = response.data.decode('utf-8')
        assert 'NETSCOPE' in html

    def test_portal_contains_release_button(self, client):
        """Portal page contains the release button."""
        response = client.get('/captive/portal')
        html = response.data.decode('utf-8')
        assert 'release-btn' in html

    def test_portal_contains_internet_text(self, client):
        """Portal page contains 'Accéder à Internet' text."""
        response = client.get('/captive/portal')
        html = response.data.decode('utf-8')
        assert 'Internet' in html


class TestCaptiveAPIStatus:
    """Tests for GET /api/captive/status."""

    def test_status_returns_200(self, client):
        """Status endpoint returns 200."""
        response = client.get('/api/captive/status')
        assert response.status_code == 200

    def test_status_returns_json(self, client):
        """Status endpoint returns valid JSON."""
        response = client.get('/api/captive/status')
        data = response.get_json()
        assert data['success'] is True
        assert 'result' in data

    def test_status_initial_captive_active(self, client):
        """Initial status shows captive active."""
        response = client.get('/api/captive/status')
        data = response.get_json()
        assert data['result']['captive_active'] is True
        assert data['result']['released_clients'] == 0

    def test_status_after_release(self, client):
        """Status reflects release after client is released."""
        manager = get_captive_manager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('192.168.88.100')
        response = client.get('/api/captive/status')
        data = response.get_json()
        assert data['result']['captive_active'] is False
        assert data['result']['released_clients'] == 1

    def test_status_format_standard(self, client):
        """Status response follows standard API format."""
        response = client.get('/api/captive/status')
        data = response.get_json()
        assert 'success' in data
        assert 'result' in data
        assert 'message' in data


class TestCaptiveAPIRelease:
    """Tests for POST /api/captive/release."""

    def test_release_returns_200(self, client):
        """Release endpoint returns 200."""
        with patch(
            'app.blueprints.captive.captive_manager.subprocess.run'
        ) as mock_run:
            mock_run.side_effect = FileNotFoundError()
            response = client.post(
                '/api/captive/release',
                content_type='application/json',
                data='{}',
            )
        assert response.status_code == 200

    def test_release_returns_success(self, client):
        """Release returns success JSON."""
        with patch(
            'app.blueprints.captive.captive_manager.subprocess.run'
        ) as mock_run:
            mock_run.side_effect = FileNotFoundError()
            response = client.post(
                '/api/captive/release',
                content_type='application/json',
                data='{}',
            )
        data = response.get_json()
        assert data['success'] is True
        assert 'client_ip' in data['result']

    def test_release_disables_captive(self, client):
        """Release disables captive mode."""
        with patch(
            'app.blueprints.captive.captive_manager.subprocess.run'
        ) as mock_run:
            mock_run.side_effect = FileNotFoundError()
            client.post(
                '/api/captive/release',
                content_type='application/json',
                data='{}',
            )
        manager = get_captive_manager()
        assert manager.is_captive_active() is False

    def test_release_idempotent(self, client):
        """Releasing twice returns already_released."""
        with patch(
            'app.blueprints.captive.captive_manager.subprocess.run'
        ) as mock_run:
            mock_run.side_effect = FileNotFoundError()
            client.post(
                '/api/captive/release',
                content_type='application/json',
                data='{}',
            )
            response = client.post(
                '/api/captive/release',
                content_type='application/json',
                data='{}',
            )
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['already_released'] is True

    def test_release_format_standard(self, client):
        """Release response follows standard API format."""
        with patch(
            'app.blueprints.captive.captive_manager.subprocess.run'
        ) as mock_run:
            mock_run.side_effect = FileNotFoundError()
            response = client.post(
                '/api/captive/release',
                content_type='application/json',
                data='{}',
            )
        data = response.get_json()
        assert 'success' in data
        assert 'result' in data
        assert 'message' in data


class TestCaptiveInterceptBehavior:
    """Tests for before_app_request captive intercept logic."""

    def test_localhost_not_intercepted(self, client):
        """Requests from localhost are never intercepted."""
        # Test client uses 127.0.0.1 by default
        response = client.get('/')
        # Should reach dashboard, not be redirected to portal
        assert response.status_code != 302 or '/captive/' not in (
            response.headers.get('Location', '')
        )

    def test_static_not_intercepted(self, client):
        """Static file requests are not intercepted."""
        response = client.get('/static/css/style.css')
        # Should return 200 or 404, not 302 to captive
        assert response.status_code != 302 or '/captive/' not in (
            response.headers.get('Location', '')
        )

    def test_captive_endpoint_not_intercepted(self, client):
        """Captive blueprint endpoints are accessible without redirect."""
        response = client.get('/captive/portal')
        assert response.status_code == 200

    def test_api_captive_not_intercepted(self, client):
        """API captive endpoints are accessible without redirect."""
        response = client.get('/api/captive/status')
        assert response.status_code == 200


class TestCaptiveDetectionResponses:
    """Tests for OS-specific captive portal detection responses."""

    def test_android_204_when_released(self, client):
        """Android captive check returns 204 for released client."""
        manager = get_captive_manager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('127.0.0.1')
        response = client.get('/generate_204')
        assert response.status_code == 204

    def test_apple_success_when_released(self, client):
        """Apple captive check returns Success body for released client."""
        manager = get_captive_manager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('127.0.0.1')
        response = client.get('/hotspot-detect.html')
        assert response.status_code == 200
        assert b'Success' in response.data

    def test_windows_connecttest_when_released(self, client):
        """Windows captive check returns connecttest body for released client."""
        manager = get_captive_manager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('127.0.0.1')
        response = client.get('/connecttest.txt')
        assert response.status_code == 200
        assert b'Microsoft Connect Test' in response.data

    def test_firefox_canonical_when_released(self, client):
        """Firefox captive check returns success for released client."""
        manager = get_captive_manager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('127.0.0.1')
        response = client.get('/canonical.html')
        assert response.status_code == 200

    def test_captive_inactive_no_intercept(self, client):
        """When captive is inactive, no interception occurs."""
        manager = get_captive_manager()
        manager._captive_active = False
        response = client.get('/')
        # Should NOT redirect to captive portal
        assert response.status_code != 302 or '/captive/' not in (
            response.headers.get('Location', '')
        )


class TestCaptiveInterceptNonLocalhost:
    """Tests for captive intercept with non-localhost clients (H2 fix)."""

    def test_non_localhost_redirected_to_portal(self, client):
        """Non-localhost unreleased client is redirected to captive portal."""
        response = client.get(
            '/',
            environ_base={'REMOTE_ADDR': '192.168.88.100'},
        )
        assert response.status_code == 302
        assert '/captive/portal' in response.headers.get('Location', '')

    def test_non_localhost_api_captive_not_intercepted(self, client):
        """Non-localhost client can still access /api/captive/ endpoints."""
        response = client.get(
            '/api/captive/status',
            environ_base={'REMOTE_ADDR': '192.168.88.100'},
        )
        assert response.status_code == 200

    def test_non_localhost_captive_portal_not_intercepted(self, client):
        """Non-localhost client can access /captive/portal directly."""
        response = client.get(
            '/captive/portal',
            environ_base={'REMOTE_ADDR': '192.168.88.100'},
        )
        assert response.status_code == 200

    def test_non_localhost_released_not_intercepted(self, client):
        """Non-localhost released client is NOT redirected."""
        manager = get_captive_manager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('192.168.88.100')
        response = client.get(
            '/',
            environ_base={'REMOTE_ADDR': '192.168.88.100'},
        )
        assert response.status_code != 302 or '/captive/' not in (
            response.headers.get('Location', '')
        )

    def test_non_localhost_dashboard_intercepted(self, client):
        """Non-localhost unreleased client intercepted on /admin too."""
        response = client.get(
            '/admin/',
            environ_base={'REMOTE_ADDR': '192.168.88.101'},
        )
        assert response.status_code == 302
        assert '/captive/portal' in response.headers.get('Location', '')


class TestCaptivePortalReleasedRedirect:
    """Tests for released client visiting /captive/portal (M3 fix)."""

    def test_released_client_redirected_from_portal(self, client):
        """Released client visiting /captive/portal is redirected to dashboard."""
        manager = get_captive_manager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('127.0.0.1')
        response = client.get('/captive/portal')
        assert response.status_code == 302
        assert '/' in response.headers.get('Location', '')
