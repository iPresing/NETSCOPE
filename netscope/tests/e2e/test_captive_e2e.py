"""End-to-end tests for captive portal flow — no mocks.

Simulates the complete captive portal flow:
  Client connects → captive detection → portal page → release → internet
"""

import pytest

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


class TestCaptiveFlowE2E:
    """End-to-end captive portal flow without mocks."""

    def test_full_captive_flow_connect_detect_release(self, client):
        """E2E: complete captive portal lifecycle.

        Simulates: status check → portal access → release → verify inactive.
        """
        # Step 1: Check initial status — captive active, no released clients
        response = client.get('/api/captive/status')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['captive_active'] is True
        assert data['result']['released_clients'] == 0

        # Step 2: Access captive portal page
        response = client.get('/captive/portal')
        assert response.status_code == 200
        html = response.data.decode('utf-8')
        assert 'NETSCOPE' in html
        assert 'release-btn' in html

        # Step 3: Release client via API
        # Note: toggle script will fail (not on Pi) — CaptiveManager
        # handles FileNotFoundError gracefully, still marks released
        response = client.post(
            '/api/captive/release',
            content_type='application/json',
            data='{}',
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'client_ip' in data['result']

        # Step 4: Verify captive is now inactive
        response = client.get('/api/captive/status')
        data = response.get_json()
        assert data['result']['captive_active'] is False
        assert data['result']['released_clients'] == 1

        # Step 5: Second release is idempotent
        response = client.post(
            '/api/captive/release',
            content_type='application/json',
            data='{}',
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['result']['already_released'] is True

    def test_released_client_gets_android_success(self, client):
        """E2E: released client gets Android captive check success."""
        # Release first
        client.post(
            '/api/captive/release',
            content_type='application/json',
            data='{}',
        )

        # Android captive check after release — should get 204
        response = client.get('/generate_204')
        assert response.status_code == 204

    def test_released_client_gets_apple_success(self, client):
        """E2E: released client gets Apple captive check success."""
        client.post(
            '/api/captive/release',
            content_type='application/json',
            data='{}',
        )

        response = client.get('/hotspot-detect.html')
        assert response.status_code == 200
        assert b'Success' in response.data

    def test_released_client_gets_windows_success(self, client):
        """E2E: released client gets Windows captive check success."""
        client.post(
            '/api/captive/release',
            content_type='application/json',
            data='{}',
        )

        response = client.get('/connecttest.txt')
        assert response.status_code == 200
        assert b'Microsoft Connect Test' in response.data

    def test_portal_page_accessible_while_captive_active(self, client):
        """E2E: portal page is accessible when captive mode is active."""
        # Captive is active (default) but localhost is not intercepted
        manager = get_captive_manager()
        assert manager.is_captive_active() is True

        response = client.get('/captive/portal')
        assert response.status_code == 200

    def test_api_accessible_while_captive_active(self, client):
        """E2E: API endpoints remain accessible during captive mode."""
        manager = get_captive_manager()
        assert manager.is_captive_active() is True

        response = client.get('/api/captive/status')
        assert response.status_code == 200

        response = client.get('/api/health')
        assert response.status_code == 200

    def test_dashboard_accessible_localhost_during_captive(self, client):
        """E2E: dashboard remains accessible from localhost during captive."""
        response = client.get('/')
        # Localhost is exempt from captive intercept
        assert response.status_code == 200

    def test_full_flow_non_localhost_intercept_release(self, client):
        """E2E: non-localhost client intercepted, then released successfully."""
        remote = {'REMOTE_ADDR': '192.168.88.150'}

        # Step 1: Non-localhost client hits dashboard → redirected to portal
        response = client.get('/', environ_base=remote)
        assert response.status_code == 302
        assert '/captive/portal' in response.headers['Location']

        # Step 2: Client accesses portal page
        response = client.get('/captive/portal', environ_base=remote)
        assert response.status_code == 200
        assert b'NETSCOPE' in response.data

        # Step 3: Client releases via API
        response = client.post(
            '/api/captive/release',
            content_type='application/json',
            data='{}',
            environ_base=remote,
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['client_ip'] == '192.168.88.150'

        # Step 4: Client can now access dashboard without redirect
        response = client.get('/', environ_base=remote)
        assert response.status_code != 302 or '/captive/' not in (
            response.headers.get('Location', '')
        )
