"""Integration tests for update check (Story 5.5).

Tests API endpoint and admin route with mocked GitHub responses.
"""

from unittest.mock import patch, MagicMock

import pytest


MOCK_RELEASE = {
    "tag_name": "v0.2.0",
    "name": "Release 0.2.0",
    "body": "## Changes\n- Feature X",
    "published_at": "2026-05-01T10:00:00Z",
    "html_url": "https://github.com/iPresing/NETSCOPE/releases/tag/v0.2.0",
}


def _mock_github_success(release_data=None):
    """Create a mock for requests.get that returns a successful GitHub response."""
    data = release_data or MOCK_RELEASE
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = data
    return mock_response


def _mock_github_error(status_code, headers=None):
    """Create a mock for requests.get that returns an error."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.headers = headers or {}
    return mock_response


class TestApiUpdateCheck:
    """Integration tests for GET /api/update/check."""

    @patch('app.services.update_service.requests.get')
    def test_api_update_check_returns_json(self, mock_get, client):
        mock_get.return_value = _mock_github_success()
        response = client.get('/api/update/check')

        assert response.status_code == 200
        data = response.get_json()
        assert 'update_available' in data
        assert 'current_version' in data

    @patch('app.services.update_service.requests.get')
    def test_api_update_available(self, mock_get, client):
        mock_get.return_value = _mock_github_success()
        response = client.get('/api/update/check')

        data = response.get_json()
        assert data['update_available'] is True
        assert data['latest_version'] == '0.2.0'
        assert data['changelog'] == '## Changes\n- Feature X'
        assert data['release_url'] is not None

    @patch('app.services.update_service.requests.get')
    def test_api_up_to_date(self, mock_get, client):
        release = dict(MOCK_RELEASE, tag_name="v0.1.0")
        mock_get.return_value = _mock_github_success(release)
        response = client.get('/api/update/check')

        data = response.get_json()
        assert data['update_available'] is False

    @patch('app.services.update_service.requests.get')
    def test_api_network_error(self, mock_get, client):
        import requests as req
        mock_get.side_effect = req.ConnectionError("No network")
        response = client.get('/api/update/check')

        data = response.get_json()
        assert data['update_available'] is False
        assert data['error_code'] == 'NETWORK_ERROR'
        assert data['error'] is not None

    @patch('app.services.update_service.requests.get')
    def test_api_rate_limited(self, mock_get, client):
        mock_get.return_value = _mock_github_error(429)
        response = client.get('/api/update/check')

        data = response.get_json()
        assert data['update_available'] is False
        assert data['error_code'] == 'RATE_LIMITED'

    @patch('app.services.update_service.requests.get')
    def test_api_github_not_found(self, mock_get, client):
        mock_get.return_value = _mock_github_error(404)
        response = client.get('/api/update/check')

        data = response.get_json()
        assert data['error_code'] == 'GITHUB_ERROR'


class TestAdminUpdateCheckRoute:
    """Integration tests for POST /admin/update/check."""

    @patch('app.services.update_service.requests.get')
    def test_admin_check_returns_html(self, mock_get, client):
        mock_get.return_value = _mock_github_success()
        response = client.post('/admin/update/check')

        assert response.status_code == 200
        html = response.data.decode('utf-8')
        assert 'Vérifier les Mises à Jour' in html

    @patch('app.services.update_service.requests.get')
    def test_admin_check_error_renders_page(self, mock_get, client):
        import requests as req
        mock_get.side_effect = req.ConnectionError("No net")
        response = client.post('/admin/update/check')

        assert response.status_code == 200


class TestAdminUpdateCheckServerRendering:
    """Integration tests for POST /admin/update/check server-side rendering."""

    @patch('app.services.update_service.requests.get')
    def test_post_renders_update_available(self, mock_get, client):
        mock_get.return_value = _mock_github_success()
        response = client.post('/admin/update/check')
        html = response.data.decode('utf-8')
        assert 'Nouvelle version disponible' in html
        assert 'v0.2.0' in html

    @patch('app.services.update_service.requests.get')
    def test_post_renders_up_to_date(self, mock_get, client):
        release = dict(MOCK_RELEASE, tag_name="v0.1.0")
        mock_get.return_value = _mock_github_success(release)
        response = client.post('/admin/update/check')
        html = response.data.decode('utf-8')
        assert 'Vous êtes à jour' in html

    @patch('app.services.update_service.requests.get')
    def test_post_renders_error(self, mock_get, client):
        import requests as req
        mock_get.side_effect = req.ConnectionError("No net")
        response = client.post('/admin/update/check')
        html = response.data.decode('utf-8')
        assert 'alert-danger' in html
        assert 'connexion internet' in html


class TestUpdatePageHtml:
    """Integration tests for update page template."""

    def test_update_page_has_check_button(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'btn-check-update' in html
        assert 'Vérifier mises à jour' in html

    def test_update_page_has_result_container(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'update-result' in html

    def test_update_page_has_js_fetch(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert '/api/update/check' in html
        assert 'escapeHtml' in html
