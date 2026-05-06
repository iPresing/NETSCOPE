"""E2E tests for update check feature (Story 5.5).

Tests the full user journey: page load → button click → result display.
GitHub API is mocked at the requests layer.
"""

from unittest.mock import patch, MagicMock

import pytest
from bs4 import BeautifulSoup


MOCK_RELEASE_NEW = {
    "tag_name": "v0.2.0",
    "name": "Release 0.2.0",
    "body": "## Changelog\n- New feature added",
    "published_at": "2026-05-01T10:00:00Z",
    "html_url": "https://github.com/iPresing/NETSCOPE/releases/tag/v0.2.0",
}

MOCK_RELEASE_SAME = {
    "tag_name": "v0.1.0",
    "name": "Release 0.1.0",
    "body": "Initial release",
    "published_at": "2026-01-01T00:00:00Z",
    "html_url": "https://github.com/iPresing/NETSCOPE/releases/tag/v0.1.0",
}


class TestUpdateCheckPageStructure:
    """E2E: Verify page structure for update check."""

    def test_page_loads_without_error(self, client):
        response = client.get('/admin/update')
        assert response.status_code == 200

    def test_check_button_present_and_enabled(self, client):
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        btn = soup.find(id='btn-check-update')
        assert btn is not None
        assert btn.get('disabled') is None
        assert 'Vérifier mises à jour' in btn.get_text()

    def test_spinner_hidden_initially(self, client):
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        spinner = soup.find(id='update-spinner')
        assert spinner is not None
        assert 'hidden' in spinner.get('class', [])

    def test_result_container_hidden_initially(self, client):
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        result = soup.find(id='update-result')
        assert result is not None
        assert 'hidden' in result.get('class', [])

    def test_version_info_displayed(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'v0.1.0' in html

    def test_javascript_included(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'btn-check-update' in html
        assert 'fetch(' in html
        assert '/api/update/check' in html


class TestUpdateCheckApiEndToEnd:
    """E2E: API endpoint returns correct data for different scenarios."""

    @patch('app.services.update_service.requests.get')
    def test_new_version_available_full_response(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = MOCK_RELEASE_NEW
        mock_get.return_value = mock_response

        response = client.get('/api/update/check')
        data = response.get_json()

        assert data['update_available'] is True
        assert data['current_version'] == '0.1.0'
        assert data['latest_version'] == '0.2.0'
        assert 'Changelog' in data['changelog']
        assert '2026-05-01' in data['published_at']
        assert 'github.com' in data['release_url']
        assert 'error' not in data

    @patch('app.services.update_service.requests.get')
    def test_already_up_to_date_full_response(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = MOCK_RELEASE_SAME
        mock_get.return_value = mock_response

        response = client.get('/api/update/check')
        data = response.get_json()

        assert data['update_available'] is False
        assert data['current_version'] == '0.1.0'
        assert 'error' not in data

    @patch('app.services.update_service.requests.get')
    def test_network_error_full_response(self, mock_get, client):
        import requests as req
        mock_get.side_effect = req.ConnectionError("No internet")

        response = client.get('/api/update/check')
        data = response.get_json()

        assert data['update_available'] is False
        assert data['error_code'] == 'NETWORK_ERROR'
        assert 'connexion internet' in data['error']

    @patch('app.services.update_service.requests.get')
    def test_rate_limit_with_reset_header(self, mock_get, client):
        import time
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"X-RateLimit-Reset": str(int(time.time()) + 600)}
        mock_get.return_value = mock_response

        response = client.get('/api/update/check')
        data = response.get_json()

        assert data['error_code'] == 'RATE_LIMITED'
        assert 'minutes' in data['error']


class TestUpdateCheckSecurityE2E:
    """E2E: Security considerations for update check."""

    def test_xss_prevention_in_template(self, client):
        """Verify template does not use |safe or innerHTML with unescaped content."""
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'escapeHtml' in html
        assert '| safe' not in html

    def test_url_scheme_validation_in_js(self, client):
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert "startsWith('https://')" in html

    @patch('app.services.update_service.requests.get')
    def test_api_response_content_type(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = MOCK_RELEASE_NEW
        mock_get.return_value = mock_response

        response = client.get('/api/update/check')
        assert 'application/json' in response.content_type
