"""Unit tests for UpdateService (Story 5.5).

Tests cover: version parsing, update detection, error handling
(network, timeout, rate limit, 404, parse errors).
"""

import time
from unittest.mock import patch, MagicMock

import pytest

from app.services.update_service import (
    UpdateService,
    UpdateCheckResult,
    UpdateErrorCode,
    parse_version,
    reset_update_service,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    reset_update_service()
    yield
    reset_update_service()


@pytest.fixture
def service():
    return UpdateService(
        github_repo="iPresing/NETSCOPE",
        check_url_template="https://api.github.com/repos/{repo}/releases/latest",
    )


@pytest.fixture
def mock_github_release():
    return {
        "tag_name": "v0.2.0",
        "name": "Release 0.2.0",
        "body": "## Changelog\n- New feature",
        "published_at": "2026-05-01T10:00:00Z",
        "html_url": "https://github.com/iPresing/NETSCOPE/releases/tag/v0.2.0",
    }


class TestParseVersion:
    def test_parse_simple_version(self):
        assert parse_version("1.2.3") == (1, 2, 3)

    def test_parse_version_with_v_prefix(self):
        assert parse_version("v1.2.3") == (1, 2, 3)

    def test_parse_version_with_spaces(self):
        assert parse_version(" v1.0.0 ") == (1, 0, 0)

    def test_compare_versions(self):
        assert parse_version("0.2.0") > parse_version("0.1.0")
        assert parse_version("1.0.0") > parse_version("0.9.9")
        assert parse_version("0.1.0") == parse_version("v0.1.0")

    def test_parse_version_with_prerelease(self):
        assert parse_version("1.0.0-beta.1") == (1, 0, 0)

    def test_parse_version_with_build_metadata(self):
        assert parse_version("1.0.0+build.123") == (1, 0, 0)

    def test_prerelease_compare(self):
        assert parse_version("0.2.0-rc.1") > parse_version("0.1.0")

    def test_invalid_version_raises(self):
        with pytest.raises(ValueError):
            parse_version("not-a-version")


class TestUpdateCheckResultToDict:
    def test_success_result_to_dict(self):
        result = UpdateCheckResult(
            update_available=True,
            current_version="0.1.0",
            latest_version="0.2.0",
            changelog="changes",
            published_at="2026-05-01",
            release_url="https://example.com",
        )
        d = result.to_dict()
        assert d["update_available"] is True
        assert d["current_version"] == "0.1.0"
        assert d["latest_version"] == "0.2.0"
        assert "error" not in d

    def test_error_result_to_dict(self):
        result = UpdateCheckResult(
            update_available=False,
            current_version="0.1.0",
            error="Network error",
            error_code=UpdateErrorCode.NETWORK_ERROR,
        )
        d = result.to_dict()
        assert d["update_available"] is False
        assert d["error"] == "Network error"
        assert d["error_code"] == "NETWORK_ERROR"


class TestCheckForUpdateSuccess:
    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_update_available(self, mock_get, mock_version_svc, service, mock_github_release):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_release
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is True
        assert result.current_version == "0.1.0"
        assert result.latest_version == "0.2.0"
        assert result.changelog == "## Changelog\n- New feature"
        assert result.published_at == "2026-05-01T10:00:00Z"
        assert result.error is None

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_already_up_to_date(self, mock_get, mock_version_svc, service, mock_github_release):
        mock_version_svc.return_value.get_version.return_value = "0.2.0"
        mock_github_release["tag_name"] = "v0.2.0"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_release
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False
        assert result.current_version == "0.2.0"
        assert result.error is None

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_current_newer_than_remote(self, mock_get, mock_version_svc, service, mock_github_release):
        mock_version_svc.return_value.get_version.return_value = "0.3.0"
        mock_github_release["tag_name"] = "v0.2.0"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_release
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False


class TestCheckForUpdateErrors:
    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_connection_error(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        import requests as req
        mock_get.side_effect = req.ConnectionError("No internet")

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.NETWORK_ERROR
        assert "connexion internet" in result.error

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_timeout_error(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        import requests as req
        mock_get.side_effect = req.Timeout("Timeout")

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.NETWORK_ERROR
        assert "Délai" in result.error

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_rate_limited_403(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {"X-RateLimit-Reset": str(int(time.time()) + 300)}
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.RATE_LIMITED
        assert "minutes" in result.error

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_rate_limited_429(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {}
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.RATE_LIMITED

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_github_404(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.GITHUB_ERROR
        assert "introuvable" in result.error

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_invalid_json_response(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.PARSE_ERROR

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_missing_tag_name_key(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"name": "no tag_name"}
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.PARSE_ERROR

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_connect_timeout_shows_timeout_message(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        import requests as req
        mock_get.side_effect = req.ConnectTimeout("Connect timeout")

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.NETWORK_ERROR
        assert "Délai" in result.error

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_generic_http_error_500(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.GITHUB_ERROR
        assert "500" in result.error

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_unparseable_version_in_tag(self, mock_get, mock_version_svc, service):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"tag_name": "not-semver"}
        mock_get.return_value = mock_response

        result = service.check_for_update()

        assert result.update_available is False
        assert result.error_code == UpdateErrorCode.PARSE_ERROR


class TestCheckForUpdateHeaders:
    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_request_uses_correct_headers(self, mock_get, mock_version_svc, service, mock_github_release):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_release
        mock_get.return_value = mock_response

        service.check_for_update()

        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["headers"]["User-Agent"] == "NETSCOPE-Updater/0.1.0"
        assert "github" in call_kwargs["headers"]["Accept"]
        assert call_kwargs["timeout"] == 10

    @patch('app.services.update_service.get_version_service')
    @patch('app.services.update_service.requests.get')
    def test_request_url_contains_repo(self, mock_get, mock_version_svc, service, mock_github_release):
        mock_version_svc.return_value.get_version.return_value = "0.1.0"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_github_release
        mock_get.return_value = mock_response

        service.check_for_update()

        call_url = mock_get.call_args[0][0]
        assert "iPresing/NETSCOPE" in call_url
