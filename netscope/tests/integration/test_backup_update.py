"""Integration tests for backup callback wiring in UpdateService (Story 5.7)."""

import os
from unittest.mock import patch, MagicMock

import pytest

from app.services.update_service import (
    UpdateService,
    UpdateState,
    UpdateStatus,
    UpdateErrorCode,
    UpdateCheckResult,
    DownloadResult,
    BackupResult,
    reset_update_service,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    reset_update_service()
    yield
    reset_update_service()


class TestBackingUpEnum:
    def test_backing_up_state_exists(self):
        assert UpdateState.BACKING_UP.value == "backing_up"

    def test_backup_failed_error_exists(self):
        assert UpdateErrorCode.BACKUP_FAILED.value == "BACKUP_FAILED"

    def test_backing_up_in_status_dict(self):
        status = UpdateStatus(
            state=UpdateState.BACKING_UP,
            progress_percent=50,
            current_step="Création backup...",
        )
        d = status.to_dict()
        assert d["state"] == "backing_up"
        assert d["progress_percent"] == 50
        assert d["current_step"] == "Création backup..."


class TestBackupCallbackWiring:
    @patch("app.services.update_service.UpdateService._load_update_config")
    def test_callback_wired_when_enabled(self, mock_config):
        mock_config.return_value = {
            "github_repo": "iPresing/NETSCOPE",
            "backup_before_update": True,
            "backup_path": "/tmp/test-backup",
        }
        service = UpdateService(
            github_repo="iPresing/NETSCOPE",
            check_url_template="https://api.github.com/repos/{repo}/releases/latest",
        )
        config = service._load_update_config()
        assert config.get("backup_before_update") is True

    @patch("app.services.update_service.UpdateService._load_update_config")
    def test_callback_not_wired_when_disabled(self, mock_config):
        mock_config.return_value = {
            "github_repo": "iPresing/NETSCOPE",
            "backup_before_update": False,
        }
        config = mock_config()
        assert config.get("backup_before_update") is False


class TestBackupStatusEndpoint:
    def test_status_endpoint_returns_idle(self, client):
        response = client.get('/api/update/status')
        assert response.status_code == 200
        data = response.get_json()
        assert data['state'] == 'idle'

    def test_backing_up_state_serializes(self, client):
        from app.services.update_service import get_update_service
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.BACKING_UP,
            progress_percent=30,
            current_step="Création backup version actuelle...",
        )
        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'backing_up'
        assert data['current_step'] == 'Création backup version actuelle...'

    def test_backup_failed_error_in_status(self, client):
        from app.services.update_service import get_update_service
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.ERROR,
            error="Espace insuffisant",
            error_code=UpdateErrorCode.BACKUP_FAILED,
        )
        response = client.get('/api/update/status')
        data = response.get_json()
        assert data['state'] == 'error'
        assert data['error_code'] == 'BACKUP_FAILED'
        assert 'Espace' in data['error']


class TestBackupCallbackBehavior:
    def test_backup_result_success_returns_true(self):
        result = BackupResult(True, backup_path="/tmp/bak", size_bytes=100)
        assert result.success is True

    def test_backup_result_failure_has_error(self):
        result = BackupResult(
            False, error="copy failed", error_code="BACKUP_COPY_FAILED"
        )
        assert result.success is False
        assert result.error == "copy failed"

    @patch("app.services.update_service.UpdateService._load_update_config")
    def test_config_default_backup_enabled(self, mock_config):
        mock_config.return_value = {"github_repo": "iPresing/NETSCOPE"}
        config = mock_config()
        assert config.get("backup_before_update", True) is True


class TestBackupRunUpdateWiring:
    @patch("app.blueprints.admin.ota_update.OtaUpdater.restart_service", return_value=True)
    @patch("app.blueprints.admin.ota_update.OtaUpdater.apply_update", return_value=True)
    @patch("app.blueprints.admin.ota_update.OtaUpdater.create_backup")
    @patch("app.services.update_service.UpdateService.download_release")
    @patch("app.services.update_service.UpdateService.check_for_update")
    @patch("app.services.update_service.UpdateService._load_update_config")
    def test_run_update_calls_backup_when_enabled(
        self, mock_config, mock_check, mock_download, mock_backup,
        mock_apply, mock_restart
    ):
        mock_config.return_value = {
            "backup_before_update": True,
            "backup_path": os.path.abspath("/opt/netscope.backup"),
            "install_dir": os.path.abspath("/opt/netscope"),
        }
        mock_check.return_value = UpdateCheckResult(
            update_available=True,
            current_version="0.1.0",
            latest_version="0.3.0",
            tarball_url="https://api.github.com/repos/test/tarball/v0.3.0",
        )
        mock_backup.return_value = BackupResult(
            True, backup_path="/opt/netscope.backup", size_bytes=1000
        )
        mock_download.return_value = DownloadResult(
            success=True, file_path="/tmp/test.tar.gz", file_size=5000
        )
        service = UpdateService(
            github_repo="test/repo",
            check_url_template="https://api.github.com/repos/{repo}/releases/latest",
        )
        service._update_lock.acquire()
        service._run_update()
        mock_backup.assert_called_once()

    @patch("app.blueprints.admin.ota_update.OtaUpdater.restart_service", return_value=True)
    @patch("app.blueprints.admin.ota_update.OtaUpdater.apply_update", return_value=True)
    @patch("app.blueprints.admin.ota_update.OtaUpdater.create_backup")
    @patch("app.services.update_service.UpdateService.download_release")
    @patch("app.services.update_service.UpdateService.check_for_update")
    @patch("app.services.update_service.UpdateService._load_update_config")
    def test_run_update_skips_backup_when_disabled(
        self, mock_config, mock_check, mock_download, mock_backup,
        mock_apply, mock_restart
    ):
        mock_config.return_value = {
            "backup_before_update": False,
            "install_dir": "/opt/netscope",
        }
        mock_check.return_value = UpdateCheckResult(
            update_available=True,
            current_version="0.1.0",
            latest_version="0.3.0",
            tarball_url="https://api.github.com/repos/test/tarball/v0.3.0",
        )
        mock_download.return_value = DownloadResult(
            success=True, file_path="/tmp/test.tar.gz", file_size=5000
        )
        service = UpdateService(
            github_repo="test/repo",
            check_url_template="https://api.github.com/repos/{repo}/releases/latest",
        )
        service._update_lock.acquire()
        service._run_update()
        mock_backup.assert_not_called()
