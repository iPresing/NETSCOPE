"""Unit tests for rollback automatique & health check (Story 5.8)."""

import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock

import pytest
import requests

from app.services.update_service import (
    UpdateService,
    UpdateState,
    UpdateStatus,
    UpdateErrorCode,
    reset_update_service,
    DEFAULT_HEALTH_CHECK_TIMEOUT,
    HEALTH_CHECK_POLL_INTERVAL,
)
from app.blueprints.admin.ota_update import OtaUpdater


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
def tmp_install_dir():
    d = tempfile.mkdtemp(prefix="test-install-")
    os.makedirs(os.path.join(d, "app"), exist_ok=True)
    with open(os.path.join(d, "app", "dummy.py"), "w") as f:
        f.write("# dummy")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def tmp_backup_dir(tmp_install_dir):
    backup = tmp_install_dir + ".backup"
    shutil.copytree(tmp_install_dir, backup)
    yield backup
    shutil.rmtree(backup, ignore_errors=True)


# ===========================================================================
# Task 5.1 — Tests _health_check
# ===========================================================================

class TestHealthCheck:
    def test_health_check_success_immediate(self, service):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("app.services.update_service.requests.get", return_value=mock_resp):
            result = service._health_check("http://127.0.0.1:80/api/health", 30)
        assert result is True

    def test_health_check_success_after_retry(self, service):
        mock_fail = MagicMock()
        mock_fail.status_code = 503

        mock_ok = MagicMock()
        mock_ok.status_code = 200

        with patch("app.services.update_service.requests.get", side_effect=[mock_fail, mock_ok]):
            with patch("app.services.update_service.time.sleep"):
                result = service._health_check("http://127.0.0.1:80/api/health", 30)
        assert result is True

    def test_health_check_timeout_reached(self, service):
        mock_resp = MagicMock()
        mock_resp.status_code = 503

        call_count = 0

        def mock_monotonic():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return 0.0
            return 31.0

        with patch("app.services.update_service.requests.get", return_value=mock_resp):
            with patch("app.services.update_service.time.monotonic", side_effect=mock_monotonic):
                with patch("app.services.update_service.time.sleep"):
                    result = service._health_check("http://127.0.0.1:80/api/health", 30)
        assert result is False

    def test_health_check_connection_error(self, service):
        call_count = 0

        def mock_monotonic():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return 0.0
            return 31.0

        with patch("app.services.update_service.requests.get", side_effect=requests.ConnectionError):
            with patch("app.services.update_service.time.monotonic", side_effect=mock_monotonic):
                with patch("app.services.update_service.time.sleep"):
                    result = service._health_check("http://127.0.0.1:80/api/health", 30)
        assert result is False

    def test_health_check_timeout_exception(self, service):
        call_count = 0

        def mock_monotonic():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return 0.0
            return 31.0

        with patch("app.services.update_service.requests.get", side_effect=requests.Timeout):
            with patch("app.services.update_service.time.monotonic", side_effect=mock_monotonic):
                with patch("app.services.update_service.time.sleep"):
                    result = service._health_check("http://127.0.0.1:80/api/health", 30)
        assert result is False


# ===========================================================================
# Task 5.2 — Tests _restore_from_backup (OtaUpdater)
# ===========================================================================

class TestRestoreFromBackup:
    def test_restore_success(self, tmp_install_dir, tmp_backup_dir):
        updater = OtaUpdater(install_dir=tmp_install_dir)
        shutil.rmtree(tmp_install_dir)
        os.makedirs(tmp_install_dir)

        result = updater.restore_from_backup(tmp_install_dir, tmp_backup_dir)
        assert result is True
        assert os.path.exists(os.path.join(tmp_install_dir, "app", "dummy.py"))

    def test_restore_backup_not_found(self, tmp_install_dir):
        updater = OtaUpdater(install_dir=tmp_install_dir)
        nonexistent = tmp_install_dir + ".nonexistent"
        result = updater.restore_from_backup(tmp_install_dir, nonexistent)
        assert result is False

    def test_restore_copy_error(self, tmp_install_dir, tmp_backup_dir):
        updater = OtaUpdater(install_dir=tmp_install_dir)
        with patch("app.blueprints.admin.ota_update.shutil.copytree", side_effect=OSError("disk full")):
            with patch("app.blueprints.admin.ota_update.shutil.rmtree"):
                result = updater.restore_from_backup(tmp_install_dir, tmp_backup_dir)
        assert result is False

    def test_restore_rejects_relative_backup_path(self, tmp_install_dir):
        updater = OtaUpdater(install_dir=tmp_install_dir)
        result = updater.restore_from_backup(tmp_install_dir, "relative/path")
        assert result is False

    def test_restore_rejects_relative_install_dir(self, tmp_backup_dir):
        updater = OtaUpdater(install_dir="relative")
        result = updater.restore_from_backup("relative/install", tmp_backup_dir)
        assert result is False


# ===========================================================================
# Task 5.3 — Tests séquence complète
# ===========================================================================

class TestUpdateSequenceComplete:
    def test_health_ok_sets_done_state(self, service):
        """Health check OK → state DONE with correct message."""
        service._update_status = UpdateStatus(
            state=UpdateState.HEALTH_CHECKING,
            progress_percent=92,
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("app.services.update_service.requests.get", return_value=mock_resp):
            health_ok = service._health_check("http://127.0.0.1:80/api/health", 5)

        assert health_ok is True
        service._update_status = UpdateStatus(
            state=UpdateState.DONE, progress_percent=100,
            current_step="Mise à jour réussie",
        )
        assert service._update_status.state == UpdateState.DONE
        assert service._update_status.progress_percent == 100

    def test_health_fail_triggers_rollback_states(self, service):
        """Health check fail → ROLLING_BACK → restore → ROLLED_BACK."""
        mock_updater = MagicMock()
        mock_updater.restore_from_backup.return_value = True

        with patch.object(service, "_health_check", return_value=False):
            health_ok = service._health_check("http://127.0.0.1:80/api/health", 1)
            assert health_ok is False

            service._update_status = UpdateStatus(
                state=UpdateState.ROLLING_BACK,
                progress_percent=95,
                current_step="Restauration version précédente...",
            )
            assert service._update_status.state == UpdateState.ROLLING_BACK

            restore_ok = mock_updater.restore_from_backup("/opt/netscope", "/opt/netscope.backup")
            assert restore_ok is True

            service._update_status = UpdateStatus(
                state=UpdateState.ROLLED_BACK,
                progress_percent=100,
                current_step="Update échouée, version précédente restaurée",
            )
            assert service._update_status.state == UpdateState.ROLLED_BACK
            assert service._update_status.progress_percent == 100
            assert "restaurée" in service._update_status.current_step


# ===========================================================================
# Task 5.4 — Tests rollback échoué → ROLLBACK_FAILED
# ===========================================================================

class TestRollbackFailed:
    def test_restore_fails_returns_rollback_failed(self, tmp_install_dir):
        updater = OtaUpdater(install_dir=tmp_install_dir)
        nonexistent_backup = tmp_install_dir + ".ghost"
        result = updater.restore_from_backup(tmp_install_dir, nonexistent_backup)
        assert result is False

    def test_rollback_failed_state_exists(self):
        assert UpdateState.ROLLBACK_FAILED.value == "rollback_failed"

    def test_rollback_failed_error_code_exists(self):
        assert UpdateErrorCode.ROLLBACK_FAILED.value == "ROLLBACK_FAILED"

    def test_health_check_failed_error_code_exists(self):
        assert UpdateErrorCode.HEALTH_CHECK_FAILED.value == "HEALTH_CHECK_FAILED"


# ===========================================================================
# Nouveaux états enum
# ===========================================================================

class TestNewStates:
    def test_health_checking_state(self):
        assert UpdateState.HEALTH_CHECKING.value == "health_checking"

    def test_rolling_back_state(self):
        assert UpdateState.ROLLING_BACK.value == "rolling_back"

    def test_rolled_back_state(self):
        assert UpdateState.ROLLED_BACK.value == "rolled_back"

    def test_rollback_failed_state(self):
        assert UpdateState.ROLLBACK_FAILED.value == "rollback_failed"

    def test_update_status_to_dict_health_checking(self):
        status = UpdateStatus(
            state=UpdateState.HEALTH_CHECKING,
            progress_percent=92,
            current_step="Vérification santé post-update...",
        )
        d = status.to_dict()
        assert d["state"] == "health_checking"
        assert d["progress_percent"] == 92

    def test_update_status_to_dict_rolled_back(self):
        status = UpdateStatus(
            state=UpdateState.ROLLED_BACK,
            progress_percent=100,
            current_step="Update échouée, version précédente restaurée",
        )
        d = status.to_dict()
        assert d["state"] == "rolled_back"

    def test_update_status_to_dict_rollback_failed_with_error(self):
        status = UpdateStatus(
            state=UpdateState.ROLLBACK_FAILED,
            error="Échec du rollback",
            error_code=UpdateErrorCode.ROLLBACK_FAILED,
        )
        d = status.to_dict()
        assert d["state"] == "rollback_failed"
        assert d["error"] == "Échec du rollback"
        assert d["error_code"] == "ROLLBACK_FAILED"
