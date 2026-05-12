"""Integration tests for rollback & health check wiring in UpdateService (Story 5.8)."""

import os
import tempfile
import shutil
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


@pytest.fixture
def tmp_dirs():
    install = tempfile.mkdtemp(prefix="test-install-")
    backup = install + ".backup"
    os.makedirs(os.path.join(install, "app"), exist_ok=True)
    with open(os.path.join(install, "app", "main.py"), "w") as f:
        f.write("# main")
    shutil.copytree(install, backup)
    yield install, backup
    shutil.rmtree(install, ignore_errors=True)
    shutil.rmtree(backup, ignore_errors=True)


def _make_service():
    return UpdateService(
        github_repo="iPresing/NETSCOPE",
        check_url_template="https://api.github.com/repos/{repo}/releases/latest",
    )


def _mock_successful_preflight(service, config, install_dir):
    """Mock all steps before health check in _run_update()."""
    mock_check = UpdateCheckResult(
        update_available=True,
        current_version="0.1.0",
        latest_version="0.3.0",
        tarball_url="https://github.com/iPresing/NETSCOPE/archive/v0.3.0.tar.gz",
    )
    mock_download = DownloadResult(success=True, file_path="/tmp/fake.tar.gz", file_size=1000)
    full_config = {"update": config, "network": {"web_port": 80}}

    return {
        "check_for_update": patch.object(service, "check_for_update", return_value=mock_check),
        "download_release": patch.object(service, "download_release", return_value=mock_download),
        "load_config": patch.object(
            UpdateService, "_load_update_config", return_value=config,
        ),
        "load_full_config": patch.object(
            UpdateService, "_load_full_config", return_value=full_config,
        ),
        "cleanup_temp_dir": patch.object(service, "_cleanup_temp_dir"),
        "mkdtemp": patch("app.services.update_service.tempfile.mkdtemp", return_value="/tmp/test"),
    }


# ===========================================================================
# Task 6.1 — _run_update() séquence complète avec health check succès
# ===========================================================================

class TestRunUpdateHealthCheckSuccess:
    def test_run_update_health_ok_reaches_done(self, tmp_dirs):
        install_dir, backup_dir = tmp_dirs
        service = _make_service()
        config = {
            "install_dir": install_dir,
            "backup_before_update": True,
            "backup_path": backup_dir,
            "rollback_on_failure": True,
            "health_check_timeout": 5,
        }

        mocks = _mock_successful_preflight(service, config, install_dir)
        mock_updater = MagicMock()
        mock_updater.apply_update.return_value = True
        mock_updater.restart_service.return_value = True
        mock_updater.post_update_callback.return_value = True
        mock_updater.create_backup.return_value = BackupResult(
            success=True, backup_path=backup_dir, size_bytes=5000,
        )

        with mocks["check_for_update"], mocks["download_release"], \
             mocks["load_config"], mocks["load_full_config"], \
             mocks["cleanup_temp_dir"], mocks["mkdtemp"]:
            with patch("app.blueprints.admin.ota_update.OtaUpdater", return_value=mock_updater):
                with patch.object(service, "_health_check", return_value=True):
                    service._update_lock.acquire()
                    service._run_update()

        assert service._update_status.state == UpdateState.DONE
        assert service._update_status.current_step == "Mise à jour réussie"
        assert service._update_status.progress_percent == 100


# ===========================================================================
# Task 6.2 — _run_update() séquence rollback (mock health check failure)
# ===========================================================================

class TestRunUpdateRollback:
    def test_run_update_health_fail_triggers_rollback(self, tmp_dirs):
        install_dir, backup_dir = tmp_dirs
        service = _make_service()
        config = {
            "install_dir": install_dir,
            "backup_before_update": True,
            "backup_path": backup_dir,
            "rollback_on_failure": True,
            "health_check_timeout": 1,
        }

        mocks = _mock_successful_preflight(service, config, install_dir)
        mock_updater = MagicMock()
        mock_updater.apply_update.return_value = True
        mock_updater.restart_service.return_value = True
        mock_updater.post_update_callback.return_value = True
        mock_updater.create_backup.return_value = BackupResult(
            success=True, backup_path=backup_dir, size_bytes=5000,
        )
        mock_updater.restore_from_backup.return_value = True

        with mocks["check_for_update"], mocks["download_release"], \
             mocks["load_config"], mocks["load_full_config"], \
             mocks["cleanup_temp_dir"], mocks["mkdtemp"]:
            with patch("app.blueprints.admin.ota_update.OtaUpdater", return_value=mock_updater):
                with patch.object(service, "_health_check", return_value=False):
                    service._update_lock.acquire()
                    service._run_update()

        assert service._update_status.state == UpdateState.ROLLED_BACK
        assert "version précédente restaurée" in service._update_status.current_step
        mock_updater.restore_from_backup.assert_called_once_with(install_dir, backup_dir)

    def test_run_update_rollback_fails_becomes_rollback_failed(self, tmp_dirs):
        install_dir, backup_dir = tmp_dirs
        service = _make_service()
        config = {
            "install_dir": install_dir,
            "backup_before_update": True,
            "backup_path": backup_dir,
            "rollback_on_failure": True,
            "health_check_timeout": 1,
        }

        mocks = _mock_successful_preflight(service, config, install_dir)
        mock_updater = MagicMock()
        mock_updater.apply_update.return_value = True
        mock_updater.restart_service.return_value = True
        mock_updater.post_update_callback.return_value = True
        mock_updater.create_backup.return_value = BackupResult(
            success=True, backup_path=backup_dir, size_bytes=5000,
        )
        mock_updater.restore_from_backup.return_value = False

        with mocks["check_for_update"], mocks["download_release"], \
             mocks["load_config"], mocks["load_full_config"], \
             mocks["cleanup_temp_dir"], mocks["mkdtemp"]:
            with patch("app.blueprints.admin.ota_update.OtaUpdater", return_value=mock_updater):
                with patch.object(service, "_health_check", return_value=False):
                    service._update_lock.acquire()
                    service._run_update()

        assert service._update_status.state == UpdateState.ROLLBACK_FAILED
        assert service._update_status.error_code == UpdateErrorCode.ROLLBACK_FAILED


# ===========================================================================
# Task 6.3 — /api/update/status retourne correctement les nouveaux états
# ===========================================================================

class TestApiUpdateStatusNewStates:
    def test_status_returns_health_checking(self, client):
        from app.services.update_service import get_update_service
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.HEALTH_CHECKING,
            progress_percent=92,
            current_step="Vérification santé post-update...",
        )
        resp = client.get('/api/update/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["state"] == "health_checking"
        assert data["progress_percent"] == 92

    def test_status_returns_rolling_back(self, client):
        from app.services.update_service import get_update_service
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.ROLLING_BACK,
            progress_percent=95,
            current_step="Restauration version précédente...",
        )
        resp = client.get('/api/update/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["state"] == "rolling_back"

    def test_status_returns_rolled_back(self, client):
        from app.services.update_service import get_update_service
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.ROLLED_BACK,
            progress_percent=100,
            current_step="Update échouée, version précédente restaurée",
        )
        resp = client.get('/api/update/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["state"] == "rolled_back"
        assert "restaurée" in data["current_step"]

    def test_status_returns_rollback_failed(self, client):
        from app.services.update_service import get_update_service
        svc = get_update_service()
        svc._update_status = UpdateStatus(
            state=UpdateState.ROLLBACK_FAILED,
            error="Échec du rollback",
            error_code=UpdateErrorCode.ROLLBACK_FAILED,
        )
        resp = client.get('/api/update/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["state"] == "rollback_failed"
        assert data["error"] == "Échec du rollback"
        assert data["error_code"] == "ROLLBACK_FAILED"


# ===========================================================================
# Task 6.4 — Config rollback_on_failure: false désactive rollback
# ===========================================================================

class TestRollbackDisabled:
    def test_rollback_disabled_health_fail_becomes_error(self, tmp_dirs):
        install_dir, backup_dir = tmp_dirs
        service = _make_service()
        config = {
            "install_dir": install_dir,
            "backup_before_update": True,
            "backup_path": backup_dir,
            "rollback_on_failure": False,
            "health_check_timeout": 1,
        }

        mocks = _mock_successful_preflight(service, config, install_dir)
        mock_updater = MagicMock()
        mock_updater.apply_update.return_value = True
        mock_updater.restart_service.return_value = True
        mock_updater.post_update_callback.return_value = True
        mock_updater.create_backup.return_value = BackupResult(
            success=True, backup_path=backup_dir, size_bytes=5000,
        )

        with mocks["check_for_update"], mocks["download_release"], \
             mocks["load_config"], mocks["load_full_config"], \
             mocks["cleanup_temp_dir"], mocks["mkdtemp"]:
            with patch("app.blueprints.admin.ota_update.OtaUpdater", return_value=mock_updater):
                with patch.object(service, "_health_check", return_value=False):
                    service._update_lock.acquire()
                    service._run_update()

        assert service._update_status.state == UpdateState.ERROR
        assert service._update_status.error_code == UpdateErrorCode.HEALTH_CHECK_FAILED
        assert "Rollback désactivé" in service._update_status.error
        mock_updater.restore_from_backup.assert_not_called()
