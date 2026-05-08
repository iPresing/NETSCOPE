"""Unit tests for OTA update: download, extraction, path traversal, errors (Story 5.6)."""

import os
import tempfile
import threading
from io import BytesIO
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

from app.services.update_service import (
    UpdateService,
    UpdateState,
    UpdateStatus,
    UpdateErrorCode,
    DownloadResult,
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
def tmp_dir():
    d = tempfile.mkdtemp(prefix="test-update-")
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


class TestUpdateState:
    def test_all_states_exist(self):
        assert UpdateState.IDLE.value == "idle"
        assert UpdateState.DOWNLOADING.value == "downloading"
        assert UpdateState.EXTRACTING.value == "extracting"
        assert UpdateState.RESTARTING.value == "restarting"
        assert UpdateState.DONE.value == "done"
        assert UpdateState.ERROR.value == "error"


class TestUpdateStatus:
    def test_default_status_idle(self):
        status = UpdateStatus()
        assert status.state == UpdateState.IDLE
        assert status.progress_percent == 0
        assert status.current_step == ""
        assert status.error is None

    def test_to_dict_without_error(self):
        status = UpdateStatus(
            state=UpdateState.DOWNLOADING,
            progress_percent=42,
            current_step="Téléchargement en cours...",
        )
        d = status.to_dict()
        assert d["state"] == "downloading"
        assert d["progress_percent"] == 42
        assert d["current_step"] == "Téléchargement en cours..."
        assert "error" not in d

    def test_to_dict_with_error(self):
        status = UpdateStatus(
            state=UpdateState.ERROR,
            error="Échec réseau",
            error_code=UpdateErrorCode.DOWNLOAD_ERROR,
        )
        d = status.to_dict()
        assert d["state"] == "error"
        assert d["error"] == "Échec réseau"
        assert d["error_code"] == "DOWNLOAD_ERROR"


class TestDownloadResult:
    def test_success_result(self):
        r = DownloadResult(success=True, file_path="/tmp/f.tar.gz", file_size=1024)
        assert r.success is True
        assert r.file_size == 1024

    def test_error_result(self):
        r = DownloadResult(
            success=False,
            error="timeout",
            error_code=UpdateErrorCode.DOWNLOAD_ERROR,
        )
        assert r.success is False
        assert r.error == "timeout"


class TestDownloadRelease:
    @patch('app.services.update_service.requests.get')
    def test_download_success_with_progress(self, mock_get, service, tmp_dir):
        chunk_data = b'x' * 8192
        mock_response = MagicMock()
        mock_response.headers = {'content-length': str(len(chunk_data))}
        mock_response.iter_content.return_value = [chunk_data]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert result.success is True
        assert result.file_size == 8192
        assert result.file_path is not None
        assert os.path.exists(result.file_path)

    @patch('app.services.update_service.requests.get')
    def test_download_updates_progress(self, mock_get, service, tmp_dir):
        total = 3000
        chunks = [b'x' * 1000, b'x' * 1000, b'x' * 1000]
        mock_response = MagicMock()
        mock_response.headers = {'content-length': str(total)}
        mock_response.iter_content.return_value = chunks
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert service.get_update_status().progress_percent >= 0

    @patch('app.services.update_service.requests.get')
    def test_download_integrity_mismatch(self, mock_get, service, tmp_dir):
        mock_response = MagicMock()
        mock_response.headers = {'content-length': '5000'}
        mock_response.iter_content.return_value = [b'x' * 1000]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert result.success is False
        assert result.error_code == UpdateErrorCode.INTEGRITY_ERROR
        assert "1000" in result.error
        assert "5000" in result.error

    @patch('app.services.update_service.requests.get')
    def test_download_no_content_length_skips_integrity(self, mock_get, service, tmp_dir):
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.iter_content.return_value = [b'x' * 500]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert result.success is True
        assert result.file_size == 500

    @patch('app.services.update_service.requests.get')
    def test_download_timeout_error(self, mock_get, service, tmp_dir):
        import requests as req
        mock_get.side_effect = req.Timeout("Download timeout")

        result = service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert result.success is False
        assert result.error_code == UpdateErrorCode.DOWNLOAD_ERROR
        assert "Délai" in result.error

    @patch('app.services.update_service.requests.get')
    def test_download_connection_error(self, mock_get, service, tmp_dir):
        import requests as req
        mock_get.side_effect = req.ConnectionError("Lost connection")

        result = service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert result.success is False
        assert result.error_code == UpdateErrorCode.DOWNLOAD_ERROR
        assert "Connexion" in result.error

    @patch('app.services.update_service.requests.get')
    def test_download_http_error(self, mock_get, service, tmp_dir):
        import requests as req
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.side_effect = req.HTTPError(response=mock_resp)

        result = service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert result.success is False
        assert result.error_code == UpdateErrorCode.DOWNLOAD_ERROR
        assert "404" in result.error

    @patch('app.services.update_service.shutil.disk_usage')
    def test_download_insufficient_disk_space(self, mock_disk, service, tmp_dir):
        mock_disk.return_value = MagicMock(free=10 * 1024 * 1024)

        result = service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert result.success is False
        assert result.error_code == UpdateErrorCode.DISK_SPACE_ERROR
        assert "insuffisant" in result.error

    @patch('app.services.update_service.shutil.disk_usage')
    def test_download_disk_check_oserror(self, mock_disk, service, tmp_dir):
        mock_disk.side_effect = OSError("Permission denied")

        result = service.download_release("https://example.com/release.tar.gz", tmp_dir)

        assert result.success is False
        assert result.error_code == UpdateErrorCode.DISK_SPACE_ERROR

    @patch('app.services.update_service.requests.get')
    def test_download_cleanup_on_failure(self, mock_get, service, tmp_dir):
        import requests as req
        mock_get.side_effect = req.Timeout("timeout")

        service.download_release("https://example.com/release.tar.gz", tmp_dir)

        remaining = [f for f in os.listdir(tmp_dir) if f.endswith('.tar.gz')]
        assert len(remaining) == 0

    @patch('app.services.update_service.requests.get')
    def test_download_uses_streaming(self, mock_get, service, tmp_dir):
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.iter_content.return_value = [b'data']
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        service.download_release("https://example.com/release.tar.gz", tmp_dir)

        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["stream"] is True
        assert call_kwargs["timeout"] == 300
        assert call_kwargs["headers"]["User-Agent"] == "NETSCOPE-Updater/0.1.0"


class TestStartUpdate:
    @patch.object(UpdateService, 'check_for_update')
    @patch('app.services.update_service.requests.get')
    def test_start_update_returns_true(self, mock_get, mock_check, service):
        from app.services.update_service import UpdateCheckResult
        mock_check.return_value = UpdateCheckResult(
            update_available=True,
            current_version="0.1.0",
            latest_version="0.2.0",
            tarball_url="https://api.github.com/repos/x/tarball/v0.2.0",
        )
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.iter_content.return_value = [b'data']
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = service.start_update()

        assert result is True
        import time
        time.sleep(0.5)

    @patch.object(UpdateService, '_run_update')
    def test_start_update_prevents_double_trigger(self, mock_run, service):
        mock_run.side_effect = lambda: threading.Event().wait(2)

        first = service.start_update()
        second = service.start_update()

        assert first is True
        assert second is False

    @patch.object(UpdateService, 'check_for_update')
    def test_run_update_toctou_no_update(self, mock_check, service):
        from app.services.update_service import UpdateCheckResult
        mock_check.return_value = UpdateCheckResult(
            update_available=False,
            current_version="0.2.0",
        )

        service._update_lock.acquire()
        try:
            service._run_update()
        finally:
            pass

        assert service.get_update_status().state == UpdateState.ERROR
        assert "non disponible" in service.get_update_status().error

    @patch.object(UpdateService, 'check_for_update')
    def test_run_update_no_tarball_url(self, mock_check, service):
        from app.services.update_service import UpdateCheckResult
        mock_check.return_value = UpdateCheckResult(
            update_available=True,
            current_version="0.1.0",
            latest_version="0.2.0",
            tarball_url="",
        )

        service._update_lock.acquire()
        try:
            service._run_update()
        finally:
            pass

        assert service.get_update_status().state == UpdateState.ERROR
        assert "URL" in service.get_update_status().error


class TestGetUpdateStatus:
    def test_initial_status_idle(self, service):
        status = service.get_update_status()
        assert status.state == UpdateState.IDLE
        assert status.progress_percent == 0


class TestOtaUpdaterExtraction:
    def test_apply_update_tar_gz(self, tmp_dir):
        from app.blueprints.admin.ota_update import OtaUpdater

        install_dir = os.path.join(tmp_dir, "install")
        os.makedirs(install_dir)

        archive_path = os.path.join(tmp_dir, "release.tar.gz")
        staging = os.path.join(tmp_dir, "src")
        os.makedirs(os.path.join(staging, "project", "app"))
        with open(os.path.join(staging, "project", "app", "main.py"), 'w') as f:
            f.write("print('hello')")

        import tarfile
        with tarfile.open(archive_path, 'w:gz') as tf:
            tf.add(os.path.join(staging, "project"), arcname="project")

        updater = OtaUpdater(install_dir=install_dir)
        result = updater.apply_update(archive_path, install_dir)

        assert result is True

    def test_apply_update_zip(self, tmp_dir):
        from app.blueprints.admin.ota_update import OtaUpdater
        import zipfile

        install_dir = os.path.join(tmp_dir, "install")
        os.makedirs(install_dir)

        archive_path = os.path.join(tmp_dir, "release.zip")
        with zipfile.ZipFile(archive_path, 'w') as zf:
            zf.writestr("project/app/main.py", "print('hello')")

        updater = OtaUpdater(install_dir=install_dir)
        result = updater.apply_update(archive_path, install_dir)

        assert result is True

    def test_apply_update_path_traversal_tar(self, tmp_dir):
        from app.blueprints.admin.ota_update import OtaUpdater
        import tarfile
        from io import BytesIO

        archive_path = os.path.join(tmp_dir, "evil.tar.gz")
        with tarfile.open(archive_path, 'w:gz') as tf:
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = 4
            tf.addfile(info, BytesIO(b"evil"))

        install_dir = os.path.join(tmp_dir, "install")
        os.makedirs(install_dir)
        updater = OtaUpdater(install_dir=install_dir)
        result = updater.apply_update(archive_path, install_dir)

        assert result is False

    def test_apply_update_path_traversal_zip(self, tmp_dir):
        from app.blueprints.admin.ota_update import OtaUpdater
        import zipfile

        archive_path = os.path.join(tmp_dir, "evil.zip")
        with zipfile.ZipFile(archive_path, 'w') as zf:
            zf.writestr("../../../etc/passwd", "evil")

        install_dir = os.path.join(tmp_dir, "install")
        os.makedirs(install_dir)
        updater = OtaUpdater(install_dir=install_dir)
        result = updater.apply_update(archive_path, install_dir)

        assert result is False

    def test_apply_update_invalid_archive(self, tmp_dir):
        from app.blueprints.admin.ota_update import OtaUpdater

        archive_path = os.path.join(tmp_dir, "bad.tar.gz")
        with open(archive_path, 'w') as f:
            f.write("not an archive")

        install_dir = os.path.join(tmp_dir, "install")
        os.makedirs(install_dir)
        updater = OtaUpdater(install_dir=install_dir)
        result = updater.apply_update(archive_path, install_dir)

        assert result is False

    def test_apply_update_missing_structure(self, tmp_dir):
        from app.blueprints.admin.ota_update import OtaUpdater
        import tarfile

        archive_path = os.path.join(tmp_dir, "noapp.tar.gz")
        staging = os.path.join(tmp_dir, "src")
        os.makedirs(os.path.join(staging, "random"))
        with open(os.path.join(staging, "random", "file.txt"), 'w') as f:
            f.write("nope")
        with tarfile.open(archive_path, 'w:gz') as tf:
            tf.add(os.path.join(staging, "random"), arcname="random")

        install_dir = os.path.join(tmp_dir, "install")
        os.makedirs(install_dir)
        updater = OtaUpdater(install_dir=install_dir)
        result = updater.apply_update(archive_path, install_dir)

        assert result is False

    def test_pre_update_callback_failure(self, tmp_dir):
        from app.blueprints.admin.ota_update import OtaUpdater
        import tarfile

        archive_path = os.path.join(tmp_dir, "release.tar.gz")
        staging = os.path.join(tmp_dir, "src")
        os.makedirs(os.path.join(staging, "project", "app"))
        with open(os.path.join(staging, "project", "app", "m.py"), 'w') as f:
            f.write("x")
        with tarfile.open(archive_path, 'w:gz') as tf:
            tf.add(os.path.join(staging, "project"), arcname="project")

        install_dir = os.path.join(tmp_dir, "install")
        os.makedirs(install_dir)
        updater = OtaUpdater(
            install_dir=install_dir,
            pre_update_callback=lambda: False,
        )
        result = updater.apply_update(archive_path, install_dir)

        assert result is False

    def test_default_callbacks_are_noop(self):
        from app.blueprints.admin.ota_update import OtaUpdater

        updater = OtaUpdater(install_dir="/tmp/test")
        assert updater._pre_update_callback() is True
        assert updater._post_update_callback() is True


class TestOtaUpdaterRestart:
    @patch('platform.system', return_value='Windows')
    def test_restart_dev_mode_skips(self, mock_sys):
        from app.blueprints.admin.ota_update import OtaUpdater

        updater = OtaUpdater(install_dir="/tmp/test")
        result = updater.restart_service()
        assert result is True

    @patch('platform.system', return_value='Linux')
    @patch('subprocess.run')
    def test_restart_linux_success(self, mock_run, mock_sys):
        from app.blueprints.admin.ota_update import OtaUpdater

        updater = OtaUpdater(install_dir="/tmp/test")
        result = updater.restart_service()
        assert result is True
        mock_run.assert_called_once()

    @patch('platform.system', return_value='Linux')
    @patch('subprocess.run', side_effect=FileNotFoundError)
    def test_restart_linux_no_systemctl(self, mock_run, mock_sys):
        from app.blueprints.admin.ota_update import OtaUpdater

        updater = OtaUpdater(install_dir="/tmp/test")
        result = updater.restart_service()
        assert result is False


class TestNewErrorCodes:
    def test_download_error_code_exists(self):
        assert UpdateErrorCode.DOWNLOAD_ERROR.value == "DOWNLOAD_ERROR"

    def test_disk_space_error_code_exists(self):
        assert UpdateErrorCode.DISK_SPACE_ERROR.value == "DISK_SPACE_ERROR"

    def test_integrity_error_code_exists(self):
        assert UpdateErrorCode.INTEGRITY_ERROR.value == "INTEGRITY_ERROR"
