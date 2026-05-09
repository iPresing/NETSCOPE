"""Unit tests for backup creation before OTA update (Story 5.7)."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from app.blueprints.admin.ota_update import OtaUpdater, BackupResult


@pytest.fixture
def updater(tmp_path):
    return OtaUpdater(install_dir=str(tmp_path / "install"))


@pytest.fixture
def install_dir(tmp_path):
    d = tmp_path / "install"
    d.mkdir()
    (d / "app").mkdir()
    (d / "app" / "main.py").write_text("print('hello')", encoding="utf-8")
    (d / "config.yaml").write_text("key: value", encoding="utf-8")
    return str(d)


@pytest.fixture
def backup_dir(tmp_path):
    return str(tmp_path / "backup")


def _disk(free=1_000_000_000):
    return MagicMock(free=free)


class TestBackupResultDataclass:
    def test_success_fields(self):
        r = BackupResult(True, backup_path="/backup", size_bytes=1000)
        assert r.success is True
        assert r.backup_path == "/backup"
        assert r.size_bytes == 1000
        assert r.error is None
        assert r.error_code is None

    def test_failure_fields(self):
        r = BackupResult(False, error="disk full", error_code="INSUFFICIENT_DISK_SPACE")
        assert r.success is False
        assert r.backup_path == ""
        assert r.size_bytes == 0
        assert r.error == "disk full"
        assert r.error_code == "INSUFFICIENT_DISK_SPACE"


class TestCreateBackupSuccess:
    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_creates_backup_directory(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        result = updater.create_backup(install_dir, backup_dir)
        assert result.success is True
        assert os.path.isdir(backup_dir)

    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_copies_all_files(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        updater.create_backup(install_dir, backup_dir)
        assert os.path.isfile(os.path.join(backup_dir, "app", "main.py"))
        assert os.path.isfile(os.path.join(backup_dir, "config.yaml"))

    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_returns_correct_backup_path(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        result = updater.create_backup(install_dir, backup_dir)
        assert result.backup_path == backup_dir

    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_returns_correct_size_bytes(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        expected_size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, fns in os.walk(install_dir)
            for f in fns
        )
        result = updater.create_backup(install_dir, backup_dir)
        assert result.size_bytes == expected_size
        assert result.size_bytes > 0


class TestCreateBackupInfoJson:
    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_creates_backup_info_file(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        updater.create_backup(install_dir, backup_dir)
        assert os.path.isfile(os.path.join(backup_dir, "backup-info.json"))

    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_info_contains_version(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        updater.create_backup(install_dir, backup_dir)
        with open(os.path.join(backup_dir, "backup-info.json"), encoding="utf-8") as f:
            info = json.load(f)
        assert info["version"] == "0.1.0"

    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_info_contains_created_at_iso(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        updater.create_backup(install_dir, backup_dir)
        with open(os.path.join(backup_dir, "backup-info.json"), encoding="utf-8") as f:
            info = json.load(f)
        assert "created_at" in info
        assert "T" in info["created_at"]

    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_info_contains_size_bytes(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        updater.create_backup(install_dir, backup_dir)
        with open(os.path.join(backup_dir, "backup-info.json"), encoding="utf-8") as f:
            info = json.load(f)
        assert info["size_bytes"] > 0

    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_info_contains_source_dir(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        updater.create_backup(install_dir, backup_dir)
        with open(os.path.join(backup_dir, "backup-info.json"), encoding="utf-8") as f:
            info = json.load(f)
        assert info["source_dir"] == install_dir


class TestCreateBackupFailures:
    def test_install_dir_not_found(self, updater, tmp_path):
        result = updater.create_backup(str(tmp_path / "nope"), str(tmp_path / "bak"))
        assert result.success is False
        assert result.error_code == "INSTALL_NOT_FOUND"

    @patch("shutil.disk_usage")
    def test_insufficient_disk_space(self, mock_du, updater, install_dir, backup_dir):
        mock_du.return_value = _disk(free=10)
        result = updater.create_backup(install_dir, backup_dir)
        assert result.success is False
        assert result.error_code == "INSUFFICIENT_DISK_SPACE"

    @patch("shutil.disk_usage", side_effect=OSError("disk error"))
    def test_disk_check_oserror(self, mock_du, updater, install_dir, backup_dir):
        result = updater.create_backup(install_dir, backup_dir)
        assert result.success is False
        assert result.error_code == "DISK_CHECK_FAILED"

    @patch("shutil.copytree", side_effect=OSError("copy failed"))
    @patch("shutil.disk_usage")
    def test_copytree_failure(self, mock_du, mock_ct, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        result = updater.create_backup(install_dir, backup_dir)
        assert result.success is False
        assert result.error_code == "BACKUP_COPY_FAILED"
        assert "copy failed" in result.error

    @patch("shutil.copytree", side_effect=OSError("copy failed"))
    @patch("shutil.disk_usage")
    def test_copytree_failure_cleans_partial(self, mock_du, mock_ct, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        os.makedirs(backup_dir)
        updater.create_backup(install_dir, backup_dir)
        assert not os.path.exists(backup_dir)


class TestCreateBackupDiskThreshold:
    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_exact_2x_threshold_passes(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        install_size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, fns in os.walk(install_dir)
            for f in fns
        )
        mock_du.return_value = _disk(free=install_size * 2)
        mock_vs.return_value.get_version.return_value = "0.1.0"
        result = updater.create_backup(install_dir, backup_dir)
        assert result.success is True

    @patch("shutil.disk_usage")
    def test_below_2x_threshold_fails(self, mock_du, updater, install_dir, backup_dir):
        install_size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, fns in os.walk(install_dir)
            for f in fns
        )
        mock_du.return_value = _disk(free=install_size * 2 - 1)
        result = updater.create_backup(install_dir, backup_dir)
        assert result.success is False
        assert result.error_code == "INSUFFICIENT_DISK_SPACE"


class TestCreateBackupOverwrite:
    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_overwrites_existing_backup(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        os.makedirs(backup_dir)
        old_marker = os.path.join(backup_dir, "old_marker.txt")
        with open(old_marker, "w") as f:
            f.write("old")
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        result = updater.create_backup(install_dir, backup_dir)
        assert result.success is True
        assert not os.path.exists(old_marker)
        assert os.path.isfile(os.path.join(backup_dir, "app", "main.py"))


class TestCreateBackupInfoWriteFailure:
    @patch("app.services.version_service.get_version_service")
    @patch("shutil.disk_usage")
    def test_info_write_failure_cleans_backup(self, mock_du, mock_vs, updater, install_dir, backup_dir):
        mock_du.return_value = _disk()
        mock_vs.return_value.get_version.return_value = "0.1.0"
        with patch("app.blueprints.admin.ota_update.json.dump", side_effect=OSError("write error")):
            result = updater.create_backup(install_dir, backup_dir)
        assert result.success is False
        assert result.error_code == "BACKUP_INFO_FAILED"
