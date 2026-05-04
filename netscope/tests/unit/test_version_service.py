"""Unit tests for VersionService."""

import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.services.version_service import (
    VersionService,
    SystemInfo,
    SystemInfoKey,
    get_version_service,
    reset_version_service,
    VERSION_FILE,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset VersionService singleton between tests."""
    reset_version_service()
    yield
    reset_version_service()


class TestGetVersion:
    """Tests for VersionService.get_version()."""

    def test_get_version_reads_file(self, tmp_path):
        """get_version returns content of VERSION file."""
        version_file = tmp_path / 'VERSION'
        version_file.write_text('1.2.3\n', encoding='utf-8')

        service = VersionService()
        with patch('app.services.version_service.VERSION_FILE', version_file):
            result = service.get_version()

        assert result == '1.2.3'

    def test_get_version_strips_whitespace(self, tmp_path):
        version_file = tmp_path / 'VERSION'
        version_file.write_text('  2.0.0  \n', encoding='utf-8')

        service = VersionService()
        with patch('app.services.version_service.VERSION_FILE', version_file):
            result = service.get_version()

        assert result == '2.0.0'

    def test_get_version_caches_result(self, tmp_path):
        version_file = tmp_path / 'VERSION'
        version_file.write_text('1.0.0\n', encoding='utf-8')

        service = VersionService()
        with patch('app.services.version_service.VERSION_FILE', version_file):
            first = service.get_version()
            version_file.write_text('2.0.0\n', encoding='utf-8')
            second = service.get_version()

        assert first == second == '1.0.0'

    def test_get_version_fallback_missing_file(self):
        service = VersionService()
        with patch('app.services.version_service.VERSION_FILE', Path('/nonexistent/VERSION')):
            result = service.get_version()

        assert result == '0.0.0'

    def test_get_version_reads_actual_version_file(self):
        service = VersionService()
        result = service.get_version()
        assert result == '0.1.0'


class TestGetInstallDate:
    """Tests for VersionService.get_install_date()."""

    def test_get_install_date_returns_formatted_mtime(self, tmp_path):
        version_file = tmp_path / 'VERSION'
        version_file.write_text('1.0.0\n', encoding='utf-8')

        service = VersionService()
        with patch('app.services.version_service.VERSION_FILE', version_file):
            result = service.get_install_date()

        assert result.endswith(' UTC')
        datetime.strptime(result, '%Y-%m-%d %H:%M UTC')

    def test_get_install_date_missing_file_returns_na(self):
        service = VersionService()
        with patch('app.services.version_service.VERSION_FILE', Path('/nonexistent/VERSION')):
            result = service.get_install_date()

        assert result == 'N/A'


class TestGetSystemUptime:
    """Tests for VersionService.get_system_uptime()."""

    def test_get_uptime_linux_proc(self):
        service = VersionService()
        with patch('app.services.version_service.platform.system', return_value='Linux'):
            with patch('app.services.version_service.Path') as mock_path_cls:
                mock_path_cls.return_value.read_text.return_value = '12345.67 98765.43\n'
                result = service._read_proc_uptime()
        assert result == 12345.67

    def test_get_uptime_returns_float_or_none(self):
        service = VersionService()
        result = service.get_system_uptime()
        # On any platform: either a positive float or None
        assert result is None or (isinstance(result, float) and result > 0)

    def test_get_uptime_fallback_psutil(self):
        service = VersionService()
        with patch('app.services.version_service.platform.system', return_value='Windows'):
            with patch('app.services.version_service.VersionService._read_psutil_uptime', return_value=3600.0):
                result = service.get_system_uptime()

        assert result == 3600.0

    def test_get_uptime_all_fail_returns_none(self):
        service = VersionService()
        with patch('app.services.version_service.platform.system', return_value='Windows'):
            with patch('app.services.version_service.VersionService._read_psutil_uptime', return_value=None):
                result = service.get_system_uptime()

        assert result is None


class TestGetUptimeFormatted:
    """Tests for VersionService.get_uptime_formatted()."""

    def test_format_days_hours_minutes(self):
        service = VersionService()
        with patch.object(service, 'get_system_uptime', return_value=90061.0):
            result = service.get_uptime_formatted()
        assert result == '1j 1h 1m'

    def test_format_hours_minutes(self):
        service = VersionService()
        with patch.object(service, 'get_system_uptime', return_value=7260.0):
            result = service.get_uptime_formatted()
        assert result == '2h 1m'

    def test_format_minutes_only(self):
        service = VersionService()
        with patch.object(service, 'get_system_uptime', return_value=300.0):
            result = service.get_uptime_formatted()
        assert result == '5m'

    def test_format_none_uptime(self):
        service = VersionService()
        with patch.object(service, 'get_system_uptime', return_value=None):
            result = service.get_uptime_formatted()
        assert result == 'N/A'


class TestGetSystemInfo:
    """Tests for VersionService.get_system_info()."""

    def test_get_system_info_aggregates_all(self, tmp_path):
        version_file = tmp_path / 'VERSION'
        version_file.write_text('1.5.0\n', encoding='utf-8')

        mock_hardware = MagicMock()
        mock_hardware.model_name = 'Raspberry Pi 4 Model B'

        service = VersionService()
        with patch('app.services.version_service.VERSION_FILE', version_file):
            with patch('app.services.hardware_detection.get_hardware_info', return_value=mock_hardware):
                with patch.object(service, 'get_system_uptime', return_value=7200.0):
                    info = service.get_system_info()

        assert isinstance(info, SystemInfo)
        assert info.version == '1.5.0'
        assert info.pi_model == 'Raspberry Pi 4 Model B'
        assert info.uptime_seconds == 7200.0
        assert info.uptime_formatted == '2h 0m'

    def test_system_info_to_dict(self):
        info = SystemInfo(
            version='1.0.0',
            install_date='2026-01-01 10:00',
            pi_model='Raspberry Pi 4',
            uptime_seconds=3600.0,
            uptime_formatted='1h 0m',
        )
        d = info.to_dict()
        assert d[SystemInfoKey.VERSION.value] == '1.0.0'
        assert d[SystemInfoKey.INSTALL_DATE.value] == '2026-01-01 10:00'
        assert d[SystemInfoKey.PI_MODEL.value] == 'Raspberry Pi 4'
        assert d[SystemInfoKey.UPTIME.value] == 3600.0
        assert d[SystemInfoKey.UPTIME_FORMATTED.value] == '1h 0m'


class TestSingleton:
    """Tests for singleton pattern."""

    def test_get_version_service_returns_same_instance(self):
        s1 = get_version_service()
        s2 = get_version_service()
        assert s1 is s2

    def test_reset_version_service_creates_new_instance(self):
        s1 = get_version_service()
        reset_version_service()
        s2 = get_version_service()
        assert s1 is not s2
