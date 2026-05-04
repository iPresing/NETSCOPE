"""Version service for NETSCOPE system information.

Provides version, install date, system uptime, and aggregated system info.
"""

import logging
import platform
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

VERSION_FILE = Path(__file__).parent.parent.parent / 'VERSION'


class SystemInfoKey(Enum):
    """Keys for system information dictionary."""
    VERSION = "version"
    INSTALL_DATE = "install_date"
    PI_MODEL = "pi_model"
    UPTIME = "uptime"
    UPTIME_FORMATTED = "uptime_formatted"


@dataclass
class SystemInfo:
    """Aggregated system information."""
    version: str
    install_date: str
    pi_model: str
    uptime_seconds: Optional[float]
    uptime_formatted: str

    def to_dict(self) -> dict:
        return {
            SystemInfoKey.VERSION.value: self.version,
            SystemInfoKey.INSTALL_DATE.value: self.install_date,
            SystemInfoKey.PI_MODEL.value: self.pi_model,
            SystemInfoKey.UPTIME.value: self.uptime_seconds,
            SystemInfoKey.UPTIME_FORMATTED.value: self.uptime_formatted,
        }


_instance: Optional['VersionService'] = None


class VersionService:
    """Singleton service for version and system information."""

    def __init__(self):
        self._version: Optional[str] = None

    def get_version(self) -> str:
        if self._version is None:
            self._version = self._read_version_file()
        return self._version

    def get_install_date(self) -> str:
        try:
            mtime = VERSION_FILE.stat().st_mtime
            dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M UTC')
        except (OSError, ValueError):
            return 'N/A'

    def get_system_uptime(self) -> Optional[float]:
        uptime = self._read_proc_uptime()
        if uptime is not None:
            return uptime
        return self._read_psutil_uptime()

    def get_uptime_formatted(self) -> str:
        return self._format_uptime(self.get_system_uptime())

    def get_system_info(self) -> SystemInfo:
        from app.services.hardware_detection import get_hardware_info
        try:
            hardware = get_hardware_info()
            pi_model = hardware.model_name
        except Exception:
            logger.warning('Hardware detection failed, using fallback')
            pi_model = 'N/A'
        uptime_seconds = self.get_system_uptime()
        return SystemInfo(
            version=self.get_version(),
            install_date=self.get_install_date(),
            pi_model=pi_model,
            uptime_seconds=uptime_seconds,
            uptime_formatted=self._format_uptime(uptime_seconds),
        )

    @staticmethod
    def _format_uptime(seconds: Optional[float]) -> str:
        if seconds is None:
            return 'N/A'
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        if days > 0:
            return f'{days}j {hours}h {minutes}m'
        if hours > 0:
            return f'{hours}h {minutes}m'
        return f'{minutes}m'

    def _read_version_file(self) -> str:
        try:
            return VERSION_FILE.read_text(encoding='utf-8').strip()
        except (OSError, ValueError):
            logger.warning('VERSION file not found, using fallback')
            return '0.0.0'

    @staticmethod
    def _read_proc_uptime() -> Optional[float]:
        if platform.system() != 'Linux':
            return None
        try:
            content = Path('/proc/uptime').read_text(encoding='utf-8')
            return float(content.split()[0])
        except (OSError, ValueError, IndexError):
            return None

    @staticmethod
    def _read_psutil_uptime() -> Optional[float]:
        try:
            import psutil
            return time.time() - psutil.boot_time()
        except (ImportError, OSError):
            return None


def get_version_service() -> VersionService:
    global _instance
    if _instance is None:
        _instance = VersionService()
    return _instance


def reset_version_service() -> None:
    global _instance
    _instance = None
