"""Update service for checking GitHub releases.

Provides version comparison and update availability detection
via the GitHub Releases API.
"""

import logging
import os
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import requests

from app.services.version_service import get_version_service

logger = logging.getLogger(__name__)

GITHUB_API_TIMEOUT = 10
DOWNLOAD_TIMEOUT = 300
DOWNLOAD_CHUNK_SIZE = 8192
MIN_DISK_SPACE_MB = 100
USER_AGENT = "NETSCOPE-Updater/0.1.0"
ALLOWED_DOWNLOAD_HOSTS = ("https://api.github.com/", "https://github.com/")


class UpdateErrorCode(Enum):
    """Error codes for update check failures."""
    NETWORK_ERROR = "NETWORK_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    GITHUB_ERROR = "GITHUB_ERROR"
    PARSE_ERROR = "PARSE_ERROR"
    DOWNLOAD_ERROR = "DOWNLOAD_ERROR"
    DISK_SPACE_ERROR = "DISK_SPACE_ERROR"
    INTEGRITY_ERROR = "INTEGRITY_ERROR"
    BACKUP_FAILED = "BACKUP_FAILED"


@dataclass
class UpdateCheckResult:
    """Result of an update availability check."""
    update_available: bool
    current_version: str
    latest_version: Optional[str] = None
    changelog: Optional[str] = None
    published_at: Optional[str] = None
    release_url: Optional[str] = None
    tarball_url: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[UpdateErrorCode] = None

    def to_dict(self) -> dict:
        result = {
            "update_available": self.update_available,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "changelog": self.changelog,
            "published_at": self.published_at,
            "release_url": self.release_url,
        }
        if self.error:
            result["error"] = self.error
            result["error_code"] = self.error_code.value if self.error_code else None
        return result


class UpdateState(Enum):
    """States for the OTA update process."""
    IDLE = "idle"
    BACKING_UP = "backing_up"
    DOWNLOADING = "downloading"
    EXTRACTING = "extracting"
    RESTARTING = "restarting"
    DONE = "done"
    ERROR = "error"


@dataclass
class UpdateStatus:
    """Current status of an ongoing update."""
    state: UpdateState = UpdateState.IDLE
    progress_percent: int = 0
    current_step: str = ""
    error: Optional[str] = None
    error_code: Optional[UpdateErrorCode] = None

    def to_dict(self) -> dict:
        result = {
            "state": self.state.value,
            "progress_percent": self.progress_percent,
            "current_step": self.current_step,
        }
        if self.error:
            result["error"] = self.error
            result["error_code"] = self.error_code.value if self.error_code else None
        return result


@dataclass
class DownloadResult:
    """Result of a release download operation."""
    success: bool
    file_path: Optional[str] = None
    file_size: int = 0
    error: Optional[str] = None
    error_code: Optional[UpdateErrorCode] = None


@dataclass
class BackupResult:
    """Result of a backup operation."""
    success: bool
    backup_path: str = ""
    size_bytes: int = 0
    error: Optional[str] = None
    error_code: Optional[str] = None


def parse_version(v: str) -> tuple:
    """Parse 'v1.2.3' or '1.2.3-beta' into comparable tuple."""
    clean = v.strip().lstrip('v')
    clean = clean.split('-')[0].split('+')[0]
    return tuple(int(x) for x in clean.split('.'))


_instance: Optional['UpdateService'] = None


class UpdateService:
    """Singleton service for checking GitHub releases."""

    def __init__(self, github_repo: str, check_url_template: str):
        self._github_repo = github_repo
        self._check_url = check_url_template.format(repo=github_repo)
        self._update_status = UpdateStatus()
        self._update_lock = threading.Lock()
        self._last_download: Optional[DownloadResult] = None

    def check_for_update(self) -> UpdateCheckResult:
        """Check GitHub API for latest release and compare versions."""
        current_version = get_version_service().get_version()

        try:
            response = requests.get(
                self._check_url,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": USER_AGENT,
                },
                timeout=GITHUB_API_TIMEOUT,
            )
        except requests.Timeout:
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Délai de connexion dépassé. Réessayez plus tard.",
                error_code=UpdateErrorCode.NETWORK_ERROR,
            )
        except requests.ConnectionError:
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Impossible de contacter GitHub. Vérifiez votre connexion internet.",
                error_code=UpdateErrorCode.NETWORK_ERROR,
            )

        if response.status_code in (403, 429):
            retry_msg = self._format_rate_limit_message(response)
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error=retry_msg,
                error_code=UpdateErrorCode.RATE_LIMITED,
            )

        if response.status_code == 404:
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Dépôt GitHub introuvable. Vérifiez la configuration.",
                error_code=UpdateErrorCode.GITHUB_ERROR,
            )

        if response.status_code != 200:
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error=f"Erreur GitHub (HTTP {response.status_code}).",
                error_code=UpdateErrorCode.GITHUB_ERROR,
            )

        try:
            data = response.json()
            tag_name = data["tag_name"]
            latest_version = tag_name.lstrip('v').strip()
            changelog = data.get("body", "")
            published_at = data.get("published_at", "")
            release_url = data.get("html_url", "")
            tarball_url = data.get("tarball_url", "")
        except (ValueError, KeyError, TypeError):
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Réponse inattendue de GitHub.",
                error_code=UpdateErrorCode.PARSE_ERROR,
            )

        try:
            update_available = parse_version(latest_version) > parse_version(current_version)
        except (ValueError, TypeError):
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Réponse inattendue de GitHub.",
                error_code=UpdateErrorCode.PARSE_ERROR,
            )

        return UpdateCheckResult(
            update_available=update_available,
            current_version=current_version,
            latest_version=latest_version,
            changelog=changelog,
            published_at=published_at,
            release_url=release_url,
            tarball_url=tarball_url,
        )

    @staticmethod
    def _format_rate_limit_message(response: requests.Response) -> str:
        reset_timestamp = response.headers.get("X-RateLimit-Reset")
        if reset_timestamp:
            try:
                reset_time = int(reset_timestamp)
                minutes_remaining = max(1, int((reset_time - time.time()) / 60))
                return (
                    f"Limite de requêtes GitHub atteinte. "
                    f"Réessayez dans {minutes_remaining} minutes."
                )
            except (ValueError, TypeError):
                pass
        return "Limite de requêtes GitHub atteinte. Réessayez plus tard."

    def get_update_status(self) -> UpdateStatus:
        status = self._update_status
        return UpdateStatus(
            state=status.state,
            progress_percent=status.progress_percent,
            current_step=status.current_step,
            error=status.error,
            error_code=status.error_code,
        )

    def start_update(self) -> bool:
        if not self._update_lock.acquire(blocking=False):
            return False
        self._update_status = UpdateStatus(
            state=UpdateState.DOWNLOADING,
            current_step="Vérification version...",
        )
        thread = threading.Thread(target=self._run_update, daemon=True)
        thread.start()
        return True

    def _run_update(self) -> None:
        try:
            check = self.check_for_update()
            if not check.update_available:
                self._update_status = UpdateStatus(
                    state=UpdateState.ERROR,
                    error="Mise à jour non disponible (re-vérification échouée).",
                    error_code=UpdateErrorCode.GITHUB_ERROR,
                )
                return

            tarball_url = check.tarball_url
            if not tarball_url:
                self._update_status = UpdateStatus(
                    state=UpdateState.ERROR,
                    error="URL de téléchargement non disponible.",
                    error_code=UpdateErrorCode.DOWNLOAD_ERROR,
                )
                return

            if not any(tarball_url.startswith(host) for host in ALLOWED_DOWNLOAD_HOSTS):
                self._update_status = UpdateStatus(
                    state=UpdateState.ERROR,
                    error="URL de téléchargement non autorisée.",
                    error_code=UpdateErrorCode.DOWNLOAD_ERROR,
                )
                return

            from app.blueprints.admin.ota_update import OtaUpdater

            config = self._load_update_config()
            install_dir = config.get("install_dir", os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ))

            backup_enabled = config.get("backup_before_update", True)
            if backup_enabled:
                backup_path = config.get(
                    "backup_path", install_dir + ".backup"
                )
                if not os.path.isabs(backup_path):
                    self._update_status = UpdateStatus(
                        state=UpdateState.ERROR,
                        error="backup_path doit être un chemin absolu.",
                        error_code=UpdateErrorCode.BACKUP_FAILED,
                    )
                    return

                self._update_status = UpdateStatus(
                    state=UpdateState.BACKING_UP,
                    progress_percent=0,
                    current_step="Création backup version actuelle...",
                )
                backup_updater = OtaUpdater(install_dir=install_dir)
                backup_result = backup_updater.create_backup(
                    install_dir, backup_path
                )
                if not backup_result.success:
                    self._update_status = UpdateStatus(
                        state=UpdateState.ERROR,
                        error=backup_result.error,
                        error_code=UpdateErrorCode.BACKUP_FAILED,
                    )
                    return
                self._update_status = UpdateStatus(
                    state=UpdateState.BACKING_UP,
                    progress_percent=100,
                    current_step="Backup créée",
                )

            self._update_status = UpdateStatus(
                state=UpdateState.DOWNLOADING,
                current_step="Téléchargement en cours...",
            )
            target_dir = tempfile.mkdtemp(prefix="netscope-update-")
            result = self.download_release(tarball_url, target_dir)

            if not result.success:
                self._cleanup_temp_dir(target_dir)
                self._update_status = UpdateStatus(
                    state=UpdateState.ERROR,
                    error=result.error,
                    error_code=result.error_code,
                )
                return

            self._last_download = result

            self._update_status = UpdateStatus(
                state=UpdateState.EXTRACTING,
                progress_percent=50,
                current_step="Extraction et application...",
            )

            updater = OtaUpdater(install_dir=install_dir)

            if not updater.apply_update(result.file_path):
                self._cleanup_temp_dir(target_dir)
                self._update_status = UpdateStatus(
                    state=UpdateState.ERROR,
                    error="Échec de l'extraction ou de l'application.",
                    error_code=UpdateErrorCode.DOWNLOAD_ERROR,
                )
                return

            self._cleanup_temp_dir(target_dir)

            self._update_status = UpdateStatus(
                state=UpdateState.RESTARTING,
                progress_percent=90,
                current_step="Redémarrage du service...",
            )

            updater.restart_service()

            if not updater._post_update_callback():
                logger.warning("Hook post-update a échoué")

            self._update_status = UpdateStatus(
                state=UpdateState.DONE,
                progress_percent=100,
                current_step="Mise à jour terminée",
            )
        except Exception as e:
            logger.error("Erreur inattendue pendant la mise à jour : %s", e)
            self._update_status = UpdateStatus(
                state=UpdateState.ERROR,
                error=f"Erreur inattendue : {e}",
                error_code=UpdateErrorCode.DOWNLOAD_ERROR,
            )
        finally:
            self._update_lock.release()

    def download_release(self, release_url: str, target_dir: str) -> DownloadResult:
        try:
            usage = shutil.disk_usage(target_dir)
            free_mb = usage.free / (1024 * 1024)
            if free_mb < MIN_DISK_SPACE_MB:
                return DownloadResult(
                    success=False,
                    error=f"Espace disque insuffisant ({free_mb:.0f} Mo libre, {MIN_DISK_SPACE_MB} Mo requis).",
                    error_code=UpdateErrorCode.DISK_SPACE_ERROR,
                )
        except OSError as e:
            return DownloadResult(
                success=False,
                error=f"Impossible de vérifier l'espace disque : {e}",
                error_code=UpdateErrorCode.DISK_SPACE_ERROR,
            )

        os.makedirs(target_dir, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(suffix='.tar.gz', dir=target_dir)
        os.close(fd)

        try:
            response = requests.get(
                release_url,
                stream=True,
                timeout=DOWNLOAD_TIMEOUT,
                headers={
                    "Accept": "application/octet-stream",
                    "User-Agent": USER_AGENT,
                },
            )
            response.raise_for_status()

            expected_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(temp_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if expected_size > 0:
                        self._update_status.progress_percent = min(
                            99, int(downloaded * 100 / expected_size)
                        )

            if expected_size > 0 and downloaded != expected_size:
                self._cleanup_temp(temp_path)
                return DownloadResult(
                    success=False,
                    error=f"Fichier corrompu : {downloaded} octets reçus, {expected_size} attendus.",
                    error_code=UpdateErrorCode.INTEGRITY_ERROR,
                )

            return DownloadResult(
                success=True,
                file_path=temp_path,
                file_size=downloaded,
            )

        except requests.Timeout:
            self._cleanup_temp(temp_path)
            return DownloadResult(
                success=False,
                error="Délai de téléchargement dépassé (timeout 5 min).",
                error_code=UpdateErrorCode.DOWNLOAD_ERROR,
            )
        except requests.ConnectionError:
            self._cleanup_temp(temp_path)
            return DownloadResult(
                success=False,
                error="Connexion interrompue pendant le téléchargement.",
                error_code=UpdateErrorCode.DOWNLOAD_ERROR,
            )
        except requests.HTTPError as e:
            self._cleanup_temp(temp_path)
            status = e.response.status_code if e.response else "inconnu"
            return DownloadResult(
                success=False,
                error=f"Erreur HTTP lors du téléchargement : {status}.",
                error_code=UpdateErrorCode.DOWNLOAD_ERROR,
            )
        except OSError as e:
            self._cleanup_temp(temp_path)
            return DownloadResult(
                success=False,
                error=f"Erreur d'écriture disque : {e}",
                error_code=UpdateErrorCode.DISK_SPACE_ERROR,
            )

    @staticmethod
    def _load_update_config() -> dict:
        import yaml
        from pathlib import Path

        config_path = Path(__file__).parent.parent.parent / 'data' / 'config' / 'netscope.yaml'
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f) or {}
            return config_data.get('update', {})
        return {}

    @staticmethod
    def _cleanup_temp(path: str) -> None:
        try:
            if os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass

    @staticmethod
    def _cleanup_temp_dir(path: str) -> None:
        try:
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


def get_update_service() -> UpdateService:
    """Get or create the UpdateService singleton."""
    global _instance
    if _instance is None:
        update_config = UpdateService._load_update_config()
        github_repo = update_config.get('github_repo', 'iPresing/NETSCOPE')
        check_url = update_config.get(
            'check_url',
            'https://api.github.com/repos/{repo}/releases/latest'
        )
        _instance = UpdateService(github_repo=github_repo, check_url_template=check_url)
    return _instance


def reset_update_service() -> None:
    """Reset singleton for testing."""
    global _instance
    _instance = None
