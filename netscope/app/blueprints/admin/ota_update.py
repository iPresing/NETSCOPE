"""OTA updater for extracting and applying updates."""

import json
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Callable, Optional

from app.services.update_service import BackupResult

logger = logging.getLogger(__name__)

EXPECTED_STRUCTURE = ['app']


class OtaUpdater:
    """Handles extraction and application of downloaded updates."""

    def __init__(
        self,
        install_dir: str,
        pre_update_callback: Optional[Callable[[], bool]] = None,
        post_update_callback: Optional[Callable[[], bool]] = None,
    ):
        self._install_dir = install_dir
        self._pre_update_callback = pre_update_callback or (lambda: True)
        self._post_update_callback = post_update_callback or (lambda: True)

    def apply_update(self, archive_path: str, install_dir: Optional[str] = None) -> bool:
        target = install_dir or self._install_dir
        staging_dir = tempfile.mkdtemp(prefix="netscope-staging-")

        try:
            if not self._validate_archive(archive_path):
                logger.error("Archive invalide : %s", archive_path)
                return False

            self._extract_archive(archive_path, staging_dir)

            content_root = self._find_content_root(staging_dir)
            if not content_root:
                logger.error("Structure attendue introuvable dans l'archive")
                return False

            if not self._pre_update_callback():
                logger.error("Hook pre-update a échoué")
                return False

            self._swap_directories(content_root, target)
            logger.info("Update appliqué avec succès vers %s", target)
            return True

        except (tarfile.TarError, zipfile.BadZipFile, OSError, ValueError) as e:
            logger.error("Erreur extraction/application : %s", e)
            return False
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    def create_backup(self, install_dir: str, backup_dir: str) -> BackupResult:
        """Create a full backup of the installation directory before update."""
        if not os.path.isdir(install_dir):
            return BackupResult(
                False, error="Install dir not found",
                error_code="INSTALL_NOT_FOUND",
            )

        install_size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, filenames in os.walk(install_dir)
            for f in filenames
        )

        parent = os.path.dirname(backup_dir) or "/"
        try:
            disk = shutil.disk_usage(parent)
        except OSError as e:
            return BackupResult(
                False, error=f"Impossible de vérifier l'espace disque : {e}",
                error_code="DISK_CHECK_FAILED",
            )

        if disk.free < install_size * 2:
            return BackupResult(
                False,
                error=f"Espace insuffisant : {disk.free} libre, {install_size * 2} requis",
                error_code="INSUFFICIENT_DISK_SPACE",
            )

        if os.path.exists(backup_dir):
            shutil.rmtree(backup_dir)

        try:
            shutil.copytree(install_dir, backup_dir)
        except OSError as e:
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir, ignore_errors=True)
            return BackupResult(
                False, error=str(e), error_code="BACKUP_COPY_FAILED",
            )

        from app.services.version_service import get_version_service
        info = {
            "version": get_version_service().get_version(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "size_bytes": install_size,
            "source_dir": install_dir,
        }
        info_path = os.path.join(backup_dir, "backup-info.json")
        try:
            with open(info_path, "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2)
        except OSError as e:
            shutil.rmtree(backup_dir, ignore_errors=True)
            return BackupResult(
                False, error=f"Échec écriture backup-info.json : {e}",
                error_code="BACKUP_INFO_FAILED",
            )

        logger.info("Backup créée : %s (%d octets)", backup_dir, install_size)
        return BackupResult(True, backup_path=backup_dir, size_bytes=install_size)

    def restart_service(self) -> bool:
        import platform
        import subprocess

        if platform.system() != "Linux":
            logger.info("Mode dev (non-Linux) : redémarrage manuel requis")
            return True

        try:
            subprocess.run(
                ["systemctl", "restart", "netscope"],
                check=True,
                timeout=30,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("Échec redémarrage service : %s", e)
            return False

    @staticmethod
    def _validate_archive(archive_path: str) -> bool:
        if not os.path.isfile(archive_path):
            return False
        if archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
            return tarfile.is_tarfile(archive_path)
        if archive_path.endswith('.zip'):
            return zipfile.is_zipfile(archive_path)
        return False

    @staticmethod
    def _extract_archive(archive_path: str, target_dir: str) -> None:
        if archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tf:
                for member in tf.getmembers():
                    if member.issym() or member.islnk():
                        raise ValueError(f"Symlink/hardlink non autorisé : {member.name}")
                    resolved = os.path.realpath(
                        os.path.join(target_dir, member.name)
                    )
                    if not resolved.startswith(os.path.realpath(target_dir)):
                        raise ValueError(f"Path traversal detected: {member.name}")
                    tf.extract(member, target_dir)
        elif archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for info in zf.infolist():
                    resolved = os.path.realpath(
                        os.path.join(target_dir, info.filename)
                    )
                    if not resolved.startswith(os.path.realpath(target_dir)):
                        raise ValueError(f"Path traversal detected: {info.filename}")
                    zf.extract(info, target_dir)
        else:
            raise ValueError(f"Format d'archive non supporté : {archive_path}")

    @staticmethod
    def _find_content_root(staging_dir: str) -> Optional[str]:
        entries = os.listdir(staging_dir)
        if len(entries) == 1:
            candidate = os.path.join(staging_dir, entries[0])
            if os.path.isdir(candidate):
                inner = os.listdir(candidate)
                if any(d in inner for d in EXPECTED_STRUCTURE):
                    return candidate
        if any(d in entries for d in EXPECTED_STRUCTURE):
            return staging_dir
        return None

    @staticmethod
    def _swap_directories(source: str, target: str) -> None:
        backup_path = target + ".bak"
        if os.path.exists(backup_path):
            shutil.rmtree(backup_path, ignore_errors=True)

        if os.path.exists(target):
            os.rename(target, backup_path)

        try:
            os.rename(source, target)
        except OSError:
            try:
                shutil.copytree(source, target)
            except OSError:
                if os.path.exists(backup_path) and not os.path.exists(target):
                    os.rename(backup_path, target)
                raise
