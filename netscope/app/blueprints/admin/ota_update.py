"""OTA updater for extracting and applying updates (Story 5.6)."""

import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from typing import Callable, Optional

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
