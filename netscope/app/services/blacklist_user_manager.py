"""Gestionnaire CRUD des blacklists utilisateur avec persistance JSON.

Story 4b.6: CRUD Blacklists — Interface Web
- Singleton pattern comme WhitelistManager
- Persistance JSON dans data/blacklists/user_blacklist.json
- Méthodes add, remove, get_all, get_by_id
- Hook de rechargement BlacklistManager après modification

Lessons Learned Epic 1/2/3/4:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Singleton pattern with get_*/reset_* functions
- Thread-safety: Lock unique, opérations atomiques, pas de TOCTOU
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from app.models.blacklist import (
    BlacklistType,
    UserBlacklistEntry,
    create_user_blacklist_entry,
    validate_value,
)

logger = logging.getLogger(__name__)

MAX_USER_BLACKLIST_ENTRIES = 1000


class BlacklistUserManager:
    """Gestionnaire CRUD des blacklists utilisateur avec persistance JSON."""

    def __init__(self, filepath: str | Path) -> None:
        self._filepath = Path(filepath)
        self._entries: list[UserBlacklistEntry] = []
        self._lock = Lock()
        self.load()

    def load(self) -> None:
        """Charge les entrées depuis le fichier JSON."""
        if not self._filepath.exists():
            self._entries = []
            return
        try:
            data = json.loads(self._filepath.read_text(encoding="utf-8"))
            self._entries = [
                UserBlacklistEntry.from_dict(e) for e in data.get("entries", [])
            ]
            logger.info(f"User blacklist chargée ({len(self._entries)} entrées)")
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error(f"Erreur chargement user blacklist (error={exc})")
            self._entries = []

    def save(self) -> None:
        """Sauvegarde les entrées vers le fichier JSON."""
        data = {
            "entries": [e.to_dict() for e in self._entries],
            "version": 1,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        self._filepath.parent.mkdir(parents=True, exist_ok=True)
        self._filepath.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def add(
        self,
        value: str,
        entry_type: BlacklistType | None = None,
        reason: str = "",
    ) -> UserBlacklistEntry:
        """Ajoute une entrée. Lève ValueError si doublon, invalide ou limite atteinte."""
        value = value.strip()

        # Auto-détection du type si non spécifié
        if entry_type is None:
            from app.models.blacklist import infer_entry_type
            entry_type = infer_entry_type(value)

        # Validation du format
        if not validate_value(entry_type, value):
            raise ValueError(f"Valeur invalide pour le type {entry_type.value}: '{value}'")

        with self._lock:
            # Vérifier limite
            if len(self._entries) >= MAX_USER_BLACKLIST_ENTRIES:
                raise ValueError(
                    f"Limite atteinte: maximum {MAX_USER_BLACKLIST_ENTRIES} entrées"
                )

            # Vérifier doublon dans les entrées user
            normalized = value.lower() if entry_type == BlacklistType.DOMAIN else value
            for e in self._entries:
                existing = e.value.lower() if e.entry_type == BlacklistType.DOMAIN else e.value
                if existing == normalized and e.entry_type == entry_type:
                    raise ValueError(f"Doublon: '{value}' déjà dans la blacklist utilisateur")

            # Vérifier doublon dans les defaults
            self._check_default_duplicate(normalized, entry_type)

            # Créer et persister
            entry = create_user_blacklist_entry(value, entry_type=entry_type, reason=reason)
            self._entries.append(entry)
            self.save()
            logger.info(f"User blacklist: ajout {entry_type.value} '{value}'")

            # Recharger le BlacklistManager pour intégrer la nouvelle entrée
            self._trigger_reload()

            return entry

    def remove(self, entry_id: str) -> UserBlacklistEntry:
        """Supprime par ID. Lève KeyError si inexistant."""
        with self._lock:
            for i, e in enumerate(self._entries):
                if e.id == entry_id:
                    removed = self._entries.pop(i)
                    self.save()
                    logger.info(f"User blacklist: suppression '{removed.value}'")

                    # Recharger le BlacklistManager
                    self._trigger_reload()

                    return removed
            raise KeyError(f"Entrée {entry_id} non trouvée")

    def get_all(self) -> list[UserBlacklistEntry]:
        """Retourne la liste complète des entrées utilisateur."""
        return list(self._entries)

    def get_by_id(self, entry_id: str) -> UserBlacklistEntry | None:
        """Retourne une entrée par ID ou None."""
        return next((e for e in self._entries if e.id == entry_id), None)

    def _check_default_duplicate(self, value: str, entry_type: BlacklistType) -> None:
        """Vérifie si la valeur existe déjà dans les defaults."""
        try:
            from app.core.detection.blacklist_manager import get_blacklist_manager
            manager = get_blacklist_manager()

            if entry_type == BlacklistType.IP and manager.check_ip(value):
                raise ValueError(f"Doublon: '{value}' déjà dans les blacklists par défaut")
            elif entry_type == BlacklistType.DOMAIN and manager.check_domain(value):
                raise ValueError(f"Doublon: '{value}' déjà dans les blacklists par défaut")
            elif entry_type == BlacklistType.TERM:
                # Pour les termes, vérifier correspondance exacte dans les defaults
                if value.lower() in {t.lower() for t in manager.terms}:
                    raise ValueError(f"Doublon: '{value}' déjà dans les blacklists par défaut")
        except ImportError:
            logger.warning("BlacklistManager non disponible — vérification doublons defaults ignorée")

    def _trigger_reload(self) -> None:
        """Déclenche le rechargement du BlacklistManager et la re-détection."""
        try:
            from app.core.detection.blacklist_manager import get_blacklist_manager
            manager = get_blacklist_manager()
            if hasattr(manager, 'merge_user_entries'):
                manager.merge_user_entries(self._entries)
                logger.debug("BlacklistManager rechargé avec entrées utilisateur")

            # Re-lancer la détection sur la dernière capture pour
            # que le health score reflète les changements immédiatement
            self._trigger_redetection()
        except Exception as exc:
            logger.warning(f"Impossible de recharger BlacklistManager: {exc}")

    def _trigger_redetection(self) -> None:
        """Re-lance la détection d'anomalies sur la dernière capture."""
        try:
            from app.core.capture import get_tcpdump_manager
            tcpdump = get_tcpdump_manager()
            if tcpdump.redetect_latest():
                logger.info("Re-détection effectuée après modification blacklist")
            else:
                logger.debug("Pas de capture disponible pour re-détection")
        except Exception as exc:
            logger.warning(f"Re-détection impossible: {exc}")


# Singleton
_instance: BlacklistUserManager | None = None


def get_blacklist_user_manager() -> BlacklistUserManager:
    """Retourne l'instance singleton du BlacklistUserManager."""
    global _instance
    if _instance is None:
        from flask import current_app

        filepath = (
            Path(current_app.root_path).parent
            / "data"
            / "blacklists"
            / "user_blacklist.json"
        )
        _instance = BlacklistUserManager(filepath)
    return _instance


def reset_blacklist_user_manager() -> None:
    """Reset le singleton (utile pour les tests)."""
    global _instance
    _instance = None
