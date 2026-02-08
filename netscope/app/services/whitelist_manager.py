"""Gestionnaire CRUD de la whitelist avec persistence JSON.

Story 3.6: CRUD Whitelist Complet (FR37, FR38, FR39)
- Singleton pattern comme BlacklistManager
- Persistence JSON dans data/whitelist/whitelist.json
- Methodes add, remove, get_all, get_by_id, is_whitelisted

Lessons Learned Epic 1/2/3:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Singleton pattern with get_*/reset_* functions
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from app.models.whitelist import WhitelistEntry, create_entry

logger = logging.getLogger(__name__)

_IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
MAX_WHITELIST_ENTRIES = 1000


class WhitelistManager:
    """Gestionnaire CRUD de la whitelist avec persistence JSON."""

    def __init__(self, filepath: str | Path) -> None:
        self._filepath = Path(filepath)
        self._entries: list[WhitelistEntry] = []
        self._lock = Lock()
        self.load()

    def load(self) -> None:
        """Charge les entrees depuis le fichier JSON."""
        if not self._filepath.exists():
            self._entries = []
            return
        try:
            data = json.loads(self._filepath.read_text(encoding="utf-8"))
            self._entries = [
                WhitelistEntry.from_dict(e) for e in data.get("entries", [])
            ]
            logger.info(f"Whitelist chargee ({len(self._entries)} entrees)")
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error(f"Erreur chargement whitelist (error={exc})")
            self._entries = []

    def save(self) -> None:
        """Sauvegarde les entrees vers le fichier JSON."""
        data = {
            "entries": [e.to_dict() for e in self._entries],
            "version": "1.0",
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        self._filepath.parent.mkdir(parents=True, exist_ok=True)
        self._filepath.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def add(self, value: str, reason: str = "") -> WhitelistEntry:
        """Ajoute une entree. Leve ValueError si doublon ou format invalide."""
        value = value.strip()
        self._validate(value)

        with self._lock:
            if len(self._entries) >= MAX_WHITELIST_ENTRIES:
                raise ValueError(
                    f"Limite atteinte: maximum {MAX_WHITELIST_ENTRIES} entrees"
                )
            if any(e.value == value for e in self._entries):
                raise ValueError(f"Doublon: {value} deja dans la whitelist")
            entry = create_entry(value, reason)
            self._entries.append(entry)
            self.save()
            logger.info(f"Whitelist: ajout {entry.entry_type.value} '{value}'")
            return entry

    def remove(self, entry_id: str) -> WhitelistEntry:
        """Supprime par ID. Leve KeyError si inexistant."""
        with self._lock:
            for i, e in enumerate(self._entries):
                if e.id == entry_id:
                    removed = self._entries.pop(i)
                    self.save()
                    logger.info(f"Whitelist: suppression '{removed.value}'")
                    return removed
            raise KeyError(f"Entree {entry_id} non trouvee")

    def get_all(self) -> list[WhitelistEntry]:
        """Retourne la liste complete des entrees."""
        return list(self._entries)

    def get_by_id(self, entry_id: str) -> WhitelistEntry | None:
        """Retourne une entree par ID ou None."""
        return next((e for e in self._entries if e.id == entry_id), None)

    def is_whitelisted(self, ip: str | None = None, port: int | None = None) -> bool:
        """Verifie si IP et/ou port sont whitelistes."""
        for e in self._entries:
            if e.entry_type.value == "ip" and ip and e.value == ip:
                return True
            if e.entry_type.value == "port" and port and e.value == str(port):
                return True
            if e.entry_type.value == "ip_port" and ip and port:
                if e.value == f"{ip}:{port}":
                    return True
        return False

    def get_whitelisted_anomaly_ids(self, anomalies) -> set[str]:
        """Retourne les IDs des anomalies matchees par la whitelist."""
        ids: set[str] = set()
        for anomaly in anomalies:
            ip, port, aid = self._extract_anomaly_info(anomaly)
            if aid and self.is_whitelisted(ip, port):
                ids.add(aid)
        return ids

    @staticmethod
    def _extract_anomaly_info(anomaly) -> tuple[str | None, int | None, str | None]:
        """Extrait IP, port et ID depuis un objet anomaly (dict ou dataclass)."""
        if isinstance(anomaly, dict):
            return anomaly.get("ip"), anomaly.get("port"), anomaly.get("id")

        aid = getattr(anomaly, "id", None)
        ip = None
        port = None

        # Priorite 1: utiliser matched_value pour les anomalies IP
        # C'est l'IP blacklistee, pas forcement ip_src du paquet
        match = getattr(anomaly, "match", None)
        if match:
            match_type = getattr(match, "match_type", None)
            if match_type and getattr(match_type, "value", None) == "ip":
                ip = getattr(match, "matched_value", None)

        # Extraire le port associe a l'IP matchee depuis packet_info
        packet_info = getattr(anomaly, "packet_info", None)
        if isinstance(packet_info, dict):
            if ip is None:
                ip = packet_info.get("ip_src") or packet_info.get("ip_dst")

            # Trouver le port du cote de l'IP matchee
            if ip and ip == packet_info.get("ip_dst"):
                raw_port = packet_info.get("port_dst")
            elif ip and ip == packet_info.get("ip_src"):
                raw_port = packet_info.get("port_src")
            else:
                raw_port = packet_info.get("port_dst") or packet_info.get("port_src")

            if raw_port is not None:
                port = int(raw_port) if not isinstance(raw_port, int) else raw_port

        return ip, port, aid

    def _validate(self, value: str) -> None:
        """Valide le format de la valeur."""
        if not value:
            raise ValueError("Valeur vide")
        if ":" in value:
            parts = value.rsplit(":", 1)
            if not parts[1].isdigit() or not (1 <= int(parts[1]) <= 65535):
                raise ValueError(f"Port invalide dans '{value}'")
            if not _IP_PATTERN.match(parts[0]):
                raise ValueError(f"IP invalide dans '{value}'")
        elif value.isdigit():
            port = int(value)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port hors limites: {port}")
        else:
            if not _IP_PATTERN.match(value):
                raise ValueError(
                    f"Format invalide: '{value}' (attendu: IP, Port ou IP:Port)"
                )


# Singleton
_instance: WhitelistManager | None = None


def get_whitelist_manager() -> WhitelistManager:
    """Retourne l'instance singleton du WhitelistManager."""
    global _instance
    if _instance is None:
        from flask import current_app

        filepath = (
            Path(current_app.root_path).parent
            / "data"
            / "whitelist"
            / "whitelist.json"
        )
        _instance = WhitelistManager(filepath)
    return _instance


def reset_whitelist_manager() -> None:
    """Reset le singleton (utile pour les tests)."""
    global _instance
    _instance = None
