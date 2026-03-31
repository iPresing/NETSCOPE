"""Blacklist data models for NETSCOPE.

Defines dataclasses and enums for blacklist management.

Story 4b.6: CRUD Blacklist user entries
- UserBlacklistEntry dataclass with serialization
- Validation and type inference utilities

Lessons Learned Epic 1/2/3/4:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use list/dict directly (not typing.List/Dict)
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?$"
)


class BlacklistType(Enum):
    """Types de blacklists supportés."""

    IP = "ip"
    DOMAIN = "domain"
    TERM = "term"


@dataclass
class BlacklistEntry:
    """Représente une entrée dans une blacklist.

    Attributes:
        value: Valeur de l'entrée (IP, domaine, ou terme)
        source_file: Fichier source de l'entrée
        blacklist_type: Type de blacklist (IP, DOMAIN, TERM)
    """

    value: str
    source_file: str
    blacklist_type: BlacklistType

    def to_dict(self) -> dict[str, str]:
        """Sérialisation JSON snake_case."""
        return {
            "value": self.value,
            "source_file": self.source_file,
            "blacklist_type": self.blacklist_type.value,
        }


@dataclass
class UserBlacklistEntry:
    """Représente une entrée blacklist ajoutée par l'utilisateur.

    Attributes:
        id: Identifiant unique (bl_xxxxxxxx)
        entry_type: Type de blacklist (IP, DOMAIN, TERM)
        value: Valeur de l'entrée
        reason: Raison/note optionnelle
        created_at: Date de création UTC
    """

    id: str
    entry_type: BlacklistType
    value: str
    reason: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Sérialisation JSON."""
        return {
            "id": self.id,
            "entry_type": self.entry_type.value,
            "value": self.value,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserBlacklistEntry:
        """Désérialisation depuis dictionnaire."""
        return cls(
            id=data["id"],
            entry_type=BlacklistType(data["entry_type"]),
            value=data["value"],
            reason=data.get("reason", ""),
            created_at=datetime.fromisoformat(data["created_at"]),
        )


@dataclass
class BlacklistStats:
    """Statistiques des blacklists chargées.

    Attributes:
        ips_count: Nombre d'IPs blacklistées
        domains_count: Nombre de domaines blacklistés
        terms_count: Nombre de termes suspects
        files_loaded: Liste des fichiers chargés
    """

    ips_count: int = 0
    domains_count: int = 0
    terms_count: int = 0
    files_loaded: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, int | list[str]]:
        """Sérialisation JSON snake_case."""
        return {
            "ips_count": self.ips_count,
            "domains_count": self.domains_count,
            "terms_count": self.terms_count,
            "files_loaded": self.files_loaded,
            "total_entries": self.ips_count + self.domains_count + self.terms_count,
        }


def validate_value(entry_type: BlacklistType, value: str) -> bool:
    """Valide une valeur selon son type de blacklist.

    Args:
        entry_type: Type attendu (IP, DOMAIN, TERM)
        value: Valeur à valider

    Returns:
        True si la valeur est valide pour le type donné
    """
    if not value or not value.strip():
        return False
    value = value.strip()
    if entry_type == BlacklistType.IP:
        return bool(_IP_RE.match(value))
    if entry_type == BlacklistType.DOMAIN:
        return (
            bool(_DOMAIN_RE.match(value))
            and len(value) <= 253
            and any(c.isalpha() for c in value)
        )
    if entry_type == BlacklistType.TERM:
        return 2 <= len(value) <= 200
    return False


def infer_entry_type(value: str) -> BlacklistType:
    """Détecte automatiquement le type d'entrée blacklist.

    Args:
        value: Valeur à analyser

    Returns:
        BlacklistType détecté
    """
    value = value.strip()
    if _IP_RE.match(value):
        return BlacklistType.IP
    if (
        "." in value
        and _DOMAIN_RE.match(value)
        and any(c.isalpha() for c in value)
    ):
        return BlacklistType.DOMAIN
    return BlacklistType.TERM


def create_user_blacklist_entry(
    value: str,
    entry_type: BlacklistType | None = None,
    reason: str = "",
) -> UserBlacklistEntry:
    """Factory pour créer une UserBlacklistEntry avec ID et timestamp.

    Args:
        value: Valeur de l'entrée
        entry_type: Type explicite (auto-détecté si None)
        reason: Raison/note optionnelle

    Returns:
        UserBlacklistEntry avec ID unique et timestamp UTC
    """
    value = value.strip()
    if entry_type is None:
        entry_type = infer_entry_type(value)
    return UserBlacklistEntry(
        id=f"bl_{uuid.uuid4().hex[:8]}",
        entry_type=entry_type,
        value=value,
        reason=reason.strip(),
        created_at=datetime.now(timezone.utc),
    )


# Error code constants
BLACKLIST_FILE_NOT_FOUND = "BLACKLIST_FILE_NOT_FOUND"
BLACKLIST_PARSE_ERROR = "BLACKLIST_PARSE_ERROR"
BLACKLIST_NOT_INITIALIZED = "BLACKLIST_NOT_INITIALIZED"
BLACKLIST_DUPLICATE = "BLACKLIST_DUPLICATE"
BLACKLIST_INVALID_TYPE = "BLACKLIST_INVALID_TYPE"
BLACKLIST_INVALID_VALUE = "BLACKLIST_INVALID_VALUE"
BLACKLIST_NOT_FOUND = "BLACKLIST_NOT_FOUND"
BLACKLIST_LIMIT_REACHED = "BLACKLIST_LIMIT_REACHED"
BLACKLIST_DEFAULT_READONLY = "BLACKLIST_DEFAULT_READONLY"
