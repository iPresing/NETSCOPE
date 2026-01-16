"""Blacklist data models for NETSCOPE.

Defines dataclasses and enums for blacklist management.

Lessons Learned Epic 1:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use list/dict directly (not typing.List/Dict)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


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


# Error code constants
BLACKLIST_FILE_NOT_FOUND = "BLACKLIST_FILE_NOT_FOUND"
BLACKLIST_PARSE_ERROR = "BLACKLIST_PARSE_ERROR"
BLACKLIST_NOT_INITIALIZED = "BLACKLIST_NOT_INITIALIZED"
