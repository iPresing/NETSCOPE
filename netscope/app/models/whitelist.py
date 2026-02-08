"""Whitelist data models for NETSCOPE.

Defines dataclasses and enums for whitelist management.

Story 3.6: CRUD Whitelist Complet (FR37, FR38, FR39)
- WhitelistEntry dataclass with serialization
- WhitelistEntryType enum (IP, PORT, IP_PORT)
- Type inference utility

Lessons Learned Epic 1/2/3:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use list/dict directly (not typing.List/Dict)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class WhitelistEntryType(Enum):
    """Types d'entrees whitelist supportes."""

    IP = "ip"
    PORT = "port"
    IP_PORT = "ip_port"


@dataclass
class WhitelistEntry:
    """Represente une entree dans la whitelist.

    Attributes:
        id: Identifiant unique de l'entree
        value: Valeur (IP, port ou IP:Port)
        entry_type: Type d'entree
        reason: Raison/note optionnelle
        created_at: Date de creation
    """

    id: str
    value: str
    entry_type: WhitelistEntryType
    reason: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Serialisation JSON."""
        return {
            "id": self.id,
            "value": self.value,
            "entry_type": self.entry_type.value,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WhitelistEntry:
        """Deserialisation depuis dictionnaire."""
        return cls(
            id=data["id"],
            value=data["value"],
            entry_type=WhitelistEntryType(data["entry_type"]),
            reason=data.get("reason", ""),
            created_at=datetime.fromisoformat(data["created_at"]),
        )


def infer_entry_type(value: str) -> WhitelistEntryType:
    """Detecte automatiquement le type d'entree.

    Args:
        value: Valeur a analyser

    Returns:
        WhitelistEntryType detecte
    """
    if ":" in value:
        parts = value.rsplit(":", 1)
        if parts[1].isdigit():
            return WhitelistEntryType.IP_PORT
    if value.isdigit():
        port = int(value)
        if 1 <= port <= 65535:
            return WhitelistEntryType.PORT
    return WhitelistEntryType.IP


def create_entry(value: str, reason: str = "") -> WhitelistEntry:
    """Factory pour creer une WhitelistEntry avec ID et timestamp.

    Args:
        value: Valeur de l'entree (IP, port ou IP:Port)
        reason: Raison/note optionnelle

    Returns:
        WhitelistEntry avec ID unique et timestamp UTC
    """
    return WhitelistEntry(
        id=f"wl_{uuid.uuid4().hex[:8]}",
        value=value.strip(),
        entry_type=infer_entry_type(value.strip()),
        reason=reason.strip(),
        created_at=datetime.now(timezone.utc),
    )
