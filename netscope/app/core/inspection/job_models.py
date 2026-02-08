"""Modeles de donnees pour les jobs d'inspection Scapy.

Story 4.1: Lancement Inspection Scapy (FR22)
- JobStatus enum: PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
- JobSpec dataclass: specification d'un job d'inspection
- JobResult dataclass: resultat d'un job d'inspection
- Job dataclass: job complet avec spec, status, result

Lessons Learned Epic 1/2/3:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Dataclasses with to_dict()/from_dict() for JSON serialization
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


_IP_V4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

DURATION_MIN = 5
DURATION_MAX = 120
DURATION_DEFAULT = 30
PORT_MIN = 1
PORT_MAX = 65535
VALID_PROTOCOLS = ("TCP", "UDP", "ICMP")


class JobStatus(Enum):
    """Status d'un job d'inspection."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class JobSpec:
    """Specification d'un job d'inspection Scapy.

    Attributes:
        id: Identifiant unique du job
        target_ip: IP cible (obligatoire, format IPv4)
        target_port: Port cible (optionnel, 1-65535)
        protocol: Protocole (optionnel, TCP/UDP/ICMP)
        duration: Duree en secondes (5-120, defaut 30)
        created_at: Date de creation
    """

    id: str
    target_ip: str
    target_port: int | None = None
    protocol: str | None = None
    duration: int = DURATION_DEFAULT
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        """Serialize vers dictionnaire pour reponse JSON."""
        return {
            "id": self.id,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "duration": self.duration,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> JobSpec:
        """Deserialize depuis un dictionnaire."""
        return cls(
            id=data["id"],
            target_ip=data["target_ip"],
            target_port=data.get("target_port"),
            protocol=data.get("protocol"),
            duration=data.get("duration", DURATION_DEFAULT),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data
            else datetime.now(timezone.utc),
        )


@dataclass
class JobResult:
    """Resultat d'un job d'inspection Scapy.

    Attributes:
        job_id: ID du job associe
        status: Statut final du job
        packets_captured: Nombre de paquets captures
        start_time: Heure de debut d'execution
        end_time: Heure de fin d'execution
        error_message: Message d'erreur si echec
        raw_data: Donnees brutes capturees
    """

    job_id: str
    status: JobStatus
    packets_captured: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    error_message: str | None = None
    raw_data: list | None = None

    def to_dict(self) -> dict:
        """Serialize vers dictionnaire pour reponse JSON."""
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "packets_captured": self.packets_captured,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: dict) -> JobResult:
        """Deserialize depuis un dictionnaire."""
        return cls(
            job_id=data["job_id"],
            status=JobStatus(data["status"]),
            packets_captured=data.get("packets_captured", 0),
            start_time=datetime.fromisoformat(data["start_time"])
            if data.get("start_time")
            else None,
            end_time=datetime.fromisoformat(data["end_time"])
            if data.get("end_time")
            else None,
            error_message=data.get("error_message"),
        )


@dataclass
class Job:
    """Job d'inspection complet.

    Attributes:
        spec: Specification du job
        status: Statut actuel
        result: Resultat (rempli apres execution)
        progress_percent: Pourcentage de progression (0-100)
    """

    spec: JobSpec
    status: JobStatus = JobStatus.PENDING
    result: JobResult | None = None
    progress_percent: int = 0

    def to_dict(self) -> dict:
        """Serialize vers dictionnaire pour reponse JSON."""
        return {
            "id": self.spec.id,
            "status": self.status.value,
            "spec": self.spec.to_dict(),
            "result": self.result.to_dict() if self.result else None,
            "progress_percent": self.progress_percent,
            "created_at": self.spec.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> Job:
        """Deserialize depuis un dictionnaire."""
        return cls(
            spec=JobSpec.from_dict(data["spec"]),
            status=JobStatus(data["status"]),
            result=JobResult.from_dict(data["result"]) if data.get("result") else None,
            progress_percent=data.get("progress_percent", 0),
        )


def _validate_ip(ip: str) -> None:
    """Valide le format d'une adresse IPv4."""
    if not isinstance(ip, str) or not _IP_V4_PATTERN.match(ip):
        raise ValueError(f"IP cible invalide: '{ip}'")


def _validate_port(port: int | None) -> None:
    """Valide un numero de port."""
    if port is not None:
        if not isinstance(port, int) or port < PORT_MIN or port > PORT_MAX:
            raise ValueError(
                f"Port invalide: {port} (doit etre entre {PORT_MIN} et {PORT_MAX})"
            )


def _validate_duration(duration: int) -> None:
    """Valide la duree d'inspection."""
    if not isinstance(duration, int) or duration < DURATION_MIN or duration > DURATION_MAX:
        raise ValueError(
            f"Duree invalide: {duration}s (doit etre entre {DURATION_MIN} et {DURATION_MAX})"
        )


def _validate_protocol(protocol: str | None) -> None:
    """Valide le protocole."""
    if protocol is not None:
        if not isinstance(protocol, str) or protocol.upper() not in VALID_PROTOCOLS:
            raise ValueError(
                f"Protocole invalide: '{protocol}' (valides: {', '.join(VALID_PROTOCOLS)})"
            )


def create_job(
    target_ip: str,
    target_port: int | None = None,
    protocol: str | None = None,
    duration: int = DURATION_DEFAULT,
) -> Job:
    """Factory pour creer un job d'inspection valide.

    Args:
        target_ip: Adresse IP cible (format IPv4, obligatoire)
        target_port: Port cible (optionnel, 1-65535)
        protocol: Protocole (optionnel, TCP/UDP/ICMP)
        duration: Duree en secondes (5-120, defaut 30)

    Returns:
        Job avec status PENDING

    Raises:
        ValueError: Si les parametres sont invalides
    """
    _validate_ip(target_ip)
    _validate_port(target_port)
    _validate_duration(duration)
    _validate_protocol(protocol)

    normalized_protocol = protocol.upper() if protocol else None

    spec = JobSpec(
        id=f"job_{uuid.uuid4().hex[:8]}",
        target_ip=target_ip,
        target_port=target_port,
        protocol=normalized_protocol,
        duration=duration,
    )

    return Job(spec=spec, status=JobStatus.PENDING)
