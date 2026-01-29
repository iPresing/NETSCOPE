"""Capture data models for NETSCOPE.

Defines dataclasses and enums for capture sessions, results, and packet information.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class CaptureStatus(Enum):
    """Status of a capture session."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class CaptureConfig:
    """Configuration for a capture session.

    Attributes:
        duration: Capture duration in seconds (30-600)
        interface: Network interface name (e.g., 'eth0', 'auto')
        bpf_filter: BPF filter string (e.g., 'not port 22')
    """

    duration: int = 120
    interface: str = "auto"
    bpf_filter: str = "not port 22"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "duration_seconds": self.duration,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
        }


@dataclass
class PacketInfo:
    """Information about a captured packet.

    Attributes:
        timestamp: Packet capture timestamp
        ip_src: Source IP address
        ip_dst: Destination IP address
        port_src: Source port (None for non-TCP/UDP)
        port_dst: Destination port (None for non-TCP/UDP)
        protocol: Protocol name (TCP, UDP, ICMP, etc.)
        length: Packet length in bytes
        dns_queries: List of DNS query names (Story 2.2 AC2)
        http_host: HTTP Host header value (Story 2.2 AC2)
        payload_preview: First 200 chars of payload for term detection (Story 2.2 AC3)
    """

    timestamp: datetime
    ip_src: str
    ip_dst: str
    port_src: int | None
    port_dst: int | None
    protocol: str
    length: int = 0
    dns_queries: list[str] = field(default_factory=list)
    http_host: str | None = None
    payload_preview: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "timestamp": self.timestamp.isoformat(),
            "ip_src": self.ip_src,
            "ip_dst": self.ip_dst,
            "port_src": self.port_src,
            "port_dst": self.port_dst,
            "protocol": self.protocol,
            "length": self.length,
        }
        # Only include if present (Story 2.2)
        if self.dns_queries:
            result["dns_queries"] = self.dns_queries
        if self.http_host:
            result["http_host"] = self.http_host
        if self.payload_preview:
            result["payload_preview"] = self.payload_preview
        return result


@dataclass
class CaptureSummary:
    """Summary statistics for a capture session.

    Attributes:
        total_packets: Total number of packets captured
        total_bytes: Total bytes captured
        unique_ips: Number of unique IP addresses
        unique_ports: Number of unique ports
        protocols: Dictionary of protocol counts
        top_ips: List of top IP addresses by packet count
        top_ports: List of top ports by packet count
        bytes_per_protocol: Dictionary of bytes per protocol
        duration_actual: Actual capture duration in seconds
    """

    total_packets: int = 0
    total_bytes: int = 0
    unique_ips: int = 0
    unique_ports: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_ports: list[tuple[int, int]] = field(default_factory=list)
    bytes_per_protocol: dict[str, int] = field(default_factory=dict)
    duration_actual: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "unique_ips": self.unique_ips,
            "unique_ports": self.unique_ports,
            "protocols": self.protocols,
            "top_ips": [{"ip": ip, "count": count} for ip, count in self.top_ips],
            "top_ports": [{"port": port, "count": count} for port, count in self.top_ports],
            "bytes_per_protocol": self.bytes_per_protocol,
            "duration_actual_seconds": self.duration_actual,
        }


@dataclass
class CaptureSession:
    """Represents a capture session.

    Attributes:
        id: Unique session identifier (e.g., 'cap_20260115_143001')
        config: Capture configuration
        status: Current capture status
        start_time: Session start timestamp
        end_time: Session end timestamp (None if running)
        capture_path: Path to capture file
        error_message: Error message if status is ERROR
        pid: Process ID of tcpdump (None if not running)
    """

    id: str
    config: CaptureConfig
    status: CaptureStatus = CaptureStatus.IDLE
    start_time: datetime | None = None
    end_time: datetime | None = None
    capture_path: Path | None = None
    error_message: str | None = None
    pid: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "capture_id": self.id,
            "config": self.config.to_dict(),
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "capture_path": str(self.capture_path) if self.capture_path else None,
            "error_message": self.error_message,
            "pid": self.pid,
        }

    @property
    def is_running(self) -> bool:
        """Check if capture is currently running."""
        return self.status == CaptureStatus.RUNNING

    @property
    def duration_elapsed(self) -> float:
        """Get elapsed duration in seconds."""
        if self.start_time is None:
            return 0.0
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()


@dataclass
class CaptureResult:
    """Results of a completed capture session.

    Attributes:
        session: The capture session
        packets: List of captured packet information
        summary: Summary statistics
    """

    session: CaptureSession
    packets: list[PacketInfo] = field(default_factory=list)
    summary: CaptureSummary = field(default_factory=CaptureSummary)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "session": self.session.to_dict(),
            "summary": self.summary.to_dict(),
            "packets_count": len(self.packets),
            # Don't include all packets in JSON - use separate endpoint
        }


class CaptureError(Exception):
    """Exception for capture-related errors.

    Attributes:
        code: Error code (e.g., 'CAPTURE_ALREADY_RUNNING')
        message: Human-readable error message
        details: Additional error details
    """

    def __init__(
        self,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON error response."""
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


# Error code constants
CAPTURE_ALREADY_RUNNING = "CAPTURE_ALREADY_RUNNING"
CAPTURE_INTERFACE_NOT_FOUND = "CAPTURE_INTERFACE_NOT_FOUND"
CAPTURE_PERMISSION_DENIED = "CAPTURE_PERMISSION_DENIED"
CAPTURE_INVALID_DURATION = "CAPTURE_INVALID_DURATION"
CAPTURE_INVALID_FILTER = "CAPTURE_INVALID_FILTER"
CAPTURE_FAILED = "CAPTURE_FAILED"
CAPTURE_PARSE_ERROR = "CAPTURE_PARSE_ERROR"
CAPTURE_NOT_RUNNING = "CAPTURE_NOT_RUNNING"


# Validation constants
MIN_CAPTURE_DURATION = 30
MAX_CAPTURE_DURATION = 600
DEFAULT_CAPTURE_DURATION = 120


def validate_duration(duration: int) -> int:
    """Validate capture duration.

    Args:
        duration: Duration in seconds

    Returns:
        Validated duration

    Raises:
        CaptureError: If duration is out of valid range
    """
    if not isinstance(duration, int):
        try:
            duration = int(duration)
        except (ValueError, TypeError):
            raise CaptureError(
                code=CAPTURE_INVALID_DURATION,
                message=f"Duration must be an integer, got {type(duration).__name__}",
            )

    if duration < MIN_CAPTURE_DURATION or duration > MAX_CAPTURE_DURATION:
        raise CaptureError(
            code=CAPTURE_INVALID_DURATION,
            message=f"Duration must be between {MIN_CAPTURE_DURATION}s and {MAX_CAPTURE_DURATION}s",
            details={
                "provided": duration,
                "min": MIN_CAPTURE_DURATION,
                "max": MAX_CAPTURE_DURATION,
            },
        )
    return duration
