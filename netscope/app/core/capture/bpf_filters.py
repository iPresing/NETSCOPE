"""BPF Filter module for NETSCOPE.

Provides utilities for building and validating Berkeley Packet Filter expressions.
"""

from __future__ import annotations

import logging
import re

from app.models.capture import CaptureError, CAPTURE_INVALID_FILTER

logger = logging.getLogger(__name__)

# Default BPF filter excludes SSH traffic
DEFAULT_BPF_FILTER = "not port 22"

# BPF syntax patterns for basic validation
# This is a simplified validation - tcpdump will do final validation
BPF_KEYWORDS = {
    "host", "net", "port", "portrange", "proto", "src", "dst",
    "tcp", "udp", "icmp", "arp", "ip", "ip6", "ether",
    "broadcast", "multicast", "gateway", "less", "greater",
    "and", "or", "not", "!", "&&", "||",
}

# Dangerous patterns that could cause issues
DANGEROUS_PATTERNS = [
    r"[;&|`$]",  # Shell injection characters
    r"\.\.",     # Path traversal
]


def build_default_filter() -> str:
    """Build the default BPF filter.

    Returns:
        Default BPF filter string (excludes SSH)
    """
    return DEFAULT_BPF_FILTER


def validate_filter(filter_string: str | None) -> str:
    """Validate a BPF filter string.

    Performs basic syntax validation. Full validation is done by tcpdump.

    Args:
        filter_string: BPF filter to validate, or None/empty for default

    Returns:
        Validated filter string (default if input was None/empty)

    Raises:
        CaptureError: If filter contains dangerous characters or is invalid
    """
    # Return default if empty
    if not filter_string or not filter_string.strip():
        logger.debug(f"Empty filter provided, using default (filter={DEFAULT_BPF_FILTER})")
        return DEFAULT_BPF_FILTER

    filter_string = filter_string.strip()

    # Check for dangerous patterns (shell injection prevention)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, filter_string):
            logger.warning(
                f"Dangerous pattern in BPF filter "
                f"(filter={filter_string}, pattern={pattern})"
            )
            raise CaptureError(
                code=CAPTURE_INVALID_FILTER,
                message="BPF filter contains invalid characters",
                details={"filter": filter_string},
            )

    # Check for reasonable length
    if len(filter_string) > 1000:
        logger.warning(f"BPF filter too long (length={len(filter_string)})")
        raise CaptureError(
            code=CAPTURE_INVALID_FILTER,
            message="BPF filter is too long (max 1000 characters)",
            details={"length": len(filter_string)},
        )

    # Basic token validation - at least one valid BPF keyword should be present
    tokens = filter_string.lower().split()
    has_valid_keyword = any(
        token in BPF_KEYWORDS or token.isdigit()
        for token in tokens
    )

    # Also allow IP addresses and port numbers
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    has_ip = bool(re.search(ip_pattern, filter_string))

    if not has_valid_keyword and not has_ip:
        logger.warning(f"BPF filter may be invalid (filter={filter_string})")
        # We warn but don't reject - let tcpdump do final validation

    logger.debug(f"BPF filter validated (filter={filter_string})")
    return filter_string


def combine_filters(base: str | None, custom: str | None) -> str:
    """Combine base and custom BPF filters.

    Args:
        base: Base filter (typically the default)
        custom: Custom filter to add

    Returns:
        Combined filter string using AND logic

    Example:
        combine_filters("not port 22", "host 192.168.1.1")
        # Returns: "(not port 22) and (host 192.168.1.1)"
    """
    # Validate both filters
    base = validate_filter(base) if base else None
    custom = validate_filter(custom) if custom else None

    if not base and not custom:
        return DEFAULT_BPF_FILTER

    if not base:
        return custom

    if not custom:
        return base

    # Don't duplicate if they're the same
    if base.strip() == custom.strip():
        return base

    # Combine with AND
    combined = f"({base}) and ({custom})"
    logger.debug(f"Combined BPF filters (result={combined})")
    return combined


def build_capture_filter(
    exclude_ssh: bool = True,
    exclude_ports: list[int] | None = None,
    include_only_ports: list[int] | None = None,
    include_only_hosts: list[str] | None = None,
    custom_filter: str | None = None,
) -> str:
    """Build a BPF filter from common options.

    Args:
        exclude_ssh: Whether to exclude SSH (port 22) traffic
        exclude_ports: List of ports to exclude
        include_only_ports: List of ports to include (exclusive)
        include_only_hosts: List of hosts to include (exclusive)
        custom_filter: Additional custom filter to combine

    Returns:
        Complete BPF filter string
    """
    filters = []

    # SSH exclusion
    if exclude_ssh:
        filters.append("not port 22")

    # Port exclusions
    if exclude_ports:
        for port in exclude_ports:
            if isinstance(port, int) and 0 < port <= 65535:
                filters.append(f"not port {port}")

    # Port inclusions (exclusive)
    if include_only_ports:
        port_filters = [
            f"port {port}"
            for port in include_only_ports
            if isinstance(port, int) and 0 < port <= 65535
        ]
        if port_filters:
            filters.append(f"({' or '.join(port_filters)})")

    # Host inclusions (exclusive)
    if include_only_hosts:
        host_filters = [
            f"host {host}"
            for host in include_only_hosts
            if host and isinstance(host, str)
        ]
        if host_filters:
            filters.append(f"({' or '.join(host_filters)})")

    # Combine all filters
    if filters:
        result = " and ".join(filters)
    else:
        # Return empty string if no filters (not default)
        result = ""

    # Add custom filter if provided
    if custom_filter:
        if result:
            result = combine_filters(result, custom_filter)
        else:
            result = validate_filter(custom_filter)

    # If still empty, return empty string (caller decides default)
    if not result:
        result = ""

    if result:
        logger.info(f"Built capture filter (result={result})")
    return result
