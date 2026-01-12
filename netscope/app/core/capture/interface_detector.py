"""Interface Detector Module for NETSCOPE.

Detects and manages network interfaces for the application,
supporting USB gadget, Ethernet, and WiFi connections.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from enum import Enum

import psutil

logger = logging.getLogger(__name__)

# Constants
USB_GADGET_IP = "192.168.50.1"
USB_GADGET_INTERFACE = "usb0"
ETHERNET_INTERFACE = "eth0"
WIFI_INTERFACE = "wlan0"
INTERFACE_PRIORITY = [ETHERNET_INTERFACE, USB_GADGET_INTERFACE, WIFI_INTERFACE]

# Interfaces to exclude from detection
EXCLUDED_INTERFACES = {"lo", "localhost", "docker0", "br-", "veth"}


class InterfaceType(Enum):
    """Network interface types supported by NETSCOPE."""

    USB_GADGET = "usb_gadget"
    ETHERNET = "ethernet"
    WIFI = "wifi"
    UNKNOWN = "unknown"


@dataclass
class NetworkInterface:
    """Represents a network interface with its properties.

    Attributes:
        name: Interface name (e.g., 'eth0', 'usb0', 'wlan0')
        type: InterfaceType enum value
        ip_address: IPv4 address or None if not assigned
        is_up: Whether the interface is up
        is_connected: Whether the interface has a valid connection
        mac_address: MAC address of the interface
        description: Human-readable description
    """

    name: str
    type: InterfaceType
    ip_address: str | None
    is_up: bool
    is_connected: bool
    mac_address: str
    description: str


def _get_interface_type(name: str) -> InterfaceType:
    """Determine the interface type from its name.

    Args:
        name: Interface name

    Returns:
        InterfaceType enum value
    """
    if name == USB_GADGET_INTERFACE or name.startswith("usb"):
        return InterfaceType.USB_GADGET
    elif name == ETHERNET_INTERFACE or name.startswith("eth") or name.startswith("enp"):
        return InterfaceType.ETHERNET
    elif name == WIFI_INTERFACE or name.startswith("wlan") or name.startswith("wlp"):
        return InterfaceType.WIFI
    return InterfaceType.UNKNOWN


def _get_interface_description(interface_type: InterfaceType) -> str:
    """Get human-readable description for interface type.

    Args:
        interface_type: InterfaceType enum value

    Returns:
        Description string
    """
    descriptions = {
        InterfaceType.USB_GADGET: "USB Ethernet Gadget",
        InterfaceType.ETHERNET: "Ethernet",
        InterfaceType.WIFI: "WiFi",
        InterfaceType.UNKNOWN: "Unknown Interface",
    }
    return descriptions.get(interface_type, "Unknown Interface")


def _is_excluded_interface(name: str) -> bool:
    """Check if interface should be excluded from detection.

    Args:
        name: Interface name

    Returns:
        True if interface should be excluded
    """
    if name in EXCLUDED_INTERFACES:
        return True
    for prefix in EXCLUDED_INTERFACES:
        if name.startswith(prefix):
            return True
    return False


def detect_interfaces() -> list[NetworkInterface]:
    """Detect all available network interfaces.

    Scans system network interfaces and returns a list of
    NetworkInterface objects excluding loopback and virtual interfaces.

    Returns:
        List of NetworkInterface objects
    """
    interfaces = []

    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addr_list in addrs.items():
            if _is_excluded_interface(name):
                continue

            ip_address = None
            mac_address = ""

            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ip_address = addr.address
                # Handle MAC address - AF_PACKET on Linux, AF_LINK on macOS/Windows
                elif hasattr(socket, 'AF_PACKET') and addr.family == socket.AF_PACKET:
                    mac_address = addr.address
                elif hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK:
                    mac_address = addr.address

            interface_stats = stats.get(name)
            is_up = interface_stats.isup if interface_stats else False

            interface_type = _get_interface_type(name)
            is_connected = is_up and ip_address is not None

            interface = NetworkInterface(
                name=name,
                type=interface_type,
                ip_address=ip_address,
                is_up=is_up,
                is_connected=is_connected,
                mac_address=mac_address,
                description=_get_interface_description(interface_type),
            )
            interfaces.append(interface)

            logger.info(
                f"Interface detected (name={name}, type={interface_type.value}, "
                f"ip={ip_address}, connected={is_connected})"
            )

    except Exception as e:
        logger.error(f"Error detecting interfaces (error={str(e)})")

    return interfaces


def get_recommended_interface(
    interfaces: list[NetworkInterface],
) -> NetworkInterface | None:
    """Get the recommended interface based on priority.

    Priority order: eth0 > usb0 > wlan0
    Only connected interfaces are considered.

    Args:
        interfaces: List of NetworkInterface objects

    Returns:
        Recommended NetworkInterface or None if none available
    """
    # Filter to only connected interfaces
    connected = [i for i in interfaces if i.is_connected]

    if not connected:
        logger.warning("No connected interfaces found")
        return None

    # Sort by priority
    for priority_name in INTERFACE_PRIORITY:
        for interface in connected:
            if interface.name == priority_name:
                logger.info(
                    f"Recommended interface selected (name={interface.name}, "
                    f"ip={interface.ip_address})"
                )
                return interface

    # If no priority match, return first connected interface
    first_connected = connected[0]
    logger.info(
        f"Using first available interface (name={first_connected.name}, "
        f"ip={first_connected.ip_address})"
    )
    return first_connected


def get_current_ip() -> str | None:
    """Get the IP address of the current active interface.

    Returns:
        IP address string or None if no active interface
    """
    interfaces = detect_interfaces()
    recommended = get_recommended_interface(interfaces)

    if recommended:
        logger.info(f"Current IP: {recommended.ip_address} (interface={recommended.name})")
        return recommended.ip_address

    logger.warning("No active interface found, using fallback")
    return None
