"""Unit tests for interface_detector module."""

import pytest
from unittest.mock import patch, MagicMock
import socket

from app.core.capture.interface_detector import (
    InterfaceType,
    NetworkInterface,
    detect_interfaces,
    get_recommended_interface,
    get_current_ip,
    _get_interface_type,
    _get_interface_description,
    _is_excluded_interface,
    USB_GADGET_IP,
    USB_GADGET_INTERFACE,
    ETHERNET_INTERFACE,
    WIFI_INTERFACE,
    INTERFACE_PRIORITY,
)


class TestInterfaceType:
    """Tests for InterfaceType enum."""

    def test_interface_type_values(self):
        """Test InterfaceType enum has correct values."""
        assert InterfaceType.USB_GADGET.value == "usb_gadget"
        assert InterfaceType.ETHERNET.value == "ethernet"
        assert InterfaceType.WIFI.value == "wifi"
        assert InterfaceType.UNKNOWN.value == "unknown"

    def test_interface_type_members(self):
        """Test all expected InterfaceType members exist."""
        members = [e.name for e in InterfaceType]
        assert "USB_GADGET" in members
        assert "ETHERNET" in members
        assert "WIFI" in members
        assert "UNKNOWN" in members


class TestNetworkInterface:
    """Tests for NetworkInterface dataclass."""

    def test_network_interface_creation(self):
        """Test NetworkInterface can be created with all fields."""
        interface = NetworkInterface(
            name="eth0",
            type=InterfaceType.ETHERNET,
            ip_address="192.168.1.100",
            is_up=True,
            is_connected=True,
            mac_address="aa:bb:cc:dd:ee:ff",
            description="Ethernet interface"
        )
        assert interface.name == "eth0"
        assert interface.type == InterfaceType.ETHERNET
        assert interface.ip_address == "192.168.1.100"
        assert interface.is_up is True
        assert interface.is_connected is True
        assert interface.mac_address == "aa:bb:cc:dd:ee:ff"
        assert interface.description == "Ethernet interface"

    def test_network_interface_with_none_ip(self):
        """Test NetworkInterface can have None ip_address."""
        interface = NetworkInterface(
            name="eth0",
            type=InterfaceType.ETHERNET,
            ip_address=None,
            is_up=True,
            is_connected=False,
            mac_address="aa:bb:cc:dd:ee:ff",
            description="Ethernet interface"
        )
        assert interface.ip_address is None
        assert interface.is_connected is False


class TestConstants:
    """Tests for module constants."""

    def test_usb_gadget_ip(self):
        """Test USB gadget IP constant."""
        assert USB_GADGET_IP == "192.168.50.1"

    def test_interface_names(self):
        """Test interface name constants."""
        assert USB_GADGET_INTERFACE == "usb0"
        assert ETHERNET_INTERFACE == "eth0"
        assert WIFI_INTERFACE == "wlan0"

    def test_interface_priority(self):
        """Test interface priority order (eth0 > usb0 > wlan0)."""
        assert INTERFACE_PRIORITY == ["eth0", "usb0", "wlan0"]
        assert INTERFACE_PRIORITY[0] == ETHERNET_INTERFACE
        assert INTERFACE_PRIORITY[1] == USB_GADGET_INTERFACE
        assert INTERFACE_PRIORITY[2] == WIFI_INTERFACE


class TestGetInterfaceType:
    """Tests for _get_interface_type helper function."""

    def test_usb0_returns_usb_gadget(self):
        """Test usb0 is identified as USB_GADGET."""
        assert _get_interface_type("usb0") == InterfaceType.USB_GADGET

    def test_usb_prefix_returns_usb_gadget(self):
        """Test interfaces starting with usb are USB_GADGET."""
        assert _get_interface_type("usb1") == InterfaceType.USB_GADGET

    def test_eth0_returns_ethernet(self):
        """Test eth0 is identified as ETHERNET."""
        assert _get_interface_type("eth0") == InterfaceType.ETHERNET

    def test_eth_prefix_returns_ethernet(self):
        """Test interfaces starting with eth are ETHERNET."""
        assert _get_interface_type("eth1") == InterfaceType.ETHERNET

    def test_enp_prefix_returns_ethernet(self):
        """Test interfaces starting with enp are ETHERNET."""
        assert _get_interface_type("enp0s3") == InterfaceType.ETHERNET

    def test_wlan0_returns_wifi(self):
        """Test wlan0 is identified as WIFI."""
        assert _get_interface_type("wlan0") == InterfaceType.WIFI

    def test_wlan_prefix_returns_wifi(self):
        """Test interfaces starting with wlan are WIFI."""
        assert _get_interface_type("wlan1") == InterfaceType.WIFI

    def test_wlp_prefix_returns_wifi(self):
        """Test interfaces starting with wlp are WIFI."""
        assert _get_interface_type("wlp2s0") == InterfaceType.WIFI

    def test_unknown_interface_returns_unknown(self):
        """Test unknown interfaces return UNKNOWN."""
        assert _get_interface_type("bond0") == InterfaceType.UNKNOWN
        assert _get_interface_type("tun0") == InterfaceType.UNKNOWN


class TestGetInterfaceDescription:
    """Tests for _get_interface_description helper function."""

    def test_usb_gadget_description(self):
        """Test USB_GADGET returns correct description."""
        assert _get_interface_description(InterfaceType.USB_GADGET) == "USB Ethernet Gadget"

    def test_ethernet_description(self):
        """Test ETHERNET returns correct description."""
        assert _get_interface_description(InterfaceType.ETHERNET) == "Ethernet"

    def test_wifi_description(self):
        """Test WIFI returns correct description."""
        assert _get_interface_description(InterfaceType.WIFI) == "WiFi"

    def test_unknown_description(self):
        """Test UNKNOWN returns correct description."""
        assert _get_interface_description(InterfaceType.UNKNOWN) == "Unknown Interface"


class TestIsExcludedInterface:
    """Tests for _is_excluded_interface helper function."""

    def test_loopback_excluded(self):
        """Test loopback interface is excluded."""
        assert _is_excluded_interface("lo") is True

    def test_localhost_excluded(self):
        """Test localhost interface is excluded."""
        assert _is_excluded_interface("localhost") is True

    def test_docker0_excluded(self):
        """Test docker0 interface is excluded."""
        assert _is_excluded_interface("docker0") is True

    def test_docker_bridge_excluded(self):
        """Test docker bridge interfaces are excluded."""
        assert _is_excluded_interface("br-abc123") is True

    def test_veth_excluded(self):
        """Test veth interfaces are excluded."""
        assert _is_excluded_interface("veth123abc") is True

    def test_eth0_not_excluded(self):
        """Test eth0 is NOT excluded."""
        assert _is_excluded_interface("eth0") is False

    def test_usb0_not_excluded(self):
        """Test usb0 is NOT excluded."""
        assert _is_excluded_interface("usb0") is False

    def test_wlan0_not_excluded(self):
        """Test wlan0 is NOT excluded."""
        assert _is_excluded_interface("wlan0") is False


class TestDetectInterfaces:
    """Tests for detect_interfaces function."""

    @patch('app.core.capture.interface_detector.psutil')
    def test_detect_interfaces_with_eth0(self, mock_psutil):
        """Test detection with eth0 interface."""
        mock_psutil.net_if_addrs.return_value = {
            'eth0': [
                MagicMock(family=socket.AF_INET, address='192.168.1.100'),
                MagicMock(family=socket.AF_PACKET if hasattr(socket, 'AF_PACKET') else -1, address='aa:bb:cc:dd:ee:ff'),
            ],
            'lo': [
                MagicMock(family=socket.AF_INET, address='127.0.0.1'),
            ],
        }
        mock_psutil.net_if_stats.return_value = {
            'eth0': MagicMock(isup=True),
            'lo': MagicMock(isup=True),
        }

        interfaces = detect_interfaces()

        # Should detect eth0, not lo (loopback)
        interface_names = [i.name for i in interfaces]
        assert 'eth0' in interface_names
        assert 'lo' not in interface_names

    @patch('app.core.capture.interface_detector.psutil')
    def test_detect_interfaces_with_usb0(self, mock_psutil):
        """Test detection with usb0 interface (USB gadget)."""
        mock_psutil.net_if_addrs.return_value = {
            'usb0': [
                MagicMock(family=socket.AF_INET, address='192.168.50.1'),
            ],
        }
        mock_psutil.net_if_stats.return_value = {
            'usb0': MagicMock(isup=True),
        }

        interfaces = detect_interfaces()

        assert len(interfaces) == 1
        assert interfaces[0].name == 'usb0'
        assert interfaces[0].type == InterfaceType.USB_GADGET
        assert interfaces[0].ip_address == '192.168.50.1'

    @patch('app.core.capture.interface_detector.psutil')
    def test_detect_interfaces_with_wlan0(self, mock_psutil):
        """Test detection with wlan0 interface (WiFi)."""
        mock_psutil.net_if_addrs.return_value = {
            'wlan0': [
                MagicMock(family=socket.AF_INET, address='192.168.1.50'),
            ],
        }
        mock_psutil.net_if_stats.return_value = {
            'wlan0': MagicMock(isup=True),
        }

        interfaces = detect_interfaces()

        assert len(interfaces) == 1
        assert interfaces[0].name == 'wlan0'
        assert interfaces[0].type == InterfaceType.WIFI

    @patch('app.core.capture.interface_detector.psutil')
    def test_detect_interfaces_excludes_loopback(self, mock_psutil):
        """Test that loopback interface is excluded."""
        mock_psutil.net_if_addrs.return_value = {
            'lo': [MagicMock(family=socket.AF_INET, address='127.0.0.1')],
        }
        mock_psutil.net_if_stats.return_value = {
            'lo': MagicMock(isup=True),
        }

        interfaces = detect_interfaces()

        assert len(interfaces) == 0

    @patch('app.core.capture.interface_detector.psutil')
    def test_detect_interfaces_empty_when_none(self, mock_psutil):
        """Test detection returns empty list when no interfaces."""
        mock_psutil.net_if_addrs.return_value = {}
        mock_psutil.net_if_stats.return_value = {}

        interfaces = detect_interfaces()

        assert interfaces == []


class TestGetRecommendedInterface:
    """Tests for get_recommended_interface function."""

    def test_recommended_interface_prefers_eth0(self):
        """Test that eth0 is preferred over usb0 and wlan0."""
        interfaces = [
            NetworkInterface(
                name="wlan0", type=InterfaceType.WIFI,
                ip_address="192.168.1.50", is_up=True, is_connected=True,
                mac_address="aa:bb:cc:dd:ee:ff", description="WiFi"
            ),
            NetworkInterface(
                name="usb0", type=InterfaceType.USB_GADGET,
                ip_address="192.168.50.1", is_up=True, is_connected=True,
                mac_address="bb:cc:dd:ee:ff:aa", description="USB"
            ),
            NetworkInterface(
                name="eth0", type=InterfaceType.ETHERNET,
                ip_address="192.168.1.100", is_up=True, is_connected=True,
                mac_address="cc:dd:ee:ff:aa:bb", description="Ethernet"
            ),
        ]

        recommended = get_recommended_interface(interfaces)

        assert recommended is not None
        assert recommended.name == "eth0"

    def test_recommended_interface_usb0_when_no_eth0(self):
        """Test that usb0 is chosen when eth0 not available."""
        interfaces = [
            NetworkInterface(
                name="wlan0", type=InterfaceType.WIFI,
                ip_address="192.168.1.50", is_up=True, is_connected=True,
                mac_address="aa:bb:cc:dd:ee:ff", description="WiFi"
            ),
            NetworkInterface(
                name="usb0", type=InterfaceType.USB_GADGET,
                ip_address="192.168.50.1", is_up=True, is_connected=True,
                mac_address="bb:cc:dd:ee:ff:aa", description="USB"
            ),
        ]

        recommended = get_recommended_interface(interfaces)

        assert recommended is not None
        assert recommended.name == "usb0"

    def test_recommended_interface_wlan0_as_fallback(self):
        """Test that wlan0 is chosen as last resort."""
        interfaces = [
            NetworkInterface(
                name="wlan0", type=InterfaceType.WIFI,
                ip_address="192.168.1.50", is_up=True, is_connected=True,
                mac_address="aa:bb:cc:dd:ee:ff", description="WiFi"
            ),
        ]

        recommended = get_recommended_interface(interfaces)

        assert recommended is not None
        assert recommended.name == "wlan0"

    def test_recommended_interface_requires_connected(self):
        """Test that only connected interfaces are considered."""
        interfaces = [
            NetworkInterface(
                name="eth0", type=InterfaceType.ETHERNET,
                ip_address=None, is_up=True, is_connected=False,
                mac_address="cc:dd:ee:ff:aa:bb", description="Ethernet"
            ),
            NetworkInterface(
                name="usb0", type=InterfaceType.USB_GADGET,
                ip_address="192.168.50.1", is_up=True, is_connected=True,
                mac_address="bb:cc:dd:ee:ff:aa", description="USB"
            ),
        ]

        recommended = get_recommended_interface(interfaces)

        assert recommended is not None
        assert recommended.name == "usb0"

    def test_recommended_interface_none_when_empty(self):
        """Test returns None when no interfaces available."""
        recommended = get_recommended_interface([])

        assert recommended is None

    def test_recommended_interface_none_when_all_disconnected(self):
        """Test returns None when all interfaces disconnected."""
        interfaces = [
            NetworkInterface(
                name="eth0", type=InterfaceType.ETHERNET,
                ip_address=None, is_up=False, is_connected=False,
                mac_address="cc:dd:ee:ff:aa:bb", description="Ethernet"
            ),
        ]

        recommended = get_recommended_interface(interfaces)

        assert recommended is None


class TestGetCurrentIp:
    """Tests for get_current_ip function."""

    @patch('app.core.capture.interface_detector.detect_interfaces')
    @patch('app.core.capture.interface_detector.get_recommended_interface')
    def test_get_current_ip_returns_ip(self, mock_recommended, mock_detect):
        """Test get_current_ip returns IP of recommended interface."""
        mock_interface = NetworkInterface(
            name="eth0", type=InterfaceType.ETHERNET,
            ip_address="192.168.1.100", is_up=True, is_connected=True,
            mac_address="aa:bb:cc:dd:ee:ff", description="Ethernet"
        )
        mock_detect.return_value = [mock_interface]
        mock_recommended.return_value = mock_interface

        ip = get_current_ip()

        assert ip == "192.168.1.100"

    @patch('app.core.capture.interface_detector.detect_interfaces')
    @patch('app.core.capture.interface_detector.get_recommended_interface')
    def test_get_current_ip_returns_none_when_no_interface(self, mock_recommended, mock_detect):
        """Test get_current_ip returns None when no interface available."""
        mock_detect.return_value = []
        mock_recommended.return_value = None

        ip = get_current_ip()

        assert ip is None
