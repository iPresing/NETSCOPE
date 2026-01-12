"""Integration tests for network API endpoints."""

import pytest
from unittest.mock import patch, MagicMock

from app.core.capture.interface_detector import (
    InterfaceType,
    NetworkInterface,
)


class TestNetworkStatusEndpoint:
    """Tests for GET /api/network/status endpoint."""

    def test_network_status_returns_200(self, client):
        """Test network status endpoint returns 200."""
        response = client.get('/api/network/status')
        assert response.status_code == 200

    def test_network_status_returns_json(self, client):
        """Test network status returns valid JSON structure."""
        response = client.get('/api/network/status')
        data = response.get_json()

        assert 'success' in data
        assert 'data' in data
        assert data['success'] is True

    def test_network_status_contains_expected_fields(self, client):
        """Test network status contains all expected fields."""
        response = client.get('/api/network/status')
        data = response.get_json()

        assert 'current_interface' in data['data']
        assert 'current_ip' in data['data']
        assert 'connection_mode' in data['data']


class TestNetworkInterfacesEndpoint:
    """Tests for GET /api/network/interfaces endpoint."""

    def test_network_interfaces_returns_200(self, client):
        """Test network interfaces endpoint returns 200."""
        response = client.get('/api/network/interfaces')
        assert response.status_code == 200

    def test_network_interfaces_returns_json(self, client):
        """Test network interfaces returns valid JSON structure."""
        response = client.get('/api/network/interfaces')
        data = response.get_json()

        assert 'success' in data
        assert 'data' in data
        assert data['success'] is True

    def test_network_interfaces_contains_interfaces_list(self, client):
        """Test network interfaces contains interfaces array."""
        response = client.get('/api/network/interfaces')
        data = response.get_json()

        assert 'interfaces' in data['data']
        assert isinstance(data['data']['interfaces'], list)

    def test_network_interfaces_contains_recommended(self, client):
        """Test network interfaces contains recommended field."""
        response = client.get('/api/network/interfaces')
        data = response.get_json()

        assert 'recommended' in data['data']

    @patch('app.blueprints.api.network.detect_interfaces')
    @patch('app.blueprints.api.network.get_recommended_interface')
    def test_network_interfaces_with_mocked_data(
        self, mock_recommended, mock_detect, client
    ):
        """Test network interfaces with controlled mock data."""
        mock_interface = NetworkInterface(
            name="eth0",
            type=InterfaceType.ETHERNET,
            ip_address="192.168.1.100",
            is_up=True,
            is_connected=True,
            mac_address="aa:bb:cc:dd:ee:ff",
            description="Ethernet"
        )
        mock_detect.return_value = [mock_interface]
        mock_recommended.return_value = mock_interface

        response = client.get('/api/network/interfaces')
        data = response.get_json()

        assert data['success'] is True
        assert len(data['data']['interfaces']) == 1
        assert data['data']['interfaces'][0]['name'] == 'eth0'
        assert data['data']['interfaces'][0]['type'] == 'ethernet'
        assert data['data']['interfaces'][0]['ip_address'] == '192.168.1.100'
        assert data['data']['recommended'] == 'eth0'

    @patch('app.blueprints.api.network.detect_interfaces')
    @patch('app.blueprints.api.network.get_recommended_interface')
    def test_network_interfaces_with_multiple_interfaces(
        self, mock_recommended, mock_detect, client
    ):
        """Test network interfaces with multiple interfaces."""
        eth_interface = NetworkInterface(
            name="eth0",
            type=InterfaceType.ETHERNET,
            ip_address="192.168.1.100",
            is_up=True,
            is_connected=True,
            mac_address="aa:bb:cc:dd:ee:ff",
            description="Ethernet"
        )
        usb_interface = NetworkInterface(
            name="usb0",
            type=InterfaceType.USB_GADGET,
            ip_address="192.168.50.1",
            is_up=True,
            is_connected=True,
            mac_address="bb:cc:dd:ee:ff:aa",
            description="USB Ethernet Gadget"
        )

        mock_detect.return_value = [eth_interface, usb_interface]
        mock_recommended.return_value = eth_interface

        response = client.get('/api/network/interfaces')
        data = response.get_json()

        assert data['success'] is True
        assert len(data['data']['interfaces']) == 2
        assert data['data']['recommended'] == 'eth0'

    @patch('app.blueprints.api.network.detect_interfaces')
    @patch('app.blueprints.api.network.get_recommended_interface')
    def test_network_interfaces_with_no_recommended(
        self, mock_recommended, mock_detect, client
    ):
        """Test network interfaces when no recommended interface."""
        mock_interface = NetworkInterface(
            name="eth0",
            type=InterfaceType.ETHERNET,
            ip_address=None,
            is_up=False,
            is_connected=False,
            mac_address="aa:bb:cc:dd:ee:ff",
            description="Ethernet"
        )
        mock_detect.return_value = [mock_interface]
        mock_recommended.return_value = None

        response = client.get('/api/network/interfaces')
        data = response.get_json()

        assert data['success'] is True
        assert data['data']['recommended'] is None

    @patch('app.blueprints.api.network.detect_interfaces')
    def test_network_interfaces_handles_error(self, mock_detect, client):
        """Test network interfaces handles exceptions gracefully."""
        mock_detect.side_effect = Exception("Network detection failed")

        response = client.get('/api/network/interfaces')
        data = response.get_json()

        assert response.status_code == 500
        assert data['success'] is False
        assert 'error' in data
        assert data['error']['code'] == 'NETWORK_INTERFACE_NOT_FOUND'


class TestNetworkApiIntegration:
    """Integration tests for network API endpoints."""

    def test_status_and_interfaces_consistency(self, client):
        """Test that status endpoint is consistent with interfaces endpoint."""
        status_response = client.get('/api/network/status')
        interfaces_response = client.get('/api/network/interfaces')

        status_data = status_response.get_json()
        interfaces_data = interfaces_response.get_json()

        # If there's a recommended interface, it should match status
        recommended = interfaces_data['data']['recommended']
        current_interface = status_data['data']['current_interface']

        # Both should be None or both should have the same value
        if recommended is not None and current_interface is not None:
            assert recommended == current_interface
