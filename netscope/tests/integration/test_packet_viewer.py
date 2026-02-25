"""Integration tests for packet viewer (Story 4.4)."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from app.models.capture import PacketInfo
from app.models.anomaly import (
    Anomaly, AnomalyCollection, BlacklistMatch,
    MatchType, CriticalityLevel,
)
from app.core.detection.anomaly_store import get_anomaly_store, reset_anomaly_store


@pytest.fixture(autouse=True)
def cleanup_anomaly_store():
    """Reset anomaly store between tests."""
    reset_anomaly_store()
    yield
    reset_anomaly_store()


class TestPacketsPage:
    """Tests for /packets page route."""

    def test_packets_page_accessible(self, client):
        """Packets page should return 200."""
        response = client.get('/packets')
        assert response.status_code == 200

    def test_packets_page_contains_table(self, client):
        """Packets page should contain the packet table."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')
        assert 'packets-table' in html
        assert 'packets-tbody' in html

    def test_packets_page_includes_scripts(self, client):
        """Packets page should include required JS files."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')
        assert 'packets.js' in html
        assert 'packet-detail.js' in html

    def test_packets_page_has_detail_panel(self, client):
        """Packets page should have the detail panel aside."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')
        assert 'packet-detail-panel' in html

    def test_packets_page_has_filters(self, client):
        """Packets page should have protocol and direction filters."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')
        assert 'protocol-filter' in html
        assert 'direction-filter' in html

    def test_packets_page_has_pagination(self, client):
        """Packets page should have pagination controls."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')
        assert 'packet-pagination' in html
        assert 'prev-page' in html
        assert 'next-page' in html


class TestPacketsApiMissingParams:
    """Tests for GET /api/packets with missing parameters."""

    def test_missing_params_returns_400(self, client):
        """Should return 400 when no capture_id or anomaly_id."""
        response = client.get('/api/packets')
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False
        assert data['error']['code'] == 'MISSING_PARAM'


class TestPacketsApiWithCapture:
    """Tests for GET /api/packets with capture_id."""

    def test_capture_not_found_returns_404(self, client):
        """Should return 404 when capture file not found."""
        response = client.get('/api/packets?capture_id=cap_nonexistent')
        assert response.status_code == 404
        data = response.get_json()
        assert data['error']['code'] == 'CAPTURE_NOT_FOUND'

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_returns_packets_with_pagination(self, mock_parse, mock_find, client):
        """Should return paginated packets."""
        from app.models.capture import CaptureSummary
        mock_find.return_value = '/fake/path.pcap'
        mock_packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, i),
                ip_src="10.0.0.1",
                ip_dst="192.168.1.1",
                port_src=12345,
                port_dst=80,
                protocol="TCP",
                length=100,
            )
            for i in range(3)
        ]
        mock_parse.return_value = (mock_packets, None)

        response = client.get('/api/packets?capture_id=cap_test&per_page=2&page=1')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        result = data['result']

        assert len(result['packets']) == 2
        assert result['pagination']['total'] == 3
        assert result['pagination']['total_pages'] == 2
        assert result['pagination']['page'] == 1

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_filter_by_ip(self, mock_parse, mock_find, client):
        """Should filter packets by IP."""
        from app.models.capture import CaptureSummary
        mock_find.return_value = '/fake/path.pcap'
        mock_packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 0),
                ip_src="10.0.0.1", ip_dst="192.168.1.1",
                port_src=12345, port_dst=80,
                protocol="TCP", length=100,
            ),
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 1),
                ip_src="10.0.0.2", ip_dst="192.168.1.2",
                port_src=12345, port_dst=443,
                protocol="TCP", length=200,
            ),
        ]
        mock_parse.return_value = (mock_packets, None)

        response = client.get('/api/packets?capture_id=cap_test&filter_ip=10.0.0.1')
        data = response.get_json()
        result = data['result']

        assert result['filter_summary']['total_filtered'] == 1
        assert result['filter_summary']['total_unfiltered'] == 2


class TestPacketsApiWithAnomaly:
    """Tests for GET /api/packets with anomaly_id."""

    def test_anomaly_not_found_returns_404(self, client):
        """Should return 404 when anomaly not found."""
        response = client.get('/api/packets?anomaly_id=anomaly_nonexistent')
        assert response.status_code == 404
        data = response.get_json()
        assert data['error']['code'] == 'ANOMALY_NOT_FOUND'

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_anomaly_resolves_capture_and_filter(self, mock_parse, mock_find, client, app):
        """Should resolve capture_id and filter from anomaly."""
        from app.models.capture import CaptureSummary
        # Setup anomaly store
        with app.app_context():
            store = get_anomaly_store()
            match = BlacklistMatch(
                match_type=MatchType.IP,
                matched_value="45.33.32.156",
                source_file="ips.txt",
                context="Blacklisted IP",
                criticality=CriticalityLevel.CRITICAL,
            )
            anomaly = Anomaly(
                id="anomaly_test001",
                match=match,
                score=85,
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id="cap_test_capture",
                packet_info={"ip_dst": "45.33.32.156", "port_dst": 443},
            )
            collection = AnomalyCollection(
                anomalies=[anomaly],
                capture_id="cap_test_capture",
            )
            store.store(collection)

        mock_find.return_value = '/fake/path.pcap'
        mock_packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 0),
                ip_src="10.0.0.1", ip_dst="45.33.32.156",
                port_src=12345, port_dst=443,
                protocol="TCP", length=100,
            ),
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 1),
                ip_src="10.0.0.2", ip_dst="192.168.1.1",
                port_src=54321, port_dst=80,
                protocol="TCP", length=200,
            ),
        ]
        mock_parse.return_value = (mock_packets, None)

        response = client.get('/api/packets?anomaly_id=anomaly_test001')
        data = response.get_json()
        assert data['success'] is True
        result = data['result']

        # Should have anomaly_context
        assert 'anomaly_context' in result
        assert result['anomaly_context']['anomaly_id'] == 'anomaly_test001'
        assert result['anomaly_context']['matched_value'] == '45.33.32.156'

        # Should auto-filter by IP
        assert result['filter_summary']['filter_ip'] == '45.33.32.156'
        assert result['filter_summary']['total_filtered'] == 1


class TestPacketDetailApi:
    """Tests for GET /api/packets/<capture_id>/<index>."""

    def test_capture_not_found(self, client):
        """Should return 404 for missing capture."""
        response = client.get('/api/packets/cap_nonexistent/0')
        assert response.status_code == 404
