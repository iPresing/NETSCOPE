"""End-to-end tests for packet inspection flow (Stories 4.4 + 4.5).

Tests the full flow from anomalies page through packet viewer to detail panel.
"""

import pytest
from unittest.mock import patch
from datetime import datetime

from app.models.capture import PacketInfo, CaptureSummary
from app.models.anomaly import (
    Anomaly, AnomalyCollection, BlacklistMatch,
    MatchType, CriticalityLevel,
)
from app.core.detection.anomaly_store import get_anomaly_store, reset_anomaly_store


@pytest.fixture(autouse=True)
def cleanup():
    """Clean up singletons between tests."""
    reset_anomaly_store()
    yield
    reset_anomaly_store()


class TestPacketViewerPageRendering:
    """E2E tests for the /packets page rendering."""

    def test_page_accessible(self, client):
        """Page /packets should be accessible."""
        response = client.get('/packets')
        assert response.status_code == 200

    def test_page_has_table_structure(self, client):
        """Page should contain the complete table structure."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')

        # Table headers
        assert 'Heure' in html
        assert 'Source' in html
        assert 'Destination' in html
        assert 'Proto' in html
        assert 'Taille' in html
        assert 'Flags' in html
        assert 'Info' in html

    def test_page_has_anomaly_context_banner(self, client):
        """Page should have the anomaly context banner (hidden by default)."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')
        assert 'anomaly-context-banner' in html
        assert 'Contexte Anomalie' in html

    def test_page_has_detail_panel_with_tabs(self, client):
        """Page should have detail panel with three tabs."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')
        assert 'packet-detail-panel' in html
        assert 'data-tab="layers"' in html
        assert 'data-tab="hex"' in html
        assert 'data-tab="ascii"' in html
        assert 'Couches' in html
        assert 'Hex Dump' in html
        assert 'ASCII' in html


class TestNavigationFromAnomaliesToPackets:
    """E2E tests for the anomalies -> packets navigation."""

    def test_anomalies_page_has_inspect_buttons(self, client):
        """Anomalies page should have inspect buttons."""
        response = client.get('/anomalies')
        html = response.data.decode('utf-8')
        assert 'anomalies.js' in html

    def test_anomalies_js_navigates_to_packets(self, client):
        """anomalies.js should navigate to /packets?anomaly_id=."""
        response = client.get('/static/js/anomalies.js')
        js = response.data.decode('utf-8')
        assert '/packets?anomaly_id=' in js
        assert 'window.location.href' in js


class TestFullApiFlow:
    """E2E tests for the complete API flow."""

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_anomaly_to_packets_to_detail(self, mock_parse, mock_find, client, app):
        """Full flow: anomaly -> packet list -> packet detail."""
        # 1. Setup anomaly
        with app.app_context():
            store = get_anomaly_store()
            match = BlacklistMatch(
                match_type=MatchType.IP,
                matched_value="185.220.101.1",
                source_file="ips_c2.txt",
                context="C2 server",
                criticality=CriticalityLevel.CRITICAL,
            )
            anomaly = Anomaly(
                id="anomaly_e2e_001",
                match=match,
                score=90,
                criticality_level=CriticalityLevel.CRITICAL,
                capture_id="cap_20260115_143001",
                packet_info={"ip_dst": "185.220.101.1", "port_dst": 443},
            )
            collection = AnomalyCollection(
                anomalies=[anomaly],
                capture_id="cap_20260115_143001",
            )
            store.store(collection)

        # 2. Setup mock pcap
        mock_find.return_value = '/fake/path.pcap'
        test_packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, i),
                ip_src="10.0.0.1",
                ip_dst="185.220.101.1",
                port_src=12345 + i,
                port_dst=443,
                protocol="TCP",
                length=100 + i * 50,
                tcp_flags="SYN" if i == 0 else "ACK",
            )
            for i in range(5)
        ]
        mock_parse.return_value = (test_packets, None)

        # 3. Call packets API with anomaly_id
        response = client.get('/api/packets?anomaly_id=anomaly_e2e_001')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

        result = data['result']

        # Verify anomaly context
        assert result['anomaly_context']['anomaly_id'] == 'anomaly_e2e_001'
        assert result['anomaly_context']['matched_value'] == '185.220.101.1'
        assert result['anomaly_context']['score'] == 90

        # Verify filter applied
        assert result['filter_summary']['filter_ip'] == '185.220.101.1'
        assert result['filter_summary']['total_filtered'] == 5

        # Verify packets have required fields
        for pkt in result['packets']:
            assert 'timestamp' in pkt
            assert 'ip_src' in pkt
            assert 'ip_dst' in pkt
            assert 'protocol' in pkt
            assert 'length' in pkt
            assert 'index' in pkt

        # Verify capture_id is set
        assert result['capture_id'] == 'cap_20260115_143001'

    def test_packets_page_rendering_complete(self, client):
        """Verify packets page renders all necessary DOM elements."""
        response = client.get('/packets')
        html = response.data.decode('utf-8')

        # Main structure
        assert 'packets-container' in html
        assert 'Visionneuse de Paquets' in html

        # Filters
        assert 'protocol-filter' in html
        assert 'direction-filter' in html

        # Table
        assert 'packets-table' in html

        # Pagination
        assert 'packet-pagination' in html

        # Detail panel
        assert 'packet-detail-panel' in html
        assert 'tab-layers' in html
        assert 'tab-hex' in html
        assert 'tab-ascii' in html

    def test_css_contains_packet_styles(self, client):
        """CSS should contain packet viewer and detail panel styles."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Packet viewer styles
        assert '.packets-container' in css
        assert '.anomaly-context-banner' in css
        assert '.packet-pagination' in css
        assert '.packet-row' in css

        # Detail panel styles
        assert '.packet-detail-panel' in css
        assert '.tab-btn' in css
        assert '.tab-content' in css
        assert '.layer-accordion' in css
        assert '.layer-header' in css
        assert '.hex-dump-content' in css
        assert '.ascii-dump-content' in css

    def test_packets_js_has_required_functions(self, client):
        """packets.js should have all required functions."""
        response = client.get('/static/js/packets.js')
        js = response.data.decode('utf-8')

        assert 'loadPackets' in js
        assert 'renderPacketTable' in js
        assert 'showAnomalyBanner' in js
        assert 'updatePagination' in js
        assert '/api/packets' in js

    def test_packet_detail_js_has_required_functions(self, client):
        """packet-detail.js should have all required functions."""
        response = client.get('/static/js/packet-detail.js')
        js = response.data.decode('utf-8')

        assert 'showPacketDetail' in js
        assert 'renderLayers' in js
        assert 'window.showPacketDetail' in js
        assert 'closePanel' in js
        assert 'setupTabs' in js
