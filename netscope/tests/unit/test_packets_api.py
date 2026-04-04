"""Unit tests for packet viewer API and helpers (Story 4.4 / 4b.7)."""

import pytest
import yaml
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.models.capture import PacketInfo
from app.core.capture.packet_parser import (
    filter_packets,
    find_pcap_by_capture_id,
    _extract_tcp_flags,
    SCAPY_AVAILABLE,
)
from app.blueprints.api.packets import (
    _filter_by_port_protocol_direction,
    _find_latest_pcap,
)


class TestFilterPackets:
    """Tests for filter_packets()."""

    def _make_packet(self, ip_src="10.0.0.1", ip_dst="192.168.1.1",
                     dns_queries=None, http_host=None, protocol="TCP"):
        return PacketInfo(
            timestamp=datetime(2026, 1, 15, 14, 30, 0),
            ip_src=ip_src,
            ip_dst=ip_dst,
            port_src=12345,
            port_dst=443,
            protocol=protocol,
            length=100,
            dns_queries=dns_queries or [],
            http_host=http_host,
        )

    def test_no_filters_returns_all(self):
        """No filters should return all packets."""
        packets = [self._make_packet(), self._make_packet()]
        result = filter_packets(packets)
        assert len(result) == 2

    def test_filter_by_ip_src(self):
        """Filter by IP should match source."""
        packets = [
            self._make_packet(ip_src="10.0.0.1"),
            self._make_packet(ip_src="10.0.0.2"),
        ]
        result = filter_packets(packets, filter_ip="10.0.0.1")
        assert len(result) == 1
        assert result[0].ip_src == "10.0.0.1"

    def test_filter_by_ip_dst(self):
        """Filter by IP should match destination."""
        packets = [
            self._make_packet(ip_dst="192.168.1.1"),
            self._make_packet(ip_dst="192.168.1.2"),
        ]
        result = filter_packets(packets, filter_ip="192.168.1.2")
        assert len(result) == 1
        assert result[0].ip_dst == "192.168.1.2"

    def test_filter_by_domain_dns(self):
        """Filter by domain should match DNS queries."""
        packets = [
            self._make_packet(dns_queries=["evil.com"]),
            self._make_packet(dns_queries=["good.com"]),
        ]
        result = filter_packets(packets, filter_domain="evil.com")
        assert len(result) == 1
        assert "evil.com" in result[0].dns_queries

    def test_filter_by_domain_http_host(self):
        """Filter by domain should match HTTP Host."""
        packets = [
            self._make_packet(http_host="malware.org"),
            self._make_packet(http_host="safe.org"),
        ]
        result = filter_packets(packets, filter_domain="malware.org")
        assert len(result) == 1
        assert result[0].http_host == "malware.org"

    def test_filter_combined_ip_and_domain(self):
        """Combined filters should intersect."""
        packets = [
            self._make_packet(ip_src="10.0.0.1", dns_queries=["evil.com"]),
            self._make_packet(ip_src="10.0.0.1", dns_queries=["good.com"]),
            self._make_packet(ip_src="10.0.0.2", dns_queries=["evil.com"]),
        ]
        result = filter_packets(packets, filter_ip="10.0.0.1", filter_domain="evil.com")
        assert len(result) == 1

    def test_filter_empty_list(self):
        """Filtering empty list should return empty list."""
        result = filter_packets([], filter_ip="10.0.0.1")
        assert result == []

    def test_filter_domain_case_insensitive(self):
        """Domain filter should be case-insensitive."""
        packets = [self._make_packet(http_host="Evil.COM")]
        result = filter_packets(packets, filter_domain="evil.com")
        assert len(result) == 1


class TestFindPcapByCaptureId:
    """Tests for find_pcap_by_capture_id()."""

    def test_find_existing_pcap(self, monkeypatch, tmp_path):
        """Should find existing pcap file in the captures directory."""
        captures_dir = tmp_path / "data" / "captures"
        captures_dir.mkdir(parents=True)
        pcap_file = captures_dir / "cap_20260115_143001.pcap"
        pcap_file.write_bytes(b"fake pcap")

        # Monkeypatch the Path constructor used inside find_pcap_by_capture_id
        import app.core.capture.packet_parser as parser_mod
        original_path = Path

        def patched_path(p):
            if p == "data/captures":
                return original_path(captures_dir)
            return original_path(p)

        monkeypatch.setattr(parser_mod, 'Path', patched_path)

        result = find_pcap_by_capture_id("cap_20260115_143001")
        assert result is not None
        assert result.exists()
        assert result.name == "cap_20260115_143001.pcap"

    def test_find_nonexistent_returns_none(self):
        """Should return None for nonexistent capture."""
        result = find_pcap_by_capture_id("cap_nonexistent_000000")
        assert result is None


class TestCaptureConfigSnapLength:
    """Tests for CaptureConfig snap_length field."""

    def test_capture_config_has_snap_length(self):
        """CaptureConfig should accept snap_length."""
        from app.models.capture import CaptureConfig
        config = CaptureConfig(snap_length=1500)
        assert config.snap_length == 1500

    def test_capture_config_default_snap_length(self):
        """CaptureConfig default snap_length should be 1500."""
        from app.models.capture import CaptureConfig
        config = CaptureConfig()
        assert config.snap_length == 1500

    def test_capture_config_to_dict_includes_snap_length(self):
        """CaptureConfig.to_dict() should include snap_length."""
        from app.models.capture import CaptureConfig
        config = CaptureConfig(snap_length=1500)
        d = config.to_dict()
        assert "snap_length" in d
        assert d["snap_length"] == 1500


class TestPacketInfoTcpFlags:
    """Tests for PacketInfo tcp_flags field."""

    def test_packet_info_has_tcp_flags(self):
        """PacketInfo should accept tcp_flags."""
        pkt = PacketInfo(
            timestamp=datetime(2026, 1, 15),
            ip_src="10.0.0.1",
            ip_dst="10.0.0.2",
            port_src=12345,
            port_dst=80,
            protocol="TCP",
            tcp_flags="SYN ACK",
        )
        assert pkt.tcp_flags == "SYN ACK"

    def test_packet_info_tcp_flags_in_to_dict(self):
        """PacketInfo.to_dict() should include tcp_flags when set."""
        pkt = PacketInfo(
            timestamp=datetime(2026, 1, 15),
            ip_src="10.0.0.1",
            ip_dst="10.0.0.2",
            port_src=12345,
            port_dst=80,
            protocol="TCP",
            tcp_flags="SYN",
        )
        d = pkt.to_dict()
        assert "tcp_flags" in d
        assert d["tcp_flags"] == "SYN"

    def test_packet_info_no_tcp_flags_not_in_dict(self):
        """PacketInfo.to_dict() should NOT include tcp_flags when None."""
        pkt = PacketInfo(
            timestamp=datetime(2026, 1, 15),
            ip_src="10.0.0.1",
            ip_dst="10.0.0.2",
            port_src=12345,
            port_dst=80,
            protocol="TCP",
        )
        d = pkt.to_dict()
        assert "tcp_flags" not in d


class TestLoadSnapLength:
    """Tests for _load_snap_length()."""

    def test_load_snap_length_returns_default_if_missing(self):
        """Should return 1500 if config file missing."""
        from app.core.capture.tcpdump_manager import _load_snap_length
        with patch('app.core.capture.tcpdump_manager.Path') as mock_path:
            mock_path.return_value.exists.return_value = False
            result = _load_snap_length()
        assert result == 1500

    def test_load_snap_length_reads_yaml_config(self, tmp_path):
        """Should read snap_length from YAML config file."""
        from app.core.capture.tcpdump_manager import _load_snap_length

        config_file = tmp_path / "netscope.yaml"
        config_data = {"capture": {"snap_length": 256}}
        config_file.write_text(yaml.dump(config_data), encoding="utf-8")

        with patch('app.core.capture.tcpdump_manager.Path') as mock_path:
            mock_instance = MagicMock()
            mock_instance.exists.return_value = True
            mock_path.return_value = mock_instance

            # Make open() use the real tmp file
            with patch('builtins.open', return_value=open(config_file, "r", encoding="utf-8")):
                result = _load_snap_length()

        assert result == 256

    def test_load_snap_length_handles_malformed_yaml(self):
        """Should return default if YAML parsing fails."""
        from app.core.capture.tcpdump_manager import _load_snap_length
        with patch('app.core.capture.tcpdump_manager.Path') as mock_path:
            mock_instance = MagicMock()
            mock_instance.exists.return_value = True
            mock_path.return_value = mock_instance

            with patch('builtins.open', side_effect=Exception("corrupt file")):
                result = _load_snap_length()

        assert result == 1500


class TestExtractTcpFlags:
    """Tests for _extract_tcp_flags()."""

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_extract_syn_flag(self):
        """Should extract SYN flag."""
        from scapy.all import TCP
        tcp_layer = TCP(flags='S')
        result = _extract_tcp_flags(tcp_layer)
        assert 'SYN' in result

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_extract_syn_ack_flags(self):
        """Should extract SYN ACK flags."""
        from scapy.all import TCP
        tcp_layer = TCP(flags='SA')
        result = _extract_tcp_flags(tcp_layer)
        assert 'SYN' in result
        assert 'ACK' in result

    def test_extract_flags_with_mock(self):
        """Should handle mock TCP layer."""
        mock_layer = MagicMock()
        mock_layer.flags = 'SA'
        result = _extract_tcp_flags(mock_layer)
        assert 'SYN' in result
        assert 'ACK' in result


class TestCaptureIdValidation:
    """Tests for capture_id validation in packets API."""

    def test_valid_capture_id_accepted(self):
        """Valid capture IDs should pass validation."""
        from app.blueprints.api.packets import _validate_capture_id
        assert _validate_capture_id("cap_20260115_143001") is True
        assert _validate_capture_id("test-capture") is True
        assert _validate_capture_id("abc123") is True

    def test_path_traversal_rejected(self):
        """Path traversal attempts should be rejected."""
        from app.blueprints.api.packets import _validate_capture_id
        assert _validate_capture_id("../../etc/passwd") is False
        assert _validate_capture_id("../config/secret") is False
        assert _validate_capture_id("cap_test/../../etc") is False

    def test_special_chars_rejected(self):
        """Special characters should be rejected."""
        from app.blueprints.api.packets import _validate_capture_id
        assert _validate_capture_id("cap test") is False
        assert _validate_capture_id("cap;rm -rf") is False
        assert _validate_capture_id("") is False

    def test_api_rejects_invalid_capture_id(self, client):
        """API should return 400 for invalid capture_id."""
        response = client.get('/api/packets?capture_id=../../etc/passwd')
        assert response.status_code == 400
        data = response.get_json()
        assert data['error']['code'] == 'INVALID_PARAM'

    def test_detail_api_rejects_invalid_capture_id(self, client):
        """Detail API should return 400 for invalid capture_id."""
        response = client.get('/api/packets/../../etc/passwd/0')
        # Flask routing with slashes may return 404 instead of 400
        assert response.status_code in (400, 404)


class TestPerPageBounds:
    """Tests for per_page parameter clamping."""

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_per_page_zero_clamped_to_one(self, mock_parse, mock_find, client):
        """per_page=0 should be clamped to 1."""
        from app.models.capture import CaptureSummary
        mock_find.return_value = '/fake/path.pcap'
        mock_packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, i),
                ip_src="10.0.0.1", ip_dst="192.168.1.1",
                port_src=12345, port_dst=80,
                protocol="TCP", length=100,
            )
            for i in range(5)
        ]
        mock_parse.return_value = (mock_packets, None)

        response = client.get('/api/packets?capture_id=cap_test&per_page=0')
        data = response.get_json()
        assert data['result']['pagination']['per_page'] == 1

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_per_page_over_max_clamped_to_200(self, mock_parse, mock_find, client):
        """per_page=999 should be clamped to 200."""
        from app.models.capture import CaptureSummary
        mock_find.return_value = '/fake/path.pcap'
        mock_packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 0),
                ip_src="10.0.0.1", ip_dst="192.168.1.1",
                port_src=12345, port_dst=80,
                protocol="TCP", length=100,
            )
        ]
        mock_parse.return_value = (mock_packets, None)

        response = client.get('/api/packets?capture_id=cap_test&per_page=999')
        data = response.get_json()
        assert data['result']['pagination']['per_page'] == 200

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_per_page_negative_clamped_to_one(self, mock_parse, mock_find, client):
        """per_page=-5 should be clamped to 1."""
        from app.models.capture import CaptureSummary
        mock_find.return_value = '/fake/path.pcap'
        mock_packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 0),
                ip_src="10.0.0.1", ip_dst="192.168.1.1",
                port_src=12345, port_dst=80,
                protocol="TCP", length=100,
            )
        ]
        mock_parse.return_value = (mock_packets, None)

        response = client.get('/api/packets?capture_id=cap_test&per_page=-5')
        data = response.get_json()
        assert data['result']['pagination']['per_page'] == 1


# ============================================================
# Story 4b.7 Tests — Port, Protocol, Direction filtering
# ============================================================

class TestFilterByPortProtocolDirection:
    """Tests for _filter_by_port_protocol_direction() helper (Story 4b.7)."""

    def _make_packet(self, ip_src="10.0.0.1", ip_dst="192.168.1.1",
                     port_src=12345, port_dst=443, protocol="TCP"):
        return PacketInfo(
            timestamp=datetime(2026, 1, 15, 14, 30, 0),
            ip_src=ip_src, ip_dst=ip_dst,
            port_src=port_src, port_dst=port_dst,
            protocol=protocol, length=100,
        )

    def test_filter_by_port_both(self):
        """Port filter with default direction matches src or dst."""
        packets = [
            self._make_packet(port_src=443, port_dst=80),
            self._make_packet(port_src=80, port_dst=443),
            self._make_packet(port_src=80, port_dst=80),
        ]
        result = _filter_by_port_protocol_direction(packets, port=443)
        assert len(result) == 2

    def test_filter_by_port_src_only(self):
        """Port filter with direction=src matches only source port."""
        packets = [
            self._make_packet(port_src=443, port_dst=80),
            self._make_packet(port_src=80, port_dst=443),
        ]
        result = _filter_by_port_protocol_direction(packets, port=443, direction='src')
        assert len(result) == 1
        assert result[0].port_src == 443

    def test_filter_by_port_dst_only(self):
        """Port filter with direction=dst matches only destination port."""
        packets = [
            self._make_packet(port_src=443, port_dst=80),
            self._make_packet(port_src=80, port_dst=443),
        ]
        result = _filter_by_port_protocol_direction(packets, port=443, direction='dst')
        assert len(result) == 1
        assert result[0].port_dst == 443

    def test_filter_by_protocol(self):
        """Protocol filter matches packet protocol."""
        packets = [
            self._make_packet(protocol="TCP"),
            self._make_packet(protocol="UDP"),
            self._make_packet(protocol="TCP"),
        ]
        result = _filter_by_port_protocol_direction(packets, protocol="TCP")
        assert len(result) == 2

    def test_filter_by_protocol_case_insensitive(self):
        """Protocol filter is case-insensitive (compared uppercase)."""
        packets = [self._make_packet(protocol="TCP")]
        result = _filter_by_port_protocol_direction(packets, protocol="tcp")
        assert len(result) == 1

    def test_filter_by_direction_ip_src(self):
        """Direction=src with filter_ip matches only ip_src."""
        packets = [
            self._make_packet(ip_src="10.0.0.1", ip_dst="192.168.1.1"),
            self._make_packet(ip_src="192.168.1.1", ip_dst="10.0.0.1"),
        ]
        result = _filter_by_port_protocol_direction(
            packets, direction='src', filter_ip='10.0.0.1')
        assert len(result) == 1
        assert result[0].ip_src == "10.0.0.1"

    def test_filter_by_direction_ip_dst(self):
        """Direction=dst with filter_ip matches only ip_dst."""
        packets = [
            self._make_packet(ip_src="10.0.0.1", ip_dst="192.168.1.1"),
            self._make_packet(ip_src="192.168.1.1", ip_dst="10.0.0.1"),
        ]
        result = _filter_by_port_protocol_direction(
            packets, direction='dst', filter_ip='192.168.1.1')
        assert len(result) == 1
        assert result[0].ip_dst == "192.168.1.1"

    def test_combined_port_and_protocol(self):
        """Combined port + protocol filter intersects correctly."""
        packets = [
            self._make_packet(port_dst=443, protocol="TCP"),
            self._make_packet(port_dst=443, protocol="UDP"),
            self._make_packet(port_dst=80, protocol="TCP"),
        ]
        result = _filter_by_port_protocol_direction(packets, port=443, protocol="TCP")
        assert len(result) == 1
        assert result[0].port_dst == 443 and result[0].protocol == "TCP"

    def test_no_filters_returns_all(self):
        """No filters returns all packets unchanged."""
        packets = [self._make_packet(), self._make_packet()]
        result = _filter_by_port_protocol_direction(packets)
        assert len(result) == 2

    def test_empty_list(self):
        """Filtering empty list returns empty list."""
        result = _filter_by_port_protocol_direction([], port=443, protocol="TCP")
        assert result == []


class TestFindLatestPcap:
    """Tests for _find_latest_pcap() helper (Story 4b.7 AC3)."""

    def test_returns_none_when_no_captures_dir(self, tmp_path):
        """Returns None when captures directory doesn't exist."""
        with patch('app.blueprints.api.packets.Path') as mock_path:
            mock_path.return_value.exists.return_value = False
            result = _find_latest_pcap()
        assert result is None

    def test_returns_none_when_no_pcap_files(self, tmp_path):
        """Returns None when captures directory is empty."""
        captures_dir = tmp_path / "captures"
        captures_dir.mkdir()

        with patch('app.blueprints.api.packets.Path') as mock_path:
            mock_captures = MagicMock()
            mock_captures.exists.return_value = True
            mock_captures.glob.return_value = []
            mock_path.return_value = mock_captures
            result = _find_latest_pcap()
        assert result is None

    def test_returns_latest_pcap_by_mtime(self, tmp_path):
        """Returns the most recent pcap file."""
        import time
        captures_dir = tmp_path / "captures"
        captures_dir.mkdir()

        old_pcap = captures_dir / "cap_old.pcap"
        old_pcap.write_bytes(b"old")
        time.sleep(0.05)
        new_pcap = captures_dir / "cap_new.pcap"
        new_pcap.write_bytes(b"new")

        with patch('app.blueprints.api.packets.Path') as mock_path:
            mock_path.return_value = captures_dir
            capture_id, path = _find_latest_pcap()

        assert capture_id == "cap_new"
        assert path == new_pcap


class TestPacketsApiNewParams:
    """Integration tests for new API params (Story 4b.7)."""

    def _make_mock_packets(self):
        """Create a diverse set of mock packets for filtering tests."""
        return [
            PacketInfo(timestamp=datetime(2026, 1, 15, 14, 30, 0),
                       ip_src="10.0.0.1", ip_dst="192.168.1.1",
                       port_src=12345, port_dst=443, protocol="TCP", length=100),
            PacketInfo(timestamp=datetime(2026, 1, 15, 14, 30, 1),
                       ip_src="10.0.0.2", ip_dst="192.168.1.1",
                       port_src=54321, port_dst=80, protocol="TCP", length=200),
            PacketInfo(timestamp=datetime(2026, 1, 15, 14, 30, 2),
                       ip_src="10.0.0.1", ip_dst="8.8.8.8",
                       port_src=5353, port_dst=53, protocol="UDP", length=80),
            PacketInfo(timestamp=datetime(2026, 1, 15, 14, 30, 3),
                       ip_src="192.168.1.1", ip_dst="10.0.0.1",
                       port_src=None, port_dst=None, protocol="ICMP", length=64),
        ]

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_filter_by_port_param(self, mock_parse, mock_find, client):
        """API should filter packets by port parameter."""
        mock_find.return_value = '/fake/path.pcap'
        mock_parse.return_value = (self._make_mock_packets(), None)

        response = client.get('/api/packets?capture_id=cap_test&port=443')
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['filter_summary']['filter_port'] == 443
        # Only the packet with port_dst=443 should match
        assert data['result']['pagination']['total'] == 1

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_filter_by_protocol_param(self, mock_parse, mock_find, client):
        """API should filter packets by protocol parameter."""
        mock_find.return_value = '/fake/path.pcap'
        mock_parse.return_value = (self._make_mock_packets(), None)

        response = client.get('/api/packets?capture_id=cap_test&protocol=UDP')
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['pagination']['total'] == 1

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_filter_by_direction_dst(self, mock_parse, mock_find, client):
        """API should filter by direction=dst for IP."""
        mock_find.return_value = '/fake/path.pcap'
        mock_parse.return_value = (self._make_mock_packets(), None)

        response = client.get('/api/packets?capture_id=cap_test&ip=192.168.1.1&direction=dst')
        data = response.get_json()
        assert data['success'] is True
        # Only packets where ip_dst=192.168.1.1
        assert data['result']['pagination']['total'] == 2

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_combined_port_protocol_direction(self, mock_parse, mock_find, client):
        """API should handle combined port + protocol + direction."""
        mock_find.return_value = '/fake/path.pcap'
        mock_parse.return_value = (self._make_mock_packets(), None)

        response = client.get('/api/packets?capture_id=cap_test&port=443&protocol=TCP&direction=dst')
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['pagination']['total'] == 1

    def test_invalid_port_rejected(self, client):
        """API should reject invalid port values."""
        response = client.get('/api/packets?capture_id=cap_test&port=99999')
        assert response.status_code == 400
        assert response.get_json()['error']['code'] == 'INVALID_PARAM'

    def test_invalid_port_string_rejected(self, client):
        """API should reject non-numeric port values."""
        response = client.get('/api/packets?capture_id=cap_test&port=abc')
        assert response.status_code == 400

    def test_invalid_protocol_rejected(self, client):
        """API should reject invalid protocol values."""
        response = client.get('/api/packets?capture_id=cap_test&protocol=INVALID')
        assert response.status_code == 400
        assert response.get_json()['error']['code'] == 'INVALID_PARAM'

    def test_invalid_direction_rejected(self, client):
        """API should reject invalid direction values."""
        response = client.get('/api/packets?capture_id=cap_test&direction=up')
        assert response.status_code == 400
        assert response.get_json()['error']['code'] == 'INVALID_PARAM'

    @patch('app.blueprints.api.packets._find_latest_pcap')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    @patch('app.blueprints.api.packets._validate_capture_id')
    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    def test_fallback_to_latest_capture(self, mock_find, mock_validate, mock_parse, mock_latest, client):
        """API should use latest capture when no capture_id provided."""
        mock_latest.return_value = ("cap_latest", Path("/fake/latest.pcap"))
        mock_validate.return_value = True
        mock_find.return_value = Path("/fake/latest.pcap")
        mock_parse.return_value = ([], None)

        response = client.get('/api/packets?ip=10.0.0.1')
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['capture_id'] == 'cap_latest'

    @patch('app.blueprints.api.packets._find_latest_pcap')
    def test_no_capture_available_message(self, mock_latest, client):
        """API should return explicit message when no captures exist (AC3)."""
        mock_latest.return_value = None

        response = client.get('/api/packets?ip=10.0.0.1')
        assert response.status_code == 404
        data = response.get_json()
        assert data['error']['code'] == 'NO_CAPTURE'
        assert 'Aucune capture disponible' in data['error']['message']

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    def test_ip_alias_param(self, mock_parse, mock_find, client):
        """API should accept 'ip' as alias for 'filter_ip'."""
        mock_find.return_value = '/fake/path.pcap'
        mock_parse.return_value = (self._make_mock_packets(), None)

        response = client.get('/api/packets?capture_id=cap_test&ip=10.0.0.1')
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['filter_summary']['filter_ip'] == '10.0.0.1'
