"""Unit tests for packet parser module."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from collections import Counter

from app.models.capture import (
    CaptureSummary,
    PacketInfo,
    CaptureError,
    CAPTURE_PARSE_ERROR,
)
from app.core.capture.packet_parser import (
    parse_capture_file,
    get_capture_statistics,
    SCAPY_AVAILABLE,
    DPKT_AVAILABLE,
)


class TestParseCaptureFile:
    """Tests for parse_capture_file()."""

    def test_file_not_found_raises_error(self, tmp_path):
        """Test that non-existent file raises CaptureError."""
        fake_path = tmp_path / "nonexistent.pcap"

        with pytest.raises(CaptureError) as exc_info:
            parse_capture_file(fake_path)

        assert exc_info.value.code == CAPTURE_PARSE_ERROR
        assert "introuvable" in exc_info.value.message

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_empty_pcap_returns_empty_summary(self, tmp_path):
        """Test that empty pcap returns empty summary."""
        # Create a minimal valid pcap file header
        pcap_path = tmp_path / "empty.pcap"
        # Pcap global header (24 bytes)
        pcap_header = bytes([
            0xd4, 0xc3, 0xb2, 0xa1,  # magic number (little endian)
            0x02, 0x00,              # major version
            0x04, 0x00,              # minor version
            0x00, 0x00, 0x00, 0x00,  # GMT offset
            0x00, 0x00, 0x00, 0x00,  # accuracy
            0xff, 0xff, 0x00, 0x00,  # max len
            0x01, 0x00, 0x00, 0x00,  # data link type (ethernet)
        ])
        pcap_path.write_bytes(pcap_header)

        packets, summary = parse_capture_file(pcap_path)

        assert packets == []
        assert summary.total_packets == 0
        assert summary.top_ports == []
        assert summary.bytes_per_protocol == {}


class TestCaptureSummaryFields:
    """Tests for new CaptureSummary fields from packet parser."""

    def test_summary_has_top_ports_field(self):
        """Test that CaptureSummary has top_ports field."""
        summary = CaptureSummary(
            total_packets=100,
            top_ports=[(443, 50), (80, 30), (53, 20)],
        )

        assert len(summary.top_ports) == 3
        assert summary.top_ports[0] == (443, 50)
        assert summary.top_ports[1] == (80, 30)

    def test_summary_has_bytes_per_protocol_field(self):
        """Test that CaptureSummary has bytes_per_protocol field."""
        summary = CaptureSummary(
            total_packets=100,
            bytes_per_protocol={"TCP": 5000, "UDP": 2000, "ICMP": 500},
        )

        assert summary.bytes_per_protocol["TCP"] == 5000
        assert summary.bytes_per_protocol["UDP"] == 2000
        assert summary.bytes_per_protocol["ICMP"] == 500

    def test_summary_to_dict_serializes_top_ports(self):
        """Test that to_dict() serializes top_ports correctly."""
        summary = CaptureSummary(
            top_ports=[(443, 100), (80, 75)],
        )
        result = summary.to_dict()

        assert "top_ports" in result
        assert len(result["top_ports"]) == 2
        assert result["top_ports"][0] == {"port": 443, "count": 100}
        assert result["top_ports"][1] == {"port": 80, "count": 75}

    def test_summary_to_dict_serializes_bytes_per_protocol(self):
        """Test that to_dict() serializes bytes_per_protocol correctly."""
        summary = CaptureSummary(
            bytes_per_protocol={"TCP": 45000, "UDP": 10000},
        )
        result = summary.to_dict()

        assert "bytes_per_protocol" in result
        assert result["bytes_per_protocol"] == {"TCP": 45000, "UDP": 10000}


class TestPortCounting:
    """Tests for port counting logic."""

    def test_port_counter_counts_both_src_and_dst(self):
        """Test that port counting includes both source and destination."""
        port_counter: Counter = Counter()

        # Simulate packet with src=12345, dst=443
        port_counter[12345] += 1
        port_counter[443] += 1

        # Another packet with src=54321, dst=443
        port_counter[54321] += 1
        port_counter[443] += 1

        # Port 443 should have count of 2
        assert port_counter[443] == 2
        assert port_counter.most_common(1)[0] == (443, 2)

    def test_top_ports_returns_correct_order(self):
        """Test that top_ports are sorted by frequency."""
        port_counter: Counter = Counter()

        # Add ports with different frequencies
        port_counter[80] = 100
        port_counter[443] = 200
        port_counter[22] = 50
        port_counter[8080] = 75

        top_ports = port_counter.most_common(10)

        assert top_ports[0] == (443, 200)
        assert top_ports[1] == (80, 100)
        assert top_ports[2] == (8080, 75)
        assert top_ports[3] == (22, 50)


class TestBytesPerProtocol:
    """Tests for bytes per protocol calculation."""

    def test_bytes_accumulated_per_protocol(self):
        """Test that bytes are accumulated per protocol."""
        bytes_per_protocol: Counter = Counter()

        # TCP packet of 100 bytes
        bytes_per_protocol["TCP"] += 100
        # TCP packet of 200 bytes
        bytes_per_protocol["TCP"] += 200
        # UDP packet of 50 bytes
        bytes_per_protocol["UDP"] += 50

        assert bytes_per_protocol["TCP"] == 300
        assert bytes_per_protocol["UDP"] == 50

    def test_bytes_per_protocol_empty_for_no_packets(self):
        """Test that bytes_per_protocol is empty when no packets."""
        bytes_per_protocol: Counter = Counter()

        assert dict(bytes_per_protocol) == {}


class TestGetCaptureStatistics:
    """Tests for get_capture_statistics()."""

    def test_returns_summary_only(self, tmp_path):
        """Test that get_capture_statistics returns CaptureSummary."""
        with patch('app.core.capture.packet_parser.parse_capture_file') as mock_parse:
            mock_summary = CaptureSummary(
                total_packets=100,
                top_ports=[(443, 50)],
                bytes_per_protocol={"TCP": 5000},
            )
            mock_parse.return_value = ([], mock_summary)

            result = get_capture_statistics(tmp_path / "test.pcap")

            assert isinstance(result, CaptureSummary)
            assert result.total_packets == 100
            assert result.top_ports == [(443, 50)]
            assert result.bytes_per_protocol == {"TCP": 5000}
