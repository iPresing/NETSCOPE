"""Unit tests for packet dissector module (Story 4.5)."""

import pytest
from pathlib import Path

from app.core.capture.packet_dissector import (
    dissect_packet,
    _generate_hex_dump,
    _extract_ascii_payload,
    _extract_layers,
    PacketDetail,
    LayerInfo,
    LayerField,
    SCAPY_AVAILABLE,
)


class TestPacketDetailDataclass:
    """Tests for PacketDetail dataclass."""

    def test_to_dict_returns_all_fields(self):
        """PacketDetail.to_dict() should return all expected fields."""
        detail = PacketDetail(
            summary="TCP 10.0.0.1:12345 > 10.0.0.2:80",
            layers=[LayerInfo(name="IP", fields=[LayerField(name="src", value="10.0.0.1")])],
            hex_dump="00000000  48 65 6c 6c 6f",
            ascii_dump="Hello",
            raw_bytes_length=100,
            packet_index=5,
            capture_id="cap_test",
        )
        d = detail.to_dict()

        assert d["summary"] == "TCP 10.0.0.1:12345 > 10.0.0.2:80"
        assert len(d["layers"]) == 1
        assert d["layers"][0]["name"] == "IP"
        assert d["layers"][0]["fields"][0]["name"] == "src"
        assert d["hex_dump"] == "00000000  48 65 6c 6c 6f"
        assert d["ascii_dump"] == "Hello"
        assert d["raw_bytes_length"] == 100
        assert d["packet_index"] == 5
        assert d["capture_id"] == "cap_test"


class TestGenerateHexDump:
    """Tests for _generate_hex_dump()."""

    def test_empty_bytes(self):
        """Empty bytes should produce empty string."""
        result = _generate_hex_dump(b"")
        assert result == ""

    def test_short_bytes(self):
        """Short byte sequence should produce single line."""
        result = _generate_hex_dump(b"Hello")
        assert "00000000" in result
        assert "48 65 6c 6c 6f" in result
        assert "|Hello|" in result

    def test_16_bytes_single_line(self):
        """16 bytes should produce exactly one line."""
        data = bytes(range(16))
        result = _generate_hex_dump(data)
        lines = result.strip().split('\n')
        assert len(lines) == 1

    def test_17_bytes_two_lines(self):
        """17 bytes should produce two lines."""
        data = bytes(range(17))
        result = _generate_hex_dump(data)
        lines = result.strip().split('\n')
        assert len(lines) == 2

    def test_non_printable_chars_show_as_dot(self):
        """Non-printable characters should show as dots in ASCII column."""
        data = bytes([0x00, 0x01, 0x02, 0x41])  # NUL, SOH, STX, 'A'
        result = _generate_hex_dump(data)
        assert "|...A|" in result

    def test_offset_format(self):
        """Offset should be 8-digit hex."""
        data = bytes(range(32))
        result = _generate_hex_dump(data)
        assert "00000000" in result
        assert "00000010" in result


class TestExtractAsciiPayload:
    """Tests for _extract_ascii_payload()."""

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_extract_from_raw_layer(self):
        """Should extract payload from Raw layer."""
        from scapy.all import IP, TCP, Raw
        pkt = IP() / TCP() / Raw(load=b"GET / HTTP/1.1\r\n")
        result = _extract_ascii_payload(pkt)
        assert "GET / HTTP/1.1" in result

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_no_raw_layer_returns_empty(self):
        """Should return empty string when no Raw layer."""
        from scapy.all import IP, TCP
        pkt = IP() / TCP()
        result = _extract_ascii_payload(pkt)
        assert result == ""

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_non_printable_replaced_with_dot(self):
        """Non-printable bytes should be replaced with dots."""
        from scapy.all import IP, TCP, Raw
        pkt = IP() / TCP() / Raw(load=bytes([0x41, 0x00, 0x42, 0x01, 0x43]))
        result = _extract_ascii_payload(pkt)
        assert result == "A.B.C"


class TestDissectPacket:
    """Tests for dissect_packet()."""

    def test_file_not_found(self):
        """Should raise FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            dissect_packet("/nonexistent/path.pcap", 0)

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_index_out_of_range(self, tmp_path):
        """Should raise ValueError for out-of-range index."""
        from scapy.all import IP, TCP, wrpcap
        pcap_path = tmp_path / "test.pcap"
        wrpcap(str(pcap_path), [IP() / TCP()])

        with pytest.raises(ValueError, match="hors limites"):
            dissect_packet(pcap_path, 999)

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_dissect_tcp_packet(self, tmp_path):
        """Should dissect a basic TCP packet."""
        from scapy.all import Ether, IP, TCP, wrpcap
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80)
        pcap_path = tmp_path / "test.pcap"
        wrpcap(str(pcap_path), [pkt])

        detail = dissect_packet(pcap_path, 0, capture_id="cap_test")

        assert isinstance(detail, PacketDetail)
        assert detail.packet_index == 0
        assert detail.capture_id == "cap_test"
        assert detail.raw_bytes_length > 0
        assert len(detail.layers) >= 3  # Ether, IP, TCP
        assert detail.hex_dump != ""

        # Check layer names
        layer_names = [l.name for l in detail.layers]
        assert "Ether" in layer_names or "Ethernet" in layer_names
        assert "IP" in layer_names
        assert "TCP" in layer_names

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_dissect_with_payload(self, tmp_path):
        """Should extract ASCII payload."""
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
        pkt = Ether() / IP() / TCP() / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n")
        pcap_path = tmp_path / "test.pcap"
        wrpcap(str(pcap_path), [pkt])

        detail = dissect_packet(pcap_path, 0)
        assert "GET / HTTP/1.1" in detail.ascii_dump

    def test_scapy_not_available_raises_runtime_error(self):
        """Should raise RuntimeError when Scapy unavailable."""
        from unittest.mock import patch
        with patch('app.core.capture.packet_dissector.SCAPY_AVAILABLE', False):
            with pytest.raises(RuntimeError, match="Scapy requis"):
                dissect_packet("/some/path.pcap", 0)


class TestExtractLayers:
    """Tests for _extract_layers()."""

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_extracts_ip_fields(self):
        """Should extract IP layer fields."""
        from scapy.all import IP, TCP
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
        layers = _extract_layers(pkt)

        ip_layer = next((l for l in layers if l.name == "IP"), None)
        assert ip_layer is not None

        field_names = [f.name for f in ip_layer.fields]
        assert "src" in field_names
        assert "dst" in field_names

    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_extracts_multiple_layers(self):
        """Should extract all layers in order."""
        from scapy.all import Ether, IP, TCP
        pkt = Ether() / IP() / TCP()
        layers = _extract_layers(pkt)
        layer_names = [l.name for l in layers]

        assert layer_names[0] in ("Ether", "Ethernet")
        assert "IP" in layer_names
        assert "TCP" in layer_names
