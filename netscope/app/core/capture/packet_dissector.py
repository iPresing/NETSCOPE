"""Packet dissector module for NETSCOPE (Story 4.5).

Deep packet inspection: layer-by-layer dissection, hex dumps, ASCII payloads.
Uses Scapy for packet parsing and field extraction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Check Scapy availability
SCAPY_AVAILABLE = False
try:
    from scapy.all import rdpcap, PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    pass


@dataclass
class LayerField:
    """A single field within a protocol layer.

    Attributes:
        name: Field name (e.g., 'src', 'dst', 'sport')
        value: Field value as string
    """
    name: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}


@dataclass
class LayerInfo:
    """Information about a single protocol layer.

    Attributes:
        name: Layer name (e.g., 'Ethernet', 'IP', 'TCP')
        fields: List of fields in this layer
    """
    name: str
    fields: list[LayerField] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "fields": [f.to_dict() for f in self.fields],
        }


@dataclass
class PacketDetail:
    """Full dissection of a single packet.

    Attributes:
        summary: One-line Scapy summary
        layers: List of protocol layers with fields
        hex_dump: Formatted hex dump string
        ascii_dump: Decoded ASCII payload
        raw_bytes_length: Total packet length in bytes
        packet_index: Index within the pcap file
        capture_id: Associated capture ID
    """
    summary: str = ""
    layers: list[LayerInfo] = field(default_factory=list)
    hex_dump: str = ""
    ascii_dump: str = ""
    raw_bytes_length: int = 0
    packet_index: int = 0
    capture_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "layers": [l.to_dict() for l in self.layers],
            "hex_dump": self.hex_dump,
            "ascii_dump": self.ascii_dump,
            "raw_bytes_length": self.raw_bytes_length,
            "packet_index": self.packet_index,
            "capture_id": self.capture_id,
        }


def dissect_packet(pcap_path: str | Path, packet_index: int, capture_id: str = "") -> PacketDetail:
    """Dissect a single packet from a pcap file.

    Args:
        pcap_path: Path to the pcap file
        packet_index: Zero-based index of the packet in the file
        capture_id: Associated capture session ID

    Returns:
        PacketDetail with full dissection

    Raises:
        RuntimeError: If Scapy is not available
        ValueError: If packet_index is out of range
        FileNotFoundError: If pcap file doesn't exist
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy requis pour la dissection des paquets")

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"Fichier pcap introuvable: {pcap_path}")

    if packet_index < 0:
        raise ValueError(f"Index paquet {packet_index} hors limites")

    # Iterate to target index without loading entire pcap into memory
    pkt = None
    total_count = 0
    try:
        with PcapReader(str(pcap_path)) as reader:
            for i, p in enumerate(reader):
                total_count = i + 1
                if i == packet_index:
                    pkt = p
                    # Continue counting for error message if needed
                    # But break early for performance
                    break
    except Exception as e:
        raise RuntimeError(f"Erreur lecture pcap: {e}") from e

    if pkt is None:
        # packet_index was beyond the file — get total count for error msg
        if total_count <= packet_index:
            raise ValueError(
                f"Index paquet {packet_index} hors limites "
                f"(0-{total_count - 1})"
            )

    # Build detail
    detail = PacketDetail(
        summary=pkt.summary(),
        layers=_extract_layers(pkt),
        hex_dump=_generate_hex_dump(bytes(pkt)),
        ascii_dump=_extract_ascii_payload(pkt),
        raw_bytes_length=len(pkt),
        packet_index=packet_index,
        capture_id=capture_id,
    )

    logger.debug(
        f"Dissected packet (index={packet_index}, "
        f"layers={len(detail.layers)}, bytes={detail.raw_bytes_length})"
    )

    return detail


def _extract_layers(pkt) -> list[LayerInfo]:
    """Extract all protocol layers from a Scapy packet.

    Traverses the packet payload chain and extracts field names/values
    for each layer.

    Args:
        pkt: Scapy packet object

    Returns:
        List of LayerInfo objects
    """
    layers = []
    current = pkt

    while current:
        layer_name = current.__class__.__name__
        fields = []

        try:
            for field_desc in current.fields_desc:
                fname = field_desc.name
                try:
                    fval = getattr(current, fname, None)
                    if fval is not None:
                        # Format bytes values
                        if isinstance(fval, bytes):
                            if len(fval) <= 20:
                                fval_str = fval.hex(':') if fval else ''
                            else:
                                fval_str = fval[:20].hex(':') + f'... ({len(fval)} bytes)'
                        else:
                            fval_str = str(fval)
                        fields.append(LayerField(name=fname, value=fval_str))
                except Exception:
                    fields.append(LayerField(name=fname, value="<error>"))
        except AttributeError:
            # Layer has no fields_desc (e.g., Raw, Padding)
            try:
                load = getattr(current, 'load', None)
                if load:
                    preview = load[:50]
                    fields.append(LayerField(
                        name="load",
                        value=f"{len(load)} bytes"
                    ))
            except Exception:
                pass

        layers.append(LayerInfo(name=layer_name, fields=fields))

        # Move to next layer
        try:
            current = current.payload
            if not current or current.__class__.__name__ == 'NoPayload':
                break
        except AttributeError:
            break

    return layers


def _generate_hex_dump(raw_bytes: bytes) -> str:
    """Generate a Wireshark-style hex dump.

    Format: offset  hex bytes (16 per line)  |ASCII|

    Args:
        raw_bytes: Raw packet bytes

    Returns:
        Formatted hex dump string
    """
    lines = []
    for offset in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[offset:offset + 16]

        # Hex portion
        hex_parts = []
        for i, byte in enumerate(chunk):
            hex_parts.append(f'{byte:02x}')
            if i == 7:
                hex_parts.append(' ')
        hex_str = ' '.join(hex_parts).ljust(49)

        # ASCII portion
        ascii_str = ''
        for byte in chunk:
            if 32 <= byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str += '.'

        lines.append(f'{offset:08x}  {hex_str}  |{ascii_str}|')

    return '\n'.join(lines)


def _extract_ascii_payload(pkt) -> str:
    """Extract and decode the ASCII-readable payload from a packet.

    Traverses to the Raw layer and decodes its content.

    Args:
        pkt: Scapy packet object

    Returns:
        Decoded ASCII string, or empty string if no payload
    """
    try:
        from scapy.all import Raw
        if Raw in pkt:
            raw_data = bytes(pkt[Raw].load)
            # Decode with replacement for non-printable chars
            decoded = ''
            for byte in raw_data:
                if 32 <= byte <= 126 or byte in (10, 13, 9):  # printable + \n, \r, \t
                    decoded += chr(byte)
                else:
                    decoded += '.'
            return decoded
    except Exception as e:
        logger.debug(f"Failed to extract ASCII payload (error={e})")
    return ''
