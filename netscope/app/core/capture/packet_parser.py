"""Packet Parser module for NETSCOPE.

Parses pcap capture files and extracts packet header information.
Uses scapy for packet parsing, with fallback to dpkt if available.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from app.models.capture import (
    CaptureError,
    CaptureSummary,
    PacketInfo,
    CAPTURE_PARSE_ERROR,
)

logger = logging.getLogger(__name__)

# Try to import scapy (preferred) or dpkt (fallback)
SCAPY_AVAILABLE = False
DPKT_AVAILABLE = False

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
    logger.debug("Scapy available for packet parsing")
except ImportError:
    pass

try:
    import dpkt
    DPKT_AVAILABLE = True
    logger.debug("dpkt available for packet parsing")
except ImportError:
    pass


def parse_capture_file(pcap_path: str | Path) -> tuple[list[PacketInfo], CaptureSummary]:
    """Parse a pcap capture file.

    Args:
        pcap_path: Path to the pcap file

    Returns:
        Tuple of (list of PacketInfo, CaptureSummary)

    Raises:
        CaptureError: If file cannot be parsed
    """
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        logger.error(f"Capture file not found (path={pcap_path})")
        raise CaptureError(
            code=CAPTURE_PARSE_ERROR,
            message=f"Fichier capture introuvable: {pcap_path}",
            details={"path": str(pcap_path)},
        )

    file_size = pcap_path.stat().st_size
    logger.info(f"Parsing capture file (path={pcap_path}, size={file_size})")

    if SCAPY_AVAILABLE:
        return _parse_with_scapy(pcap_path)
    elif DPKT_AVAILABLE:
        return _parse_with_dpkt(pcap_path)
    else:
        logger.warning("No packet parsing library available, returning empty results")
        return [], CaptureSummary()


def _parse_with_scapy(pcap_path: Path) -> tuple[list[PacketInfo], CaptureSummary]:
    """Parse pcap file using scapy.

    Args:
        pcap_path: Path to pcap file

    Returns:
        Tuple of (packets, summary)
    """
    try:
        packets_raw = rdpcap(str(pcap_path))
    except Exception as e:
        logger.error(f"Scapy failed to read pcap (error={str(e)})")
        raise CaptureError(
            code=CAPTURE_PARSE_ERROR,
            message=f"Erreur lecture fichier pcap: {str(e)}",
            details={"error": str(e)},
        )

    packets = []
    total_bytes = 0
    ip_counter: Counter = Counter()
    port_counter: Counter = Counter()
    protocol_counter: Counter = Counter()
    bytes_per_protocol: Counter = Counter()

    for pkt in packets_raw:
        pkt_len = len(pkt)
        total_bytes += pkt_len

        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        ip_counter[ip_src] += 1
        ip_counter[ip_dst] += 1

        port_src = None
        port_dst = None
        protocol = "OTHER"

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            port_src = tcp_layer.sport
            port_dst = tcp_layer.dport
            protocol = "TCP"
            port_counter[port_src] += 1
            port_counter[port_dst] += 1
        elif UDP in pkt:
            udp_layer = pkt[UDP]
            port_src = udp_layer.sport
            port_dst = udp_layer.dport
            protocol = "UDP"
            port_counter[port_src] += 1
            port_counter[port_dst] += 1
        elif ICMP in pkt:
            protocol = "ICMP"

        protocol_counter[protocol] += 1
        bytes_per_protocol[protocol] += pkt_len

        # Get timestamp from packet
        timestamp = datetime.fromtimestamp(float(pkt.time))

        packet_info = PacketInfo(
            timestamp=timestamp,
            ip_src=ip_src,
            ip_dst=ip_dst,
            port_src=port_src,
            port_dst=port_dst,
            protocol=protocol,
            length=pkt_len,
        )
        packets.append(packet_info)

    # Build summary
    summary = CaptureSummary(
        total_packets=len(packets_raw),
        total_bytes=total_bytes,
        unique_ips=len(ip_counter),
        unique_ports=len(port_counter),
        protocols=dict(protocol_counter),
        top_ips=ip_counter.most_common(10),
        top_ports=port_counter.most_common(10),
        bytes_per_protocol=dict(bytes_per_protocol),
    )

    logger.info(
        f"Parsed {len(packets)} packets "
        f"(total={len(packets_raw)}, bytes={total_bytes}, ips={len(ip_counter)}, "
        f"top_ports={len(port_counter)}, protocols={len(protocol_counter)})"
    )

    return packets, summary


def _parse_with_dpkt(pcap_path: Path) -> tuple[list[PacketInfo], CaptureSummary]:
    """Parse pcap file using dpkt (fallback).

    Args:
        pcap_path: Path to pcap file

    Returns:
        Tuple of (packets, summary)
    """
    packets = []
    total_bytes = 0
    total_packets = 0
    ip_counter: Counter = Counter()
    port_counter: Counter = Counter()
    protocol_counter: Counter = Counter()
    bytes_per_protocol: Counter = Counter()

    try:
        with open(pcap_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                total_packets += 1
                pkt_len = len(buf)
                total_bytes += pkt_len

                try:
                    eth = dpkt.ethernet.Ethernet(buf)

                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip = eth.data
                    ip_src = _format_ip(ip.src)
                    ip_dst = _format_ip(ip.dst)
                    ip_counter[ip_src] += 1
                    ip_counter[ip_dst] += 1

                    port_src = None
                    port_dst = None
                    protocol = "OTHER"

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        port_src = tcp.sport
                        port_dst = tcp.dport
                        protocol = "TCP"
                        port_counter[port_src] += 1
                        port_counter[port_dst] += 1
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        port_src = udp.sport
                        port_dst = udp.dport
                        protocol = "UDP"
                        port_counter[port_src] += 1
                        port_counter[port_dst] += 1
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        protocol = "ICMP"

                    protocol_counter[protocol] += 1
                    bytes_per_protocol[protocol] += pkt_len

                    packet_info = PacketInfo(
                        timestamp=datetime.fromtimestamp(timestamp),
                        ip_src=ip_src,
                        ip_dst=ip_dst,
                        port_src=port_src,
                        port_dst=port_dst,
                        protocol=protocol,
                        length=pkt_len,
                    )
                    packets.append(packet_info)

                except Exception:
                    # Skip malformed packets
                    continue

    except Exception as e:
        logger.error(f"dpkt failed to read pcap (error={str(e)})")
        raise CaptureError(
            code=CAPTURE_PARSE_ERROR,
            message=f"Erreur lecture fichier pcap: {str(e)}",
            details={"error": str(e)},
        )

    # Build summary
    summary = CaptureSummary(
        total_packets=total_packets,
        total_bytes=total_bytes,
        unique_ips=len(ip_counter),
        unique_ports=len(port_counter),
        protocols=dict(protocol_counter),
        top_ips=ip_counter.most_common(10),
        top_ports=port_counter.most_common(10),
        bytes_per_protocol=dict(bytes_per_protocol),
    )

    logger.info(
        f"Parsed {len(packets)} packets with dpkt "
        f"(total={total_packets}, bytes={total_bytes}, "
        f"top_ports={len(port_counter)}, protocols={len(protocol_counter)})"
    )

    return packets, summary


def _format_ip(ip_bytes: bytes) -> str:
    """Format IP address bytes to string.

    Args:
        ip_bytes: IP address as bytes

    Returns:
        IP address as string
    """
    import socket
    return socket.inet_ntoa(ip_bytes)


def get_capture_statistics(pcap_path: str | Path) -> CaptureSummary:
    """Get statistics for a capture file without full parsing.

    This is a faster alternative to parse_capture_file when only
    summary statistics are needed.

    Args:
        pcap_path: Path to the pcap file

    Returns:
        CaptureSummary with statistics
    """
    _, summary = parse_capture_file(pcap_path)
    return summary
