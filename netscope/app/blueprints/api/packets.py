"""Packet viewer API endpoints for NETSCOPE (Story 4.4 / 4b.7).

Provides REST API for browsing and inspecting captured packets.
Re-parses pcap files on disk to provide filtered, paginated packet data.
Supports filtering by IP, port, protocol, and direction (Story 4b.7).
"""

import logging
import re
from pathlib import Path
from flask import jsonify, request

from . import api_bp
from app.core.detection.anomaly_store import get_anomaly_store
from app.core.capture.packet_parser import (
    parse_capture_file,
    filter_packets,
    find_pcap_by_capture_id,
)
from app.core.capture.packet_dissector import dissect_packet

logger = logging.getLogger(__name__)

# Validation pattern for capture_id (alphanumeric, underscore, hyphen only)
_CAPTURE_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')

# Valid protocols and directions for parameter validation (rule #13)
_VALID_PROTOCOLS = {'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'HTTP', 'HTTPS', 'TLS'}
_VALID_DIRECTIONS = {'src', 'dst', 'both'}

# Simple pcap parse cache: {path_str: (mtime, packets_list)}
_pcap_cache: dict[str, tuple[float, list]] = {}
_PCAP_CACHE_MAX = 4


def _get_parsed_packets(pcap_path: Path):
    """Parse pcap file with mtime-based caching.

    Avoids re-parsing the same file on every page request.

    Args:
        pcap_path: Path to pcap file

    Returns:
        Tuple of (packets_list, summary)
    """
    path_str = str(pcap_path)
    mtime = pcap_path.stat().st_mtime

    if path_str in _pcap_cache:
        cached_mtime, cached_packets = _pcap_cache[path_str]
        if cached_mtime == mtime:
            return cached_packets, None

    packets, summary = parse_capture_file(pcap_path)

    # Evict oldest if cache full
    if len(_pcap_cache) >= _PCAP_CACHE_MAX:
        oldest_key = next(iter(_pcap_cache))
        del _pcap_cache[oldest_key]

    _pcap_cache[path_str] = (mtime, packets)
    return packets, summary


def _find_latest_pcap() -> tuple[str, Path] | None:
    """Find the most recent pcap file in data/captures/.

    Returns:
        Tuple of (capture_id, pcap_path) or None if no captures exist
    """
    captures_dir = Path("data/captures")
    if not captures_dir.exists():
        return None

    pcap_files = sorted(captures_dir.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not pcap_files:
        return None

    latest = pcap_files[0]
    capture_id = latest.stem
    return capture_id, latest


def _filter_by_port_protocol_direction(packets, port=None, protocol=None, direction=None, filter_ip=None):
    """Apply additional server-side filtering for port, protocol, and direction.

    Args:
        packets: List of PacketInfo objects
        port: Port number to filter by (optional)
        protocol: Protocol name to filter by (optional)
        direction: 'src', 'dst', or 'both' - applies to both IP and port filtering (optional)
        filter_ip: IP address for direction-aware filtering (optional)

    Returns:
        Filtered list of PacketInfo objects
    """
    filtered = packets

    if protocol:
        protocol_upper = protocol.upper()
        filtered = [p for p in filtered if p.protocol == protocol_upper]

    if port is not None:
        if direction == 'src':
            filtered = [p for p in filtered if p.port_src == port]
        elif direction == 'dst':
            filtered = [p for p in filtered if p.port_dst == port]
        else:  # 'both' or unspecified
            filtered = [p for p in filtered if p.port_src == port or p.port_dst == port]

    if filter_ip and direction and direction != 'both':
        if direction == 'src':
            filtered = [p for p in filtered if p.ip_src == filter_ip]
        elif direction == 'dst':
            filtered = [p for p in filtered if p.ip_dst == filter_ip]

    return filtered


def _validate_capture_id(capture_id: str) -> bool:
    """Validate capture_id against path traversal.

    Args:
        capture_id: Capture ID string

    Returns:
        True if valid
    """
    return bool(_CAPTURE_ID_RE.match(capture_id))


@api_bp.route('/packets', methods=['GET'])
def get_packets():
    """Get packets from a capture, optionally filtered.

    Query Parameters:
        capture_id: str - Capture session ID (auto-detects latest if absent)
        anomaly_id: str - Anomaly ID to auto-resolve capture and filter (optional)
        ip: str - Filter by IP address (optional, alias: filter_ip)
        filter_domain: str - Filter by domain name (optional)
        port: int - Filter by port number 1-65535 (optional)
        protocol: str - Filter by protocol TCP/UDP/ICMP/etc. (optional)
        direction: str - Filter direction: src/dst/both (optional)
        page: int - Page number (default: 1)
        per_page: int - Results per page (default: 50, max: 200)

    Returns:
        JSON response with paginated packet list
    """
    capture_id = request.args.get('capture_id')
    anomaly_id = request.args.get('anomaly_id')
    filter_ip = request.args.get('filter_ip') or request.args.get('ip')
    filter_domain = request.args.get('filter_domain')
    port_str = request.args.get('port')
    protocol = request.args.get('protocol')
    direction = request.args.get('direction')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    # Validate port (rule #13)
    filter_port = None
    if port_str:
        try:
            filter_port = int(port_str)
            if filter_port < 1 or filter_port > 65535:
                return jsonify({
                    "success": False,
                    "error": {"code": "INVALID_PARAM", "message": "Port invalide (1-65535)"},
                }), 400
        except ValueError:
            return jsonify({
                "success": False,
                "error": {"code": "INVALID_PARAM", "message": "Port doit être un nombre entier"},
            }), 400

    # Validate protocol (rule #13)
    if protocol and protocol.upper() not in _VALID_PROTOCOLS:
        return jsonify({
            "success": False,
            "error": {"code": "INVALID_PARAM", "message": f"Protocole invalide: {protocol}"},
        }), 400

    # Validate direction (rule #13)
    if direction and direction not in _VALID_DIRECTIONS:
        return jsonify({
            "success": False,
            "error": {"code": "INVALID_PARAM", "message": f"Direction invalide: {direction} (src/dst/both)"},
        }), 400

    # Clamp per_page
    per_page = min(max(per_page, 1), 200)
    page = max(page, 1)

    anomaly_context = None

    # Resolve from anomaly if provided
    if anomaly_id:
        store = get_anomaly_store()
        anomaly = store.get_anomaly(anomaly_id)
        if anomaly is None:
            return jsonify({
                "success": False,
                "error": {"code": "ANOMALY_NOT_FOUND", "message": f"Anomalie '{anomaly_id}' introuvable"},
            }), 404

        capture_id = anomaly.capture_id
        anomaly_context = {
            "anomaly_id": anomaly.id,
            "matched_value": anomaly.match.matched_value,
            "match_type": anomaly.match.match_type.value,
            "criticality": anomaly.criticality_level.value,
            "score": anomaly.score,
        }

        # Auto-set filter from anomaly
        if anomaly.match.match_type.value == 'ip' and not filter_ip:
            filter_ip = anomaly.match.matched_value
        elif anomaly.match.match_type.value == 'domain' and not filter_domain:
            filter_domain = anomaly.match.matched_value
        elif anomaly.match.match_type.value == 'term':
            # For terms, try to filter by the IP from packet_info
            if anomaly.packet_info and anomaly.packet_info.get('ip_dst') and not filter_ip:
                filter_ip = anomaly.packet_info['ip_dst']

    # Fallback to latest capture if no capture_id (Story 4b.7 AC3)
    if not capture_id:
        latest = _find_latest_pcap()
        if latest is None:
            return jsonify({
                "success": False,
                "error": {"code": "NO_CAPTURE", "message": "Aucune capture disponible. Lancez une capture depuis le Dashboard."},
            }), 404
        capture_id, _ = latest
        logger.info(f"No capture_id specified, using latest: {capture_id}")

    # Validate capture_id against path traversal (M1)
    if not _validate_capture_id(capture_id):
        return jsonify({
            "success": False,
            "error": {"code": "INVALID_PARAM", "message": "capture_id invalide"},
        }), 400

    # Find pcap file
    pcap_path = find_pcap_by_capture_id(capture_id)
    if pcap_path is None:
        return jsonify({
            "success": False,
            "error": {"code": "CAPTURE_NOT_FOUND", "message": f"Fichier capture '{capture_id}' introuvable"},
        }), 404

    # Parse pcap (with caching to avoid re-parse on every page)
    try:
        packets, _ = _get_parsed_packets(pcap_path)
    except Exception as e:
        logger.error(f"Failed to parse pcap (capture_id={capture_id}, error={e})")
        return jsonify({
            "success": False,
            "error": {"code": "PARSE_ERROR", "message": "Erreur lors du parsing de la capture"},
        }), 500

    # Build index mapping before filtering (O(n) instead of O(n²))
    packet_index_map = {id(p): i for i, p in enumerate(packets)}

    # Filter by IP/domain (existing), then by port/protocol/direction (Story 4b.7)
    filtered = filter_packets(packets, filter_ip=filter_ip, filter_domain=filter_domain)
    if filter_port is not None or protocol or direction:
        filtered = _filter_by_port_protocol_direction(
            filtered, port=filter_port, protocol=protocol,
            direction=direction, filter_ip=filter_ip,
        )

    # Paginate
    total = len(filtered)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    page_packets = filtered[start:end]

    # Build response with global index for detail lookup
    packets_data = []
    for i, pkt in enumerate(page_packets):
        pkt_dict = pkt.to_dict()
        # O(1) lookup via id() instead of O(n) packets.index()
        pkt_dict["index"] = packet_index_map.get(id(pkt), start + i)
        packets_data.append(pkt_dict)

    result = {
        "packets": packets_data,
        "capture_id": capture_id,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
        },
        "filter_summary": {
            "filter_ip": filter_ip,
            "filter_domain": filter_domain,
            "filter_port": filter_port,
            "filter_protocol": protocol,
            "filter_direction": direction,
            "total_unfiltered": len(packets),
            "total_filtered": total,
        },
    }

    if anomaly_context:
        result["anomaly_context"] = anomaly_context

    logger.info(
        f"Packets retrieved (capture_id={capture_id}, "
        f"filtered={total}/{len(packets)}, page={page}/{total_pages})"
    )

    return jsonify({"success": True, "result": result})


@api_bp.route('/packets/<capture_id>/<int:packet_index>', methods=['GET'])
def get_packet_detail(capture_id: str, packet_index: int):
    """Get detailed dissection of a single packet (Story 4.5).

    Args:
        capture_id: Capture session ID
        packet_index: Zero-based index of the packet

    Returns:
        JSON response with PacketDetail
    """
    # Validate capture_id against path traversal (M1)
    if not _validate_capture_id(capture_id):
        return jsonify({
            "success": False,
            "error": {"code": "INVALID_PARAM", "message": "capture_id invalide"},
        }), 400

    pcap_path = find_pcap_by_capture_id(capture_id)
    if pcap_path is None:
        return jsonify({
            "success": False,
            "error": {"code": "CAPTURE_NOT_FOUND", "message": f"Fichier capture '{capture_id}' introuvable"},
        }), 404

    try:
        detail = dissect_packet(pcap_path, packet_index, capture_id=capture_id)
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": {"code": "INDEX_OUT_OF_RANGE", "message": str(e)},
        }), 400
    except RuntimeError as e:
        return jsonify({
            "success": False,
            "error": {"code": "SCAPY_UNAVAILABLE", "message": str(e)},
        }), 503
    except Exception as e:
        logger.error(f"Packet dissection failed (capture_id={capture_id}, index={packet_index}, error={e})")
        return jsonify({
            "success": False,
            "error": {"code": "DISSECTION_ERROR", "message": f"Erreur dissection: {str(e)}"},
        }), 500

    logger.info(f"Packet dissected (capture_id={capture_id}, index={packet_index})")

    return jsonify({"success": True, "result": detail.to_dict()})
