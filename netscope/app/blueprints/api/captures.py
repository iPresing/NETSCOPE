"""Capture API endpoints for NETSCOPE.

Provides REST API for network capture operations.
"""

import logging
from flask import jsonify, request

from . import api_bp
from app.models.capture import (
    CaptureError,
    CaptureStatus,
    validate_duration,
    DEFAULT_CAPTURE_DURATION,
    MIN_CAPTURE_DURATION,
    MAX_CAPTURE_DURATION,
)
from app.core.capture import (
    get_tcpdump_manager,
    parse_capture_file,
    validate_filter,
    DEFAULT_BPF_FILTER,
)
from app.core.analysis.four_essentials import get_four_essentials_analyzer
from app.core.detection.anomaly_store import get_anomaly_store

logger = logging.getLogger(__name__)


@api_bp.route('/captures/start', methods=['POST'])
def start_capture():
    """Start a network capture.

    Request Body (JSON):
        duration: int - Capture duration in seconds (30-600, default: 120)
        interface: str - Network interface (default: "auto")
        bpf_filter: str - BPF filter (default: "not port 22")

    Returns:
        JSON response with capture session details

    Example:
        POST /api/captures/start
        {"duration": 120, "interface": "eth0", "bpf_filter": "not port 22"}
    """
    logger.info("POST /api/captures/start called")

    # Parse request body
    data = request.get_json() or {}

    duration = data.get("duration", DEFAULT_CAPTURE_DURATION)
    interface = data.get("interface", "auto")
    bpf_filter = data.get("bpf_filter", DEFAULT_BPF_FILTER)

    try:
        # Validate parameters
        duration = validate_duration(duration)
        bpf_filter = validate_filter(bpf_filter)

        # Start capture
        manager = get_tcpdump_manager()
        session = manager.start_capture(
            duration=duration,
            interface=interface,
            bpf_filter=bpf_filter,
        )

        logger.info(
            f"Capture started "
            f"(capture_id={session.id}, interface={interface}, duration={duration})"
        )

        return jsonify({
            "success": True,
            "session": session.to_dict(),
        }), 200

    except CaptureError as e:
        logger.warning(f"Capture start failed (code={e.code}, message={e.message})")
        return jsonify({
            "success": False,
            "error": e.to_dict(),
        }), 400

    except Exception as e:
        logger.error(f"Unexpected error starting capture (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "CAPTURE_FAILED",
                "message": f"Erreur inattendue: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/captures/stop', methods=['POST'])
def stop_capture():
    """Stop the current capture.

    Returns:
        JSON response with stopped session details
    """
    logger.info("POST /api/captures/stop called")

    try:
        manager = get_tcpdump_manager()
        session = manager.stop_capture()

        logger.info(f"Capture stopped (capture_id={session.id})")

        return jsonify({
            "success": True,
            "session": session.to_dict(),
        }), 200

    except CaptureError as e:
        logger.warning(f"Capture stop failed (code={e.code}, message={e.message})")
        return jsonify({
            "success": False,
            "error": e.to_dict(),
        }), 400

    except Exception as e:
        logger.error(f"Unexpected error stopping capture (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "CAPTURE_FAILED",
                "message": f"Erreur inattendue: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/captures/status', methods=['GET'])
def get_capture_status():
    """Get current capture status.

    Returns:
        JSON response with current session status or idle state
    """
    logger.debug("GET /api/captures/status called")

    try:
        manager = get_tcpdump_manager()
        session = manager.get_status()

        if session is None:
            return jsonify({
                "success": True,
                "status": CaptureStatus.IDLE.value,
                "session": None,
            }), 200

        return jsonify({
            "success": True,
            "status": session.status.value,
            "session": session.to_dict(),
        }), 200

    except Exception as e:
        logger.error(f"Error getting capture status (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "CAPTURE_FAILED",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/captures/latest', methods=['GET'])
def get_latest_capture():
    """Get the latest capture results.

    Query Parameters:
        include_packets: bool - Include packet details (default: false)
        parse: bool - Parse capture file for full results (default: false)

    Returns:
        JSON response with capture results and summary
    """
    logger.info("GET /api/captures/latest called")

    include_packets = request.args.get("include_packets", "false").lower() == "true"
    do_parse = request.args.get("parse", "false").lower() == "true"

    try:
        manager = get_tcpdump_manager()
        result = manager.get_latest_result()

        if result is None:
            return jsonify({
                "success": True,
                "result": None,
                "message": "Aucune capture disponible",
            }), 200

        # Parse capture file if requested and file exists
        if do_parse and result.session.capture_path and result.session.capture_path.exists():
            try:
                packets, summary = parse_capture_file(result.session.capture_path)
                result.packets = packets
                result.summary = summary
            except Exception as e:
                logger.warning(f"Failed to parse capture file (error={str(e)})")

        response_data = {
            "success": True,
            "result": result.to_dict(),
        }

        # Include packets if requested
        if include_packets and result.packets:
            response_data["packets"] = [p.to_dict() for p in result.packets[:1000]]  # Limit to 1000
            response_data["packets_truncated"] = len(result.packets) > 1000

        return jsonify(response_data), 200

    except CaptureError as e:
        logger.warning(f"Error getting latest capture (code={e.code})")
        return jsonify({
            "success": False,
            "error": e.to_dict(),
        }), 400

    except Exception as e:
        logger.error(f"Unexpected error getting latest capture (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "CAPTURE_FAILED",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/captures/config', methods=['GET'])
def get_capture_config():
    """Get capture configuration options.

    Returns default values and valid ranges for capture parameters.

    Returns:
        JSON with configuration options
    """
    return jsonify({
        "success": True,
        "config": {
            "duration": {
                "default": DEFAULT_CAPTURE_DURATION,
                "min": MIN_CAPTURE_DURATION,
                "max": MAX_CAPTURE_DURATION,
                "options": [30, 60, 120, 300, 600],
            },
            "interface": {
                "default": "auto",
                "description": "Network interface (auto, eth0, usb0, wlan0)",
            },
            "bpf_filter": {
                "default": DEFAULT_BPF_FILTER,
                "description": "Berkeley Packet Filter expression",
            },
        },
    }), 200


@api_bp.route('/captures/essentials', methods=['GET'])
def get_capture_essentials():
    """Get the 4 essential analyses for a capture.

    Provides quick overview with Top IPs, Protocol Distribution,
    Ports Used, and Volume Data analyses.

    Query Parameters:
        capture_id: str - Specific capture ID (default: latest)

    Returns:
        JSON response with FourEssentialsResult containing:
        - top_ips: Top active IPs with internal/external distinction
        - protocols: TCP/UDP/ICMP distribution with alerts
        - ports: Active ports with suspicious marking
        - volume: Traffic statistics with anomaly detection
        - overall_status: Aggregated status (critical/warning/normal)
        - overall_indicator: Visual indicator emoji

    Example Response:
        {
            "success": true,
            "result": {
                "capture_id": "cap_20260122_150000",
                "top_ips": {...},
                "protocols": {...},
                "ports": {...},
                "volume": {...},
                "overall_status": "normal",
                "overall_indicator": "🟢"
            }
        }
    """
    logger.info("GET /api/captures/essentials called")

    capture_id = request.args.get("capture_id")

    try:
        manager = get_tcpdump_manager()

        # Get capture result
        if capture_id:
            # Future: support getting specific capture by ID
            # For now, just use latest
            result = manager.get_latest_result()
            if result is None or result.session.id != capture_id:
                return jsonify({
                    "success": False,
                    "error": {
                        "code": "CAPTURE_NOT_FOUND",
                        "message": f"Capture {capture_id} non trouvee",
                        "details": {},
                    },
                }), 404
        else:
            result = manager.get_latest_result()

        if result is None:
            return jsonify({
                "success": False,
                "error": {
                    "code": "ANALYSIS_NO_CAPTURE",
                    "message": "Aucune capture disponible pour analyse",
                    "details": {},
                },
            }), 404

        # Parse capture file if needed
        if not result.packets and result.session.capture_path and result.session.capture_path.exists():
            try:
                packets, summary = parse_capture_file(result.session.capture_path)
                result.packets = packets
                result.summary = summary
            except Exception as e:
                logger.warning(f"Failed to parse capture file (error={str(e)})")

        # Get anomalies from store
        anomaly_store = get_anomaly_store()
        anomaly_collection = anomaly_store.get_by_capture(result.session.id)
        anomalies = anomaly_collection.anomalies if anomaly_collection else []

        # Run four essentials analysis
        analyzer = get_four_essentials_analyzer()
        essentials_result = analyzer.analyze(result, anomalies)

        logger.info(
            f"Four essentials analysis returned "
            f"(capture_id={result.session.id}, overall={essentials_result.overall_status.value})"
        )

        return jsonify({
            "success": True,
            "result": essentials_result.to_dict(),
        }), 200

    except CaptureError as e:
        logger.warning(f"Error getting essentials (code={e.code})")
        return jsonify({
            "success": False,
            "error": e.to_dict(),
        }), 400

    except Exception as e:
        logger.error(f"Unexpected error getting essentials (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "ANALYSIS_FAILED",
                "message": f"Erreur analyse: {str(e)}",
                "details": {},
            },
        }), 500
