"""Analysis API endpoints for NETSCOPE.

Provides REST API for accessing analysis results including four essentials.

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
"""

import logging
from flask import jsonify, request

from . import api_bp
from app.core.capture import get_tcpdump_manager, parse_capture_file
from app.core.analysis.four_essentials import get_four_essentials_analyzer
from app.core.detection.anomaly_store import get_anomaly_store
from app.models.capture import CaptureError

logger = logging.getLogger(__name__)


@api_bp.route('/analysis/four-essentials', methods=['GET'])
def get_four_essentials():
    """Get the 4 essential analyses for dashboard status cards.

    Provides Top IPs, Protocol Distribution, Ports Used, and Volume Data
    analyses with status indicators (critical/warning/normal).

    Query Parameters:
        capture_id: str - Specific capture ID (default: "latest")

    Returns:
        JSON response with FourEssentialsResult

    Example Success Response (200):
        {
            "success": true,
            "result": {
                "capture_id": "cap_20260123_150000",
                "top_ips": {
                    "name": "top_ips",
                    "title": "Top IPs",
                    "status": "critical",
                    "indicator": "🔴",
                    "message": "2 IP(s) blacklistee(s) detectee(s)",
                    "data": {...},
                    "details": []
                },
                "protocols": {...},
                "ports": {...},
                "volume": {...},
                "overall_status": "critical",
                "overall_indicator": "🔴"
            }
        }

    Example No Capture Response (200):
        {
            "success": true,
            "result": null,
            "message": "Aucune capture disponible"
        }
    """
    capture_id = request.args.get("capture_id", "latest")

    logger.debug("Four essentials requested (capture_id=%s)", capture_id)

    try:
        manager = get_tcpdump_manager()

        # Get capture result
        if capture_id and capture_id != "latest":
            # Future: support getting specific capture by ID
            # For now, check if latest matches
            result = manager.get_latest_result()
            if result is None or result.session.id != capture_id:
                return jsonify({
                    "success": True,
                    "result": None,
                    "message": "Capture " + capture_id + " non trouvee",
                }), 200
        else:
            result = manager.get_latest_result()

        if result is None:
            logger.debug("No capture available for four essentials")
            return jsonify({
                "success": True,
                "result": None,
                "message": "Aucune capture disponible",
            }), 200

        # Parse capture file if needed
        # Note: We update the shared result object here. This is acceptable for
        # sync Gunicorn workers (one request per worker at a time). For async
        # scenarios, consider creating a local copy of the result.
        if not result.packets and result.session.capture_path and result.session.capture_path.exists():
            try:
                packets, summary = parse_capture_file(result.session.capture_path)
                result.packets = packets
                result.summary = summary
            except Exception as e:
                logger.warning("Failed to parse capture file (error=%s)", str(e))

        # Get anomalies from store
        anomaly_store = get_anomaly_store()
        anomaly_collection = anomaly_store.get_by_capture(result.session.id)
        anomalies = anomaly_collection.anomalies if anomaly_collection else []

        # Run four essentials analysis
        analyzer = get_four_essentials_analyzer()
        essentials_result = analyzer.analyze(result, anomalies)

        logger.debug(
            "Returning FourEssentialsResult (overall=%s)",
            essentials_result.overall_status.value
        )
        logger.info(
            "Four essentials served (capture=%s, status=%s)",
            result.session.id, essentials_result.overall_status.value
        )

        return jsonify({
            "success": True,
            "result": essentials_result.to_dict(),
        }), 200

    except CaptureError as e:
        logger.warning("Capture error getting four essentials (code=%s)", e.code)
        return jsonify({
            "success": False,
            "error": {
                "code": e.code,
                "message": e.message,
                "details": e.details,
            },
        }), 400

    except Exception as e:
        logger.error("Error getting four essentials (error=%s)", str(e))
        return jsonify({
            "success": False,
            "error": {
                "code": "ANALYSIS_ERROR",
                "message": "Erreur: " + str(e),
                "details": {},
            },
        }), 500
