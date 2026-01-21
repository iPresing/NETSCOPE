"""Anomaly API endpoints for NETSCOPE.

Provides REST API for accessing detected anomalies.

Lessons Learned Epic 1:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
"""

import logging
from flask import jsonify, request

from . import api_bp
from app.core.detection.anomaly_store import get_anomaly_store

logger = logging.getLogger(__name__)


@api_bp.route('/anomalies', methods=['GET'])
def get_anomalies():
    """Get detected anomalies.

    Query Parameters:
        capture_id: str - Filter by capture ID (optional)
        latest: bool - Get only from latest capture (default: true)

    Returns:
        JSON response with anomaly list

    Example Response:
        {
            "success": true,
            "result": {
                "anomalies": [
                    {
                        "id": "anomaly_abc123",
                        "match_type": "ip",
                        "matched_value": "45.33.32.156",
                        "source_file": "blacklist",
                        "context": "IP 45.33.32.156:4444 (destination) - 192.168.1.10 -> 45.33.32.156 (TCP)",
                        "criticality": "critical",
                        "score": 85,
                        "packet_info": {...},
                        "capture_id": "cap_20260117_143000",
                        "created_at": "2026-01-17T14:30:05Z"
                    }
                ],
                "total": 1,
                "by_criticality": {
                    "critical": 1,
                    "warning": 0,
                    "normal": 0
                }
            }
        }
    """
    logger.debug("GET /api/anomalies called")

    capture_id = request.args.get("capture_id")
    get_latest = request.args.get("latest", "true").lower() == "true"

    try:
        store = get_anomaly_store()

        if capture_id:
            # Get anomalies for specific capture
            collection = store.get_by_capture(capture_id)
        elif get_latest:
            # Get anomalies from latest capture
            collection = store.get_latest()
        else:
            # Get all anomalies (build a combined response)
            all_anomalies = store.get_all_anomalies()
            from app.models.anomaly import CriticalityLevel

            by_criticality = {"critical": 0, "warning": 0, "normal": 0}
            for a in all_anomalies:
                by_criticality[a.criticality_level.value] += 1

            return jsonify({
                "success": True,
                "result": {
                    "anomalies": [a.to_dict() for a in all_anomalies],
                    "total": len(all_anomalies),
                    "by_criticality": by_criticality,
                },
            }), 200

        if collection is None:
            return jsonify({
                "success": True,
                "result": {
                    "anomalies": [],
                    "total": 0,
                    "by_criticality": {
                        "critical": 0,
                        "warning": 0,
                        "normal": 0,
                    },
                },
                "message": "Aucune anomalie détectée",
            }), 200

        return jsonify({
            "success": True,
            "result": collection.to_dict(),
        }), 200

    except Exception as e:
        logger.error(f"Error getting anomalies (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "ANOMALY_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/anomalies/<anomaly_id>', methods=['GET'])
def get_anomaly(anomaly_id: str):
    """Get a specific anomaly by ID.

    Path Parameters:
        anomaly_id: Unique anomaly identifier

    Returns:
        JSON response with anomaly details

    Example Response:
        {
            "success": true,
            "anomaly": {
                "id": "anomaly_abc123",
                "match_type": "ip",
                "matched_value": "45.33.32.156",
                ...
            }
        }
    """
    logger.debug(f"GET /api/anomalies/{anomaly_id} called")

    try:
        store = get_anomaly_store()
        anomaly = store.get_anomaly(anomaly_id)

        if anomaly is None:
            return jsonify({
                "success": False,
                "error": {
                    "code": "ANOMALY_NOT_FOUND",
                    "message": f"Anomalie '{anomaly_id}' introuvable",
                    "details": {"anomaly_id": anomaly_id},
                },
            }), 404

        return jsonify({
            "success": True,
            "anomaly": anomaly.to_dict(),
        }), 200

    except Exception as e:
        logger.error(f"Error getting anomaly (anomaly_id={anomaly_id}, error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "ANOMALY_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/anomalies/summary', methods=['GET'])
def get_anomalies_summary():
    """Get summary of detected anomalies.

    Returns aggregated statistics across all captures.

    Returns:
        JSON response with summary statistics
    """
    logger.debug("GET /api/anomalies/summary called")

    try:
        store = get_anomaly_store()
        all_anomalies = store.get_all_anomalies()

        from app.models.anomaly import CriticalityLevel, MatchType

        by_criticality = {"critical": 0, "warning": 0, "normal": 0}
        by_type = {"ip": 0, "domain": 0, "term": 0}

        for anomaly in all_anomalies:
            by_criticality[anomaly.criticality_level.value] += 1
            by_type[anomaly.match.match_type.value] += 1

        return jsonify({
            "success": True,
            "summary": {
                "total": len(all_anomalies),
                "by_criticality": by_criticality,
                "by_type": by_type,
            },
        }), 200

    except Exception as e:
        logger.error(f"Error getting anomalies summary (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "ANOMALY_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500
