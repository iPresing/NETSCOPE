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
        include_breakdown: bool - Include score breakdown (default: false)

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
                        "score": 100,
                        "score_breakdown": {  // Only if include_breakdown=true
                            "blacklist_score": 85,
                            "heuristic_score": 25,
                            "total_score": 100,
                            "factors": {...},
                            "criticality": "critical"
                        },
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
    include_breakdown = request.args.get("include_breakdown", "false").lower() == "true"

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
                    "anomalies": [a.to_dict(include_breakdown=include_breakdown) for a in all_anomalies],
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
            "result": collection.to_dict(include_breakdown=include_breakdown),
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


@api_bp.route('/anomalies/score-stats', methods=['GET'])
def get_anomalies_score_stats():
    """Get scoring statistics for detected anomalies.

    Returns detailed scoring statistics including score distribution,
    heuristic factor frequencies, and average scores.

    Returns:
        JSON response with scoring statistics

    Example Response:
        {
            "success": true,
            "stats": {
                "total_anomalies": 5,
                "score_distribution": {
                    "critical": {"count": 3, "avg_score": 92},
                    "warning": {"count": 2, "avg_score": 65},
                    "normal": {"count": 0, "avg_score": 0}
                },
                "heuristic_factors": {
                    "external_ip": 4,
                    "suspicious_port": 2,
                    "high_volume": 1,
                    "unknown_protocol": 0
                },
                "avg_score": 81.4,
                "min_score": 55,
                "max_score": 100
            }
        }
    """
    logger.debug("GET /api/anomalies/score-stats called")

    try:
        store = get_anomaly_store()
        all_anomalies = store.get_all_anomalies()

        if not all_anomalies:
            return jsonify({
                "success": True,
                "stats": {
                    "total_anomalies": 0,
                    "score_distribution": {
                        "critical": {"count": 0, "avg_score": 0},
                        "warning": {"count": 0, "avg_score": 0},
                        "normal": {"count": 0, "avg_score": 0},
                    },
                    "heuristic_factors": {
                        "external_ip": 0,
                        "suspicious_port": 0,
                        "high_volume": 0,
                        "unknown_protocol": 0,
                    },
                    "avg_score": 0,
                    "min_score": 0,
                    "max_score": 0,
                },
            }), 200

        # Calculate statistics
        scores = [a.score for a in all_anomalies]
        total = len(all_anomalies)

        # Score distribution by criticality
        score_distribution = {
            "critical": {"count": 0, "total_score": 0},
            "warning": {"count": 0, "total_score": 0},
            "normal": {"count": 0, "total_score": 0},
        }

        # Heuristic factor frequencies
        heuristic_factors = {
            "external_ip": 0,
            "suspicious_port": 0,
            "high_volume": 0,
            "unknown_protocol": 0,
        }

        for anomaly in all_anomalies:
            crit = anomaly.criticality_level.value
            score_distribution[crit]["count"] += 1
            score_distribution[crit]["total_score"] += anomaly.score

            # Count heuristic factors if breakdown available
            if anomaly.score_breakdown is not None:
                factors = anomaly.score_breakdown.factors
                if factors.is_external_ip:
                    heuristic_factors["external_ip"] += 1
                if factors.is_suspicious_port:
                    heuristic_factors["suspicious_port"] += 1
                if factors.is_high_volume:
                    heuristic_factors["high_volume"] += 1
                if factors.is_unknown_protocol:
                    heuristic_factors["unknown_protocol"] += 1

        # Calculate averages
        for crit in score_distribution:
            count = score_distribution[crit]["count"]
            total_score = score_distribution[crit]["total_score"]
            score_distribution[crit] = {
                "count": count,
                "avg_score": round(total_score / count, 1) if count > 0 else 0,
            }

        return jsonify({
            "success": True,
            "stats": {
                "total_anomalies": total,
                "score_distribution": score_distribution,
                "heuristic_factors": heuristic_factors,
                "avg_score": round(sum(scores) / total, 1),
                "min_score": min(scores),
                "max_score": max(scores),
            },
        }), 200

    except Exception as e:
        logger.error(f"Error getting anomalies score stats (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "ANOMALY_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500
