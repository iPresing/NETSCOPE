"""Health Score API endpoints for NETSCOPE.

Provides REST API for network health score (Story 3.2).

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
"""

import logging
from flask import jsonify

from . import api_bp
from app.core.capture import get_tcpdump_manager
from app.core.analysis.health_score import get_health_calculator
from app.core.detection.anomaly_store import get_anomaly_store
from app.models.health_score import HealthScoreResult

logger = logging.getLogger(__name__)


@api_bp.route('/health/score', methods=['GET'])
def get_health_score():
    """Get network health score from latest capture.

    Calculates health score based on anomalies detected in the most recent
    network capture using the HealthScoreCalculator (Story 3.1).

    Returns:
        JSON response with HealthScoreResult data

    Example Success Response (200):
        {
            "success": true,
            "data": {
                "displayed_score": 72,
                "real_score": 65,
                "base_score": 100,
                "critical_count": 1,
                "warning_count": 3,
                "whitelist_hits": 2,
                "whitelist_impact": 7,
                "status_color": "warning"
            }
        }

    Example No Capture Response (200):
        {
            "success": true,
            "data": null,
            "message": "Aucune capture disponible"
        }

    Example Error Response (500):
        {
            "success": false,
            "error": {
                "code": "HEALTH_SCORE_ERROR",
                "message": "Erreur lors du calcul du score",
                "details": {}
            }
        }
    """
    logger.debug("GET /api/health/score called")

    try:
        manager = get_tcpdump_manager()
        latest_result = manager.get_latest_result()

        if latest_result is None or latest_result.session is None:
            logger.debug("No capture available for health score")
            return jsonify({
                "success": True,
                "data": None,
                "message": "Aucune capture disponible",
            }), 200

        # Get anomalies for this capture
        anomaly_store = get_anomaly_store()
        anomaly_collection = anomaly_store.get_by_capture(latest_result.session.id)

        if anomaly_collection and len(anomaly_collection.anomalies) > 0:
            # Calculate health score from anomalies
            calculator = get_health_calculator()
            health_result = calculator.calculate(anomaly_collection)

            logger.debug(
                f"Health score calculated (score={health_result.displayed_score}, "
                f"status={health_result.get_status_color()}, "
                f"critical={health_result.critical_count}, "
                f"warning={health_result.warning_count})"
            )
            logger.info(
                f"Health score served (capture={latest_result.session.id}, "
                f"score={health_result.displayed_score})"
            )

            return jsonify({
                "success": True,
                "data": health_result.to_dict(),
            }), 200

        else:
            # No anomalies = perfect score
            health_result = HealthScoreResult(
                displayed_score=100,
                real_score=100,
            )

            logger.debug("Health score: 100 (no anomalies detected)")
            logger.info(
                f"Health score served (capture={latest_result.session.id}, score=100)"
            )

            return jsonify({
                "success": True,
                "data": health_result.to_dict(),
            }), 200

    except Exception as e:
        logger.error(f"Error calculating health score (error={str(e)})", exc_info=True)
        return jsonify({
            "success": False,
            "error": {
                "code": "HEALTH_SCORE_ERROR",
                "message": "Erreur lors du calcul du score sante",
                "details": {},
            },
        }), 500
