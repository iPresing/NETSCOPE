"""System status API endpoint for NETSCOPE.

Story 4.7: Graceful Degradation (FR44)
- GET /api/system/status: Returns degradation state and CPU info

Rules:
- module-level logger
- Standard response format: {"success": bool, "result": {...}}
"""

import logging

from flask import jsonify

from . import api_bp
from app.services.resource_monitor import get_resource_monitor
from app.services.graceful_degradation import get_degradation_manager

logger = logging.getLogger(__name__)


@api_bp.route('/system/status', methods=['GET'])
def get_system_status():
    """Get system degradation status and CPU info.

    Returns:
        200: System status with degradation and CPU data
    """
    logger.debug("GET /api/system/status called")

    monitor = get_resource_monitor()
    degradation = get_degradation_manager()

    monitor_status = monitor.get_status()
    degradation_status = degradation.get_status()

    return jsonify({
        "success": True,
        "result": {
            "degradation": degradation_status,
            "resources": monitor_status,
        },
    }), 200
