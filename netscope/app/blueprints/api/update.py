"""API endpoint for update checking (Story 5.5)."""

import logging

from flask import jsonify

from . import api_bp

logger = logging.getLogger(__name__)


@api_bp.route('/update/check')
def check_update():
    """Check for available updates via GitHub API.

    Returns:
        JSON with update status, version info, or error details
    """
    from app.services.update_service import get_update_service

    logger.info('GET /api/update/check called')
    service = get_update_service()
    result = service.check_for_update()
    return jsonify(result.to_dict()), 200
