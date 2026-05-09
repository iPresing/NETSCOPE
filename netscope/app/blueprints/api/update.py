"""API endpoints for update checking and OTA update (Stories 5.5, 5.6)."""

import logging

from flask import jsonify, request

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


@api_bp.route('/update/status')
def update_status():
    """Get current update process status.

    Returns:
        JSON with state, progress_percent, current_step, error, error_code
    """
    from app.services.update_service import get_update_service

    service = get_update_service()
    status = service.get_update_status()
    return jsonify(status.to_dict()), 200


@api_bp.route('/update/history')
def update_history():
    """Get update history (past attempts).

    Returns:
        JSON with success flag and history list sorted by date descending
    """
    from app.services.update_service import get_update_service

    service = get_update_service()
    try:
        history = service.get_update_history()
        return jsonify({"success": True, "history": history}), 200
    except Exception as e:
        logger.error("[api.update] Erreur lecture historique : %s", e)
        return jsonify({
            "success": False,
            "error": "Impossible de lire l'historique des mises à jour.",
            "error_code": "UPDATE_HISTORY_READ_ERROR",
        }), 500


@api_bp.route('/update/apply', methods=['POST'])
def apply_update():
    """Trigger OTA update process.

    Returns:
        JSON with started status or error if already running
    """
    from app.services.update_service import get_update_service

    logger.info('POST /api/update/apply called (ip=%s)', request.remote_addr)
    service = get_update_service()
    started = service.start_update()
    if started:
        return jsonify({"started": True, "message": "Mise à jour démarrée."}), 202
    return jsonify({"started": False, "message": "Une mise à jour est déjà en cours."}), 409
