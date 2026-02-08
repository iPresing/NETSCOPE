"""Whitelist API endpoints for NETSCOPE.

Provides REST API for whitelist CRUD management.

Story 3.6: CRUD Whitelist Complet (FR37, FR38, FR39)

Lessons Learned Epic 1/2/3:
- Use module-level logger, NOT current_app.logger
- Standard response format: {"success": bool, "result": {...}, "error": {...}}
"""

import logging

from flask import jsonify, request

from . import api_bp
from app.services.whitelist_manager import get_whitelist_manager

logger = logging.getLogger(__name__)


@api_bp.route('/whitelist', methods=['GET'])
def list_whitelist():
    """List all whitelist entries.

    Returns:
        JSON response with list of entries and count
    """
    logger.debug("GET /api/whitelist called")

    try:
        manager = get_whitelist_manager()
        entries = manager.get_all()

        return jsonify({
            "success": True,
            "result": {
                "entries": [e.to_dict() for e in entries],
                "count": len(entries),
            },
        }), 200

    except (OSError, IOError, ValueError, KeyError) as e:
        logger.error(f"Error listing whitelist (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "WHITELIST_LIST_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/whitelist', methods=['POST'])
def add_whitelist():
    """Add an entry to the whitelist.

    Request Body:
        {"value": "192.168.1.100", "reason": "Optional note"}

    Returns:
        201: Entry created successfully
        400: Invalid value
        409: Duplicate entry
    """
    logger.debug("POST /api/whitelist called")

    data = request.get_json(silent=True)
    if not data or "value" not in data:
        return jsonify({
            "success": False,
            "error": {
                "code": "WHITELIST_INVALID_VALUE",
                "message": "Champ 'value' requis",
                "details": {},
            },
        }), 400

    try:
        manager = get_whitelist_manager()
        entry = manager.add(data["value"], data.get("reason", ""))

        logger.info(f"Whitelist entry added (id={entry.id}, value={entry.value})")

        return jsonify({
            "success": True,
            "result": entry.to_dict(),
        }), 201

    except ValueError as exc:
        code = "WHITELIST_DUPLICATE" if "Doublon" in str(exc) else "WHITELIST_INVALID_VALUE"
        status = 409 if "Doublon" in str(exc) else 400
        return jsonify({
            "success": False,
            "error": {
                "code": code,
                "message": str(exc),
                "details": {},
            },
        }), status


@api_bp.route('/whitelist/<entry_id>', methods=['DELETE'])
def remove_whitelist(entry_id):
    """Remove an entry from the whitelist.

    Args:
        entry_id: ID of the entry to remove

    Returns:
        200: Entry removed successfully
        404: Entry not found
    """
    logger.debug(f"DELETE /api/whitelist/{entry_id} called")

    try:
        manager = get_whitelist_manager()
        removed = manager.remove(entry_id)

        logger.info(f"Whitelist entry removed (id={entry_id}, value={removed.value})")

        return jsonify({
            "success": True,
            "result": removed.to_dict(),
        }), 200

    except KeyError:
        return jsonify({
            "success": False,
            "error": {
                "code": "WHITELIST_NOT_FOUND",
                "message": f"Entree '{entry_id}' non trouvee",
                "details": {},
            },
        }), 404
