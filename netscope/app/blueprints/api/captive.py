"""Captive portal API endpoints for NETSCOPE."""

import logging

from flask import jsonify, request

from . import api_bp
from app.blueprints.captive.captive_manager import get_captive_manager

logger = logging.getLogger(__name__)


@api_bp.route('/captive/status')
def captive_status():
    """Get captive portal status.

    Returns:
        JSON with captive_active flag, released client count, and IPs.
    """
    manager = get_captive_manager()
    status = manager.get_status()

    return jsonify({
        'success': True,
        'result': status,
        'message': 'Captive portal status retrieved',
    }), 200


@api_bp.route('/captive/release', methods=['POST'])
def captive_release():
    """Release the requesting client from captive portal.

    Adds the client IP to the released set and disables captive
    mode globally (DNS hijack + DNAT removed).

    Returns:
        JSON with release result.
    """
    manager = get_captive_manager()
    client_ip = request.remote_addr

    if manager.is_released(client_ip):
        return jsonify({
            'success': True,
            'result': {'already_released': True, 'client_ip': client_ip},
            'message': 'Client already released',
        }), 200

    success = manager.release_client(client_ip)

    if success:
        logger.info('Client %s released via API', client_ip)
        return jsonify({
            'success': True,
            'result': {
                'client_ip': client_ip,
                'captive_active': manager.is_captive_active(),
            },
            'message': 'Client released successfully',
        }), 200

    return jsonify({
        'success': False,
        'result': {},
        'message': 'Failed to release client',
    }), 500
