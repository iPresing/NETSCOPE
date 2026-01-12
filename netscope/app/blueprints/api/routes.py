"""API routes for NETSCOPE."""

from flask import jsonify

from . import api_bp


@api_bp.route('/health')
def health_check():
    """Health check endpoint.

    Returns:
        JSON response with status and version
    """
    return jsonify({
        'status': 'ok',
        'version': '0.1.0'
    }), 200
