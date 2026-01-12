"""Admin routes for NETSCOPE."""

from flask import jsonify

from . import admin_bp


@admin_bp.route('/')
def admin_index():
    """Admin home page.

    Returns:
        JSON response with admin status
    """
    return jsonify({
        'status': 'admin_panel',
        'message': 'NETSCOPE Administration'
    })
