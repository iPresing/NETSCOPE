"""Admin routes for NETSCOPE."""

import logging
from flask import render_template, request

from . import admin_bp

logger = logging.getLogger(__name__)


@admin_bp.route('/')
def admin_index():
    """Admin home page.

    Returns:
        Rendered admin template
    """
    logger.debug(f'Admin page rendered (ip={request.remote_addr})')
    return render_template('admin.html')


@admin_bp.route('/update')
def update():
    """Update management page.

    Returns:
        Rendered update template
    """
    logger.debug(f'Update page rendered (ip={request.remote_addr})')
    return render_template('update.html')


@admin_bp.route('/config')
def config():
    """Configuration page.

    Returns:
        Rendered config template
    """
    logger.debug(f'Config page rendered (ip={request.remote_addr})')
    return render_template('config.html')
