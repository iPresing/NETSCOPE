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
    from app.services.version_service import get_version_service

    logger.debug(f'Admin page rendered (ip={request.remote_addr})')
    service = get_version_service()
    system_info = service.get_system_info()
    return render_template('admin.html', system_info=system_info)


@admin_bp.route('/update')
def update():
    """Update management page.

    Returns:
        Rendered update template
    """
    from app.services.version_service import get_version_service

    logger.debug(f'Update page rendered (ip={request.remote_addr})')
    service = get_version_service()
    system_info = service.get_system_info()
    return render_template('update.html', system_info=system_info)


@admin_bp.route('/config')
def config():
    """Configuration page.

    Returns:
        Rendered config template
    """
    logger.debug(f'Config page rendered (ip={request.remote_addr})')
    return render_template('config.html')
