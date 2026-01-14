"""Dashboard routes for NETSCOPE."""

import logging
from flask import render_template, request

from . import dashboard_bp

logger = logging.getLogger(__name__)


@dashboard_bp.route('/')
def index():
    """Dashboard home page.

    Returns:
        Rendered dashboard template
    """
    logger.debug(f'Dashboard rendered (ip={request.remote_addr})')
    return render_template('dashboard.html')


@dashboard_bp.route('/anomalies')
def anomalies():
    """Anomalies list page.

    Returns:
        Rendered anomalies template
    """
    logger.debug(f'Anomalies page rendered (ip={request.remote_addr})')
    return render_template('anomalies.html')


@dashboard_bp.route('/jobs')
def jobs():
    """Jobs inspection page.

    Returns:
        Rendered jobs template
    """
    logger.debug(f'Jobs page rendered (ip={request.remote_addr})')
    return render_template('jobs.html')
