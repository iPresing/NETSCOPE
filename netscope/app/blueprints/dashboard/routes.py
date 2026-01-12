"""Dashboard routes for NETSCOPE."""

from flask import render_template

from . import dashboard_bp


@dashboard_bp.route('/')
def index():
    """Dashboard home page.

    Returns:
        Rendered dashboard template
    """
    return render_template('base.html')
