"""Dashboard routes for NETSCOPE."""

import logging
from flask import render_template, request

from . import dashboard_bp
from app.core.capture import get_tcpdump_manager
from app.core.analysis.health_score import get_health_calculator
from app.core.detection.anomaly_store import get_anomaly_store
from app.models.health_score import HealthScoreResult

logger = logging.getLogger(__name__)


@dashboard_bp.route('/')
def index():
    """Dashboard home page.

    Calculates health score from latest capture if available.

    Returns:
        Rendered dashboard template with health_score data
    """
    logger.debug(f'Dashboard rendered (ip={request.remote_addr})')

    # Calculate health score from latest capture (Story 3.2, AC4)
    health_score = None

    try:
        manager = get_tcpdump_manager()
        latest_result = manager.get_latest_result()

        if latest_result and latest_result.session:
            # Get anomalies for this capture
            anomaly_store = get_anomaly_store()
            anomaly_collection = anomaly_store.get_by_capture(latest_result.session.id)

            if anomaly_collection:
                # Calculate health score
                calculator = get_health_calculator()
                health_result = calculator.calculate(anomaly_collection)
                health_score = health_result.to_dict()
                logger.debug(
                    f'Health score calculated (score={health_result.displayed_score}, '
                    f'status={health_result.get_status_color()})'
                )
            else:
                # No anomalies = perfect score
                health_score = HealthScoreResult(
                    displayed_score=100,
                    real_score=100,
                ).to_dict()
                logger.debug('Health score: 100 (no anomalies)')

    except Exception as e:
        logger.warning(f'Failed to calculate health score (error={str(e)})')
        # Continue without health score - will show empty state

    return render_template('dashboard.html', health_score=health_score)


@dashboard_bp.route('/anomalies')
def anomalies():
    """Anomalies list page.

    Returns:
        Rendered anomalies template
    """
    logger.debug(f'Anomalies page rendered (ip={request.remote_addr})')
    return render_template('anomalies.html')


@dashboard_bp.route('/whitelist')
def whitelist():
    """Whitelist management page (Story 3.6).

    Returns:
        Rendered whitelist template
    """
    logger.debug(f'Whitelist page rendered (ip={request.remote_addr})')
    return render_template('whitelist.html')


@dashboard_bp.route('/jobs')
def jobs():
    """Jobs inspection page.

    Returns:
        Rendered jobs template
    """
    logger.debug(f'Jobs page rendered (ip={request.remote_addr})')
    return render_template('jobs.html')
