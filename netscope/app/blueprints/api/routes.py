"""API routes for NETSCOPE."""

import logging
from flask import jsonify, current_app

from . import api_bp

logger = logging.getLogger(__name__)


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


@api_bp.route('/hardware')
def get_hardware():
    """Get hardware information and performance targets.

    Returns detected Raspberry Pi model, hardware specifications,
    and adapted performance targets.

    Returns:
        JSON response with hardware info and performance targets
    """
    logger.info(' GET /api/hardware called')

    hardware_info = current_app.config.get('NETSCOPE_HARDWARE_INFO')
    performance_targets = current_app.config.get('NETSCOPE_PERFORMANCE_TARGETS')

    if hardware_info is None or performance_targets is None:
        logger.warning(
            ' Hardware info not available '
            '(reason=detection_not_run_or_failed)'
        )
        return jsonify({
            'success': False,
            'error': {
                'code': 'HARDWARE_DETECTION_FAILED',
                'message': 'Hardware detection has not been performed or failed',
                'details': {}
            }
        }), 500

    response = {
        'success': True,
        'hardware': hardware_info.to_dict(),
        'performance_targets': performance_targets.to_dict()
    }

    logger.info(
        f' Hardware info returned '
        f'(model={hardware_info.model_name})'
    )

    return jsonify(response), 200
