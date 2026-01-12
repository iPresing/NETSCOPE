"""Network API endpoints for NETSCOPE.

Provides REST endpoints for network interface status and information.
"""

import logging

from flask import current_app, jsonify

from . import api_bp
from app.core.capture.interface_detector import (
    detect_interfaces,
    get_recommended_interface,
)

logger = logging.getLogger(__name__)


@api_bp.route('/network/status')
def network_status():
    """Get current network status.

    Returns the currently active network interface information
    including IP address, interface name, and connection mode.

    Returns:
        JSON response with network status:
        {
            "success": true,
            "data": {
                "current_interface": "eth0",
                "current_ip": "192.168.1.45",
                "connection_mode": "Ethernet"
            }
        }
    """
    return jsonify({
        'success': True,
        'data': {
            'current_interface': current_app.config.get('NETSCOPE_INTERFACE'),
            'current_ip': current_app.config.get('NETSCOPE_IP'),
            'connection_mode': current_app.config.get('NETSCOPE_CONNECTION_MODE'),
        }
    }), 200


@api_bp.route('/network/interfaces')
def network_interfaces():
    """Get all detected network interfaces.

    Scans and returns all network interfaces available on the system
    with their current status and configuration.

    Returns:
        JSON response with interfaces list:
        {
            "success": true,
            "data": {
                "interfaces": [
                    {
                        "name": "eth0",
                        "type": "ethernet",
                        "ip_address": "192.168.1.45",
                        "is_up": true,
                        "is_connected": true,
                        "mac_address": "dc:a6:32:xx:xx:xx",
                        "description": "Ethernet"
                    }
                ],
                "recommended": "eth0"
            }
        }
    """
    try:
        interfaces = detect_interfaces()
        recommended = get_recommended_interface(interfaces)

        interfaces_data = [
            {
                'name': iface.name,
                'type': iface.type.value,
                'ip_address': iface.ip_address,
                'is_up': iface.is_up,
                'is_connected': iface.is_connected,
                'mac_address': iface.mac_address,
                'description': iface.description,
            }
            for iface in interfaces
        ]

        return jsonify({
            'success': True,
            'data': {
                'interfaces': interfaces_data,
                'recommended': recommended.name if recommended else None,
            }
        }), 200

    except Exception as e:
        logger.error(f'Failed to get network interfaces (error={str(e)})')
        return jsonify({
            'success': False,
            'error': {
                'code': 'NETWORK_INTERFACE_NOT_FOUND',
                'message': 'Failed to detect network interfaces',
                'details': {'error': str(e)}
            }
        }), 500
