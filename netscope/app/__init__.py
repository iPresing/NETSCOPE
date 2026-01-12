"""NETSCOPE Application Factory.

This module provides the application factory pattern for creating Flask
application instances with the appropriate configuration.
"""

import logging
from datetime import datetime
from flask import Flask

from app.config import config


def create_app(config_name='default'):
    """Create and configure the Flask application.

    Args:
        config_name: Configuration name ('development', 'testing', 'production', 'default')

    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Configure logging
    _configure_logging(app, config_name)

    # Detect network interface and configure IP
    _configure_network(app)

    # Register blueprints
    _register_blueprints(app)

    # Register error handlers
    _register_error_handlers(app)

    # Register context processors
    _register_context_processors(app)

    app.logger.info(f'Application created (config={config_name})')

    return app


def _configure_logging(app, config_name):
    """Configure application logging with structured format.

    Args:
        app: Flask application instance
        config_name: Current configuration name
    """
    log_format = '[%(asctime)s][%(levelname)s][%(name)s] %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    logging.basicConfig(
        level=logging.DEBUG if app.config.get('DEBUG') else logging.INFO,
        format=log_format,
        datefmt=date_format
    )


def _configure_network(app):
    """Detect and configure network interface at startup.

    Detects the active network interface and stores the IP address
    and connection mode in app.config for use throughout the application.

    Args:
        app: Flask application instance
    """
    from app.core.capture.interface_detector import (
        detect_interfaces,
        get_recommended_interface,
        InterfaceType,
    )

    try:
        interfaces = detect_interfaces()
        recommended = get_recommended_interface(interfaces)

        if recommended:
            app.config['NETSCOPE_IP'] = recommended.ip_address
            app.config['NETSCOPE_INTERFACE'] = recommended.name
            app.config['NETSCOPE_CONNECTION_MODE'] = _get_connection_mode(recommended.type)
            app.logger.info(
                f'Network configured (ip={recommended.ip_address}, '
                f'interface={recommended.name}, mode={app.config["NETSCOPE_CONNECTION_MODE"]})'
            )
        else:
            app.config['NETSCOPE_IP'] = None
            app.config['NETSCOPE_INTERFACE'] = None
            app.config['NETSCOPE_CONNECTION_MODE'] = 'unknown'
            app.logger.warning('No active network interface detected')

    except Exception as e:
        app.logger.error(f'Failed to detect network interface (error={str(e)})')
        app.config['NETSCOPE_IP'] = None
        app.config['NETSCOPE_INTERFACE'] = None
        app.config['NETSCOPE_CONNECTION_MODE'] = 'unknown'


def _get_connection_mode(interface_type):
    """Get human-readable connection mode from interface type.

    Args:
        interface_type: InterfaceType enum value

    Returns:
        Connection mode string
    """
    from app.core.capture.interface_detector import InterfaceType

    mode_map = {
        InterfaceType.USB_GADGET: 'USB Gadget',
        InterfaceType.ETHERNET: 'Ethernet',
        InterfaceType.WIFI: 'WiFi',
        InterfaceType.UNKNOWN: 'Unknown',
    }
    return mode_map.get(interface_type, 'Unknown')


def _register_blueprints(app):
    """Register all application blueprints.

    Args:
        app: Flask application instance
    """
    from app.blueprints.dashboard import dashboard_bp
    from app.blueprints.api import api_bp
    from app.blueprints.admin import admin_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/admin')


def _register_error_handlers(app):
    """Register custom error handlers.

    Args:
        app: Flask application instance
    """
    from flask import jsonify

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({
            'success': False,
            'error': {
                'code': 'SYSTEM_NOT_FOUND',
                'message': 'The requested resource was not found',
                'details': {}
            }
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            'success': False,
            'error': {
                'code': 'SYSTEM_INTERNAL_ERROR',
                'message': 'An internal server error occurred',
                'details': {}
            }
        }), 500


def _register_context_processors(app):
    """Register context processors for Jinja2 templates.

    Provides global variables available in all templates.

    Args:
        app: Flask application instance
    """

    @app.context_processor
    def inject_network_info():
        """Inject network information into all templates."""
        return {
            'netscope_ip': app.config.get('NETSCOPE_IP'),
            'netscope_interface': app.config.get('NETSCOPE_INTERFACE'),
            'netscope_connection_mode': app.config.get('NETSCOPE_CONNECTION_MODE'),
        }
