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

    # Detect hardware and configure performance targets
    _configure_hardware(app)

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
    """Configure application logging with NETSCOPE structured format.

    Uses custom NetScopeFormatter to produce short module names conforming
    to architecture standard: [TIME][LEVEL][module.submodule] Message

    Args:
        app: Flask application instance
        config_name: Current configuration name
    """
    from app.logging_config import configure_logging
    configure_logging(app, config_name)


def _configure_hardware(app):
    """Detect hardware and configure performance targets.

    Detects the Raspberry Pi model at startup and stores hardware info
    and performance targets in app.config for use throughout the application.

    Args:
        app: Flask application instance
    """
    from app.services import get_hardware_info, get_current_targets

    try:
        # Detect hardware
        hardware_info = get_hardware_info()

        # Get performance targets based on detected hardware
        performance_targets = get_current_targets()

        # Store in app.config
        app.config['NETSCOPE_HARDWARE_INFO'] = hardware_info
        app.config['NETSCOPE_PERFORMANCE_TARGETS'] = performance_targets

        app.logger.info(
            f'Hardware configured (model={hardware_info.model_name}, '
            f'cpu_count={hardware_info.cpu_count}, ram_mb={hardware_info.ram_mb}, '
            f'cpu_threshold={performance_targets.cpu_threshold_percent}%, '
            f'max_jobs={performance_targets.max_concurrent_jobs})'
        )

    except Exception as e:
        app.logger.error(f'Failed to detect hardware (error={str(e)})')
        # Set defaults for graceful degradation
        app.config['NETSCOPE_HARDWARE_INFO'] = None
        app.config['NETSCOPE_PERFORMANCE_TARGETS'] = None


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

    @app.context_processor
    def inject_hardware_info():
        """Inject hardware information and performance targets into all templates.

        Provides the following template variables:
        - hardware_model: Human-readable model name
        - hardware_model_code: PiModel enum value
        - hardware_cpu_count: Number of CPU cores
        - hardware_ram_mb: RAM in megabytes
        - performance_cpu_threshold: CPU usage threshold percent
        - performance_ram_threshold: RAM usage threshold percent
        - performance_max_jobs: Maximum concurrent jobs allowed
        """
        hardware_info = app.config.get('NETSCOPE_HARDWARE_INFO')
        performance_targets = app.config.get('NETSCOPE_PERFORMANCE_TARGETS')

        if hardware_info and performance_targets:
            return {
                'hardware_model': hardware_info.model_name,
                'hardware_model_code': hardware_info.model.value,
                'hardware_cpu_count': hardware_info.cpu_count,
                'hardware_ram_mb': hardware_info.ram_mb,
                'performance_cpu_threshold': performance_targets.cpu_threshold_percent,
                'performance_ram_threshold': performance_targets.ram_threshold_percent,
                'performance_max_jobs': performance_targets.max_concurrent_jobs,
            }
        return {
            'hardware_model': 'Unknown',
            'hardware_model_code': 'UNKNOWN',
            'hardware_cpu_count': 0,
            'hardware_ram_mb': 0,
            'performance_cpu_threshold': 30,
            'performance_ram_threshold': 30,
            'performance_max_jobs': 1,
        }
