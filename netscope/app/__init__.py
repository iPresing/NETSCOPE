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

    # Register blueprints
    _register_blueprints(app)

    # Register error handlers
    _register_error_handlers(app)

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
