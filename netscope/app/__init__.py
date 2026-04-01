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

    # Initialize blacklist manager
    _configure_blacklists(app)

    # Initialize graceful degradation monitoring (Story 4.7)
    _configure_degradation(app)

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
        InterfaceType.ACCESS_POINT: 'Access Point',
        InterfaceType.ETHERNET: 'Ethernet',
        InterfaceType.WIFI: 'WiFi',
        InterfaceType.UNKNOWN: 'Unknown',
    }
    return mode_map.get(interface_type, 'Unknown')


def _configure_blacklists(app):
    """Load and configure blacklists at startup.

    Loads blacklists from configuration file and stores the manager
    reference in app.extensions for easy access. If reload_on_change
    is enabled in config, starts a file watcher for hot-reload.

    Args:
        app: Flask application instance
    """
    import yaml
    from pathlib import Path
    from app.core.detection import get_blacklist_manager, start_blacklist_watcher

    try:
        # Get base path (netscope directory)
        base_path = Path(app.root_path).parent

        # Load config from YAML
        config_path = base_path / 'data' / 'config' / 'netscope.yaml'

        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)

            blacklist_config = config_data.get('blacklists', {})
        else:
            app.logger.warning(f'Config file not found: {config_path}')
            blacklist_config = {}

        # Initialize and load blacklists (defaults depuis fichiers)
        manager = get_blacklist_manager()
        manager.load_blacklists(blacklist_config, base_path=base_path)

        # Appliquer les entrées user JSON persistées (sessions précédentes)
        # Sans cela, les entrées user sont invisibles à la détection jusqu'au
        # premier add/remove de la session courante.
        try:
            from app.services.blacklist_user_manager import BlacklistUserManager
            user_json_path = Path(app.root_path).parent / "data" / "blacklists" / "user_blacklist.json"
            if user_json_path.exists():
                user_mgr_tmp = BlacklistUserManager(user_json_path)
                user_entries = user_mgr_tmp.get_all()
                if user_entries:
                    manager.merge_user_entries(user_entries)
                    app.logger.info(
                        f'User blacklist entries applied at startup ({len(user_entries)} entrées)'
                    )
        except Exception as e:
            app.logger.warning(f'Could not apply user blacklist entries at startup (error={str(e)})')

        # Store reference in app for easy access
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['blacklist_manager'] = manager

        # Store stats in config for template access
        stats = manager.get_stats()
        app.config['NETSCOPE_BLACKLIST_STATS'] = stats

        app.logger.info(
            f'Blacklists configured (ips={stats.ips_count}, '
            f'domains={stats.domains_count}, terms={stats.terms_count})'
        )

        # Start hot-reload watcher if enabled in config
        if blacklist_config.get('reload_on_change', False):
            watcher = start_blacklist_watcher(blacklist_config, base_path=base_path)
            if watcher:
                app.extensions['blacklist_watcher'] = watcher
                app.logger.info('Blacklist hot-reload watcher started')
            else:
                app.logger.warning('Failed to start blacklist hot-reload watcher')

    except Exception as e:
        app.logger.error(f'Failed to configure blacklists (error={str(e)})')
        # Set defaults for graceful degradation
        app.config['NETSCOPE_BLACKLIST_STATS'] = None


def _configure_degradation(app):
    """Initialize graceful degradation monitoring.

    Sets up ResourceMonitor and GracefulDegradationManager,
    wires callbacks, and starts the monitoring daemon thread.

    Args:
        app: Flask application instance
    """
    from app.services.resource_monitor import get_resource_monitor
    from app.services.graceful_degradation import get_degradation_manager
    from app.services.performance_config import get_current_targets

    try:
        targets = get_current_targets()
        sample_interval = 5
        degradation_samples = targets.degradation_window_seconds // sample_interval
        recovery_samples = targets.recovery_window_seconds // sample_interval
        critical_samples = targets.critical_window_seconds // sample_interval

        monitor = get_resource_monitor()
        monitor.configure(
            degradation_threshold=targets.degradation_cpu_threshold,
            recovery_threshold=targets.recovery_cpu_threshold,
            critical_threshold=targets.critical_cpu_threshold,
            degradation_samples=degradation_samples,
            recovery_samples=recovery_samples,
            critical_samples=critical_samples,
        )

        degradation = get_degradation_manager()
        monitor.set_callbacks(
            on_degradation_enter=degradation.on_degradation_enter,
            on_degradation_exit=degradation.on_degradation_exit,
            on_critical_overload=degradation.on_critical_overload,
        )

        monitor.start()

        app.logger.info(
            'Degradation monitoring configured '
            '(thresholds: degrade=%d%%, recover=%d%%, critical=%d%%)',
            targets.degradation_cpu_threshold,
            targets.recovery_cpu_threshold,
            targets.critical_cpu_threshold,
        )

    except Exception as e:
        app.logger.error(
            'Failed to configure degradation monitoring (error=%s)', str(e)
        )


def _register_blueprints(app):
    """Register all application blueprints.

    Args:
        app: Flask application instance
    """
    from app.blueprints.dashboard import dashboard_bp
    from app.blueprints.api import api_bp
    from app.blueprints.admin import admin_bp
    from app.blueprints.captive import captive_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(captive_bp, url_prefix='/captive')


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

    @app.context_processor
    def inject_blacklist_info():
        """Inject blacklist statistics into all templates.

        Provides the following template variables:
        - blacklist_ips_count: Number of blacklisted IPs
        - blacklist_domains_count: Number of blacklisted domains
        - blacklist_terms_count: Number of suspect terms
        - blacklist_total_entries: Total number of entries

        Reads live stats from BlacklistManager singleton to reflect
        user additions/removals in real-time (fix: was using stale startup snapshot).
        """
        try:
            from app.core.detection.blacklist_manager import get_blacklist_manager
            manager = get_blacklist_manager()
            stats = manager.get_stats()
            return {
                'blacklist_ips_count': stats.ips_count,
                'blacklist_domains_count': stats.domains_count,
                'blacklist_terms_count': stats.terms_count,
                'blacklist_total_entries': stats.ips_count + stats.domains_count + stats.terms_count,
            }
        except Exception:
            return {
                'blacklist_ips_count': 0,
                'blacklist_domains_count': 0,
                'blacklist_terms_count': 0,
                'blacklist_total_entries': 0,
            }
