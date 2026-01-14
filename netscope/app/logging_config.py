"""NETSCOPE logging configuration with custom formatter.

Provides a custom formatter that transforms Python module paths
to short module names following the architecture standard:
[YYYY-MM-DD HH:MM:SS][LEVEL][module.submodule] Message (key=value)

Examples:
    app.services.hardware_detection -> services.hardware_detection
    app.blueprints.api.routes -> api.routes
    app.core.capture.tcpdump_manager -> capture.tcpdump
"""

import logging
import re


class NetScopeFormatter(logging.Formatter):
    """Custom formatter that produces short module names.

    Transforms full Python module paths to short names conforming
    to the NETSCOPE architecture logging standard.
    """

    # Suffixes to remove for cleaner module names
    SUFFIXES_TO_STRIP = ('_manager', '_inspector', '_handler', '_service')

    def __init__(
        self,
        fmt: str = '[%(asctime)s][%(levelname)s][%(shortname)s] %(message)s',
        datefmt: str = '%Y-%m-%d %H:%M:%S',
    ):
        """Initialize the formatter.

        Args:
            fmt: Log format string. Use %(shortname)s for the short module name.
            datefmt: Date format string.
        """
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with short module name.

        Args:
            record: The log record to format.

        Returns:
            Formatted log string.
        """
        # Transform the logger name to short format
        record.shortname = self._get_short_name(record.name)
        return super().format(record)

    def _get_short_name(self, name: str) -> str:
        """Transform full module path to short name.

        Args:
            name: Full Python module path (e.g., 'app.services.hardware_detection')

        Returns:
            Short module name (e.g., 'services.hardware_detection')
        """
        # Remove 'app.' prefix if present
        if name.startswith('app.'):
            name = name[4:]

        # Remove 'blueprints.' from blueprint modules for shorter names
        # app.blueprints.api.routes -> api.routes
        if name.startswith('blueprints.'):
            name = name[11:]

        # Remove common suffixes for cleaner names
        # core.capture.tcpdump_manager -> core.capture.tcpdump
        for suffix in self.SUFFIXES_TO_STRIP:
            if name.endswith(suffix):
                name = name[:-len(suffix)]
                break

        # Remove 'core.' prefix since it's implied
        # core.capture.tcpdump -> capture.tcpdump
        if name.startswith('core.'):
            name = name[5:]

        return name


def configure_logging(app, config_name: str = 'default') -> None:
    """Configure application logging with NETSCOPE formatter.

    Args:
        app: Flask application instance.
        config_name: Configuration name for determining log level.
    """
    # Determine log level
    log_level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO

    # Create formatter
    formatter = NetScopeFormatter()

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add console handler with custom formatter
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Reduce noise from external libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
