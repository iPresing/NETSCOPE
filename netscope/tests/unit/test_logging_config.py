"""Unit tests for logging_config module."""

import logging
import pytest

from app.logging_config import NetScopeFormatter


class TestNetScopeFormatterShortName:
    """Tests for _get_short_name transformation."""

    def setup_method(self):
        """Create formatter instance for each test."""
        self.formatter = NetScopeFormatter()

    def test_removes_app_prefix(self):
        """Test that 'app.' prefix is removed."""
        assert self.formatter._get_short_name('app.services.hardware_detection') == 'services.hardware_detection'

    def test_removes_app_and_blueprints_prefix(self):
        """Test that 'app.blueprints.' is collapsed to just the blueprint name."""
        assert self.formatter._get_short_name('app.blueprints.api.routes') == 'api.routes'
        assert self.formatter._get_short_name('app.blueprints.dashboard.views') == 'dashboard.views'
        assert self.formatter._get_short_name('app.blueprints.admin.routes') == 'admin.routes'

    def test_removes_core_prefix(self):
        """Test that 'core.' prefix is removed."""
        assert self.formatter._get_short_name('app.core.capture.tcpdump') == 'capture.tcpdump'
        assert self.formatter._get_short_name('app.core.analysis.scoring') == 'analysis.scoring'
        assert self.formatter._get_short_name('app.core.detection.blacklist') == 'detection.blacklist'

    def test_removes_manager_suffix(self):
        """Test that '_manager' suffix is stripped."""
        assert self.formatter._get_short_name('app.core.capture.tcpdump_manager') == 'capture.tcpdump'
        assert self.formatter._get_short_name('app.services.thread_manager') == 'services.thread'

    def test_removes_inspector_suffix(self):
        """Test that '_inspector' suffix is stripped."""
        assert self.formatter._get_short_name('app.core.inspection.scapy_inspector') == 'inspection.scapy'

    def test_removes_handler_suffix(self):
        """Test that '_handler' suffix is stripped."""
        assert self.formatter._get_short_name('app.blueprints.api.error_handler') == 'api.error'

    def test_removes_service_suffix(self):
        """Test that '_service' suffix is stripped."""
        assert self.formatter._get_short_name('app.services.auth_service') == 'services.auth'

    def test_preserves_name_without_app_prefix(self):
        """Test that names without 'app.' prefix are handled."""
        assert self.formatter._get_short_name('external.module') == 'external.module'
        assert self.formatter._get_short_name('werkzeug.serving') == 'werkzeug.serving'

    def test_handles_simple_names(self):
        """Test that simple names without dots are handled."""
        # 'app' alone (no dot) stays as 'app' - edge case, unlikely in practice
        assert self.formatter._get_short_name('app') == 'app'
        assert self.formatter._get_short_name('root') == 'root'
        assert self.formatter._get_short_name('__main__') == '__main__'


class TestNetScopeFormatterFormat:
    """Tests for log record formatting."""

    def setup_method(self):
        """Create formatter instance for each test."""
        self.formatter = NetScopeFormatter()

    def test_format_includes_short_name(self):
        """Test that formatted output includes the short module name."""
        record = logging.LogRecord(
            name='app.services.hardware_detection',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='Test message',
            args=(),
            exc_info=None,
        )

        formatted = self.formatter.format(record)

        assert '[services.hardware_detection]' in formatted
        assert 'Test message' in formatted
        assert '[INFO]' in formatted

    def test_format_with_blueprint_module(self):
        """Test formatting for blueprint modules."""
        record = logging.LogRecord(
            name='app.blueprints.api.routes',
            level=logging.WARNING,
            pathname='',
            lineno=0,
            msg='API warning',
            args=(),
            exc_info=None,
        )

        formatted = self.formatter.format(record)

        assert '[api.routes]' in formatted
        assert '[WARNING]' in formatted

    def test_format_with_core_module(self):
        """Test formatting for core modules."""
        record = logging.LogRecord(
            name='app.core.capture.tcpdump_manager',
            level=logging.DEBUG,
            pathname='',
            lineno=0,
            msg='Capture started',
            args=(),
            exc_info=None,
        )

        formatted = self.formatter.format(record)

        assert '[capture.tcpdump]' in formatted
        assert '[DEBUG]' in formatted

    def test_format_includes_timestamp(self):
        """Test that formatted output includes timestamp."""
        record = logging.LogRecord(
            name='app.services.test',
            level=logging.INFO,
            pathname='',
            lineno=0,
            msg='Test',
            args=(),
            exc_info=None,
        )

        formatted = self.formatter.format(record)

        # Should have format like [2026-01-15 10:00:00]
        assert '[20' in formatted  # Year starts with 20
        assert '][' in formatted  # Separator between timestamp and level


class TestNetScopeFormatterArchitectureCompliance:
    """Tests verifying compliance with architecture logging standard."""

    def setup_method(self):
        """Create formatter instance for each test."""
        self.formatter = NetScopeFormatter()

    def test_services_hardware_detection_format(self):
        """Test architecture example: services.hardware_detection."""
        short_name = self.formatter._get_short_name('app.services.hardware_detection')
        assert short_name == 'services.hardware_detection'

    def test_capture_tcpdump_format(self):
        """Test architecture example: capture.tcpdump."""
        short_name = self.formatter._get_short_name('app.core.capture.tcpdump_manager')
        assert short_name == 'capture.tcpdump'

    def test_analysis_scoring_format(self):
        """Test architecture example: analysis.scoring."""
        short_name = self.formatter._get_short_name('app.core.analysis.scoring')
        assert short_name == 'analysis.scoring'

    def test_inspection_scapy_format(self):
        """Test architecture example: inspection.scapy."""
        short_name = self.formatter._get_short_name('app.core.inspection.scapy_inspector')
        assert short_name == 'inspection.scapy'

    def test_api_routes_format(self):
        """Test architecture example: api.routes."""
        short_name = self.formatter._get_short_name('app.blueprints.api.routes')
        assert short_name == 'api.routes'
