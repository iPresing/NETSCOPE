"""Pytest fixtures for NETSCOPE tests."""

import os
import sys

# Scapy sur Windows cherche %ProgramFiles% absent dans Git Bash
if sys.platform == 'win32' and 'ProgramFiles' not in os.environ:
    os.environ['ProgramFiles'] = os.environ.get('PROGRAMFILES', 'C:\\Program Files')

import pytest

from app import create_app
from app.core.inspection.job_queue import reset_job_queue
from app.services.whitelist_manager import reset_whitelist_manager
from app.services.resource_monitor import reset_resource_monitor
from app.services.graceful_degradation import reset_degradation_manager
from app.blueprints.captive.captive_manager import reset_captive_manager


@pytest.fixture
def app():
    """Create application for testing.

    Returns:
        Flask: Application configured for testing
    """
    reset_whitelist_manager()
    reset_job_queue()
    reset_resource_monitor()
    reset_degradation_manager()
    reset_captive_manager()
    app = create_app('testing')
    yield app
    reset_whitelist_manager()
    reset_job_queue()
    reset_resource_monitor()
    reset_degradation_manager()
    reset_captive_manager()


@pytest.fixture
def client(app):
    """Create test client.

    Args:
        app: Flask application fixture

    Returns:
        FlaskClient: Test client for making requests
    """
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create test CLI runner.

    Args:
        app: Flask application fixture

    Returns:
        FlaskCliRunner: CLI runner for testing commands
    """
    return app.test_cli_runner()
