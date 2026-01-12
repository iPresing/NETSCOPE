"""Pytest fixtures for NETSCOPE tests."""

import pytest

from app import create_app


@pytest.fixture
def app():
    """Create application for testing.

    Returns:
        Flask: Application configured for testing
    """
    app = create_app('testing')
    yield app


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
