"""Unit tests for NETSCOPE application factory."""

import pytest
from flask import Flask

from app import create_app
from app.config import config


class TestCreateApp:
    """Tests for create_app function."""

    def test_create_app_returns_flask_instance(self):
        """Test that create_app returns a Flask application."""
        app = create_app('testing')
        assert isinstance(app, Flask)

    def test_create_app_default_config(self):
        """Test that default config is loaded when no config specified."""
        app = create_app()
        assert app is not None
        assert isinstance(app, Flask)

    def test_create_app_testing_config(self):
        """Test that testing config sets TESTING to True."""
        app = create_app('testing')
        assert app.config['TESTING'] is True
        assert app.config['DEBUG'] is False

    def test_create_app_development_config(self):
        """Test that development config sets DEBUG to True."""
        app = create_app('development')
        assert app.config['DEBUG'] is True
        assert app.config['TESTING'] is False

    def test_create_app_production_config(self):
        """Test that production config disables DEBUG and TESTING."""
        app = create_app('production')
        assert app.config['DEBUG'] is False
        assert app.config['TESTING'] is False


class TestHealthEndpoint:
    """Tests for /api/health endpoint."""

    def test_health_endpoint_returns_200(self, client):
        """Test that health endpoint returns 200 OK."""
        response = client.get('/api/health')
        assert response.status_code == 200

    def test_health_endpoint_returns_json(self, client):
        """Test that health endpoint returns JSON response."""
        response = client.get('/api/health')
        assert response.content_type == 'application/json'

    def test_health_endpoint_returns_ok_status(self, client):
        """Test that health endpoint returns status ok."""
        response = client.get('/api/health')
        data = response.get_json()
        assert data['status'] == 'ok'

    def test_health_endpoint_returns_version(self, client):
        """Test that health endpoint returns version."""
        response = client.get('/api/health')
        data = response.get_json()
        assert 'version' in data
        assert data['version'] == '0.1.0'


class TestConfigClasses:
    """Tests for configuration classes."""

    def test_config_dict_contains_all_environments(self):
        """Test that config dict has all environment keys."""
        assert 'development' in config
        assert 'testing' in config
        assert 'production' in config
        assert 'default' in config

    def test_all_configs_have_secret_key(self):
        """Test that all configs have SECRET_KEY."""
        for config_name in ['development', 'testing', 'production']:
            app = create_app(config_name)
            assert app.config['SECRET_KEY'] is not None
