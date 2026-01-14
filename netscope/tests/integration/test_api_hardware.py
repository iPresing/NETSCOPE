"""Integration tests for hardware API endpoint."""

import pytest
from unittest.mock import patch

from app.services.hardware_detection import (
    PiModel,
    HardwareInfo,
    reset_hardware_info,
)
from app.services.performance_config import (
    PerformanceTargets,
    reset_performance_targets,
)
from app.services.thread_manager import reset_thread_manager


@pytest.fixture(autouse=True)
def reset_services():
    """Reset all service singletons before and after each test."""
    reset_hardware_info()
    reset_performance_targets()
    reset_thread_manager()
    yield
    reset_hardware_info()
    reset_performance_targets()
    reset_thread_manager()


class TestApiHardwareEndpoint:
    """Integration tests for GET /api/hardware endpoint."""

    def test_get_hardware_returns_200(self, client):
        """Test GET /api/hardware returns 200 status."""
        response = client.get('/api/hardware')

        assert response.status_code == 200

    def test_get_hardware_returns_json(self, client):
        """Test GET /api/hardware returns JSON content type."""
        response = client.get('/api/hardware')

        assert response.content_type == 'application/json'

    def test_get_hardware_has_success_field(self, client):
        """Test GET /api/hardware response has success field."""
        response = client.get('/api/hardware')
        data = response.get_json()

        assert 'success' in data
        assert data['success'] is True

    def test_get_hardware_has_hardware_section(self, client):
        """Test GET /api/hardware response has hardware section."""
        response = client.get('/api/hardware')
        data = response.get_json()

        assert 'hardware' in data
        hardware = data['hardware']

        assert 'model' in hardware
        assert 'model_code' in hardware
        assert 'cpu_count' in hardware
        assert 'ram_mb' in hardware
        assert 'cpu_max_mhz' in hardware

    def test_get_hardware_has_performance_targets_section(self, client):
        """Test GET /api/hardware response has performance_targets section."""
        response = client.get('/api/hardware')
        data = response.get_json()

        assert 'performance_targets' in data
        targets = data['performance_targets']

        assert 'cpu_threshold_percent' in targets
        assert 'ram_threshold_percent' in targets
        assert 'max_concurrent_jobs' in targets

    def test_get_hardware_values_are_integers(self, client):
        """Test GET /api/hardware numeric values are integers."""
        response = client.get('/api/hardware')
        data = response.get_json()

        hardware = data['hardware']
        assert isinstance(hardware['cpu_count'], int)
        assert isinstance(hardware['ram_mb'], int)
        assert isinstance(hardware['cpu_max_mhz'], int)

        targets = data['performance_targets']
        assert isinstance(targets['cpu_threshold_percent'], int)
        assert isinstance(targets['ram_threshold_percent'], int)
        assert isinstance(targets['max_concurrent_jobs'], int)

    def test_get_hardware_model_code_is_valid_enum(self, client):
        """Test GET /api/hardware model_code is a valid PiModel value."""
        response = client.get('/api/hardware')
        data = response.get_json()

        valid_codes = [m.value for m in PiModel]
        assert data['hardware']['model_code'] in valid_codes

    def test_get_hardware_targets_are_reasonable(self, client):
        """Test GET /api/hardware targets have reasonable values."""
        response = client.get('/api/hardware')
        data = response.get_json()

        targets = data['performance_targets']

        # CPU threshold should be percentage (1-100)
        assert 1 <= targets['cpu_threshold_percent'] <= 100

        # RAM threshold should be percentage (1-100)
        assert 1 <= targets['ram_threshold_percent'] <= 100

        # Max concurrent jobs should be at least 1
        assert targets['max_concurrent_jobs'] >= 1

    def test_get_hardware_hardware_values_are_reasonable(self, client):
        """Test GET /api/hardware hardware values are reasonable."""
        response = client.get('/api/hardware')
        data = response.get_json()

        hardware = data['hardware']

        # CPU count should be at least 1
        assert hardware['cpu_count'] >= 1

        # RAM should be at least 256MB (even for development env)
        assert hardware['ram_mb'] >= 256 or hardware['model_code'] == 'UNKNOWN'

        # CPU MHz should be at least 700 (Pi specs)
        assert hardware['cpu_max_mhz'] >= 700 or hardware['model_code'] == 'UNKNOWN'


class TestApiHardwareConsistency:
    """Tests for hardware API response consistency."""

    def test_multiple_requests_return_same_data(self, client):
        """Test multiple requests return identical data (singleton)."""
        response1 = client.get('/api/hardware')
        response2 = client.get('/api/hardware')

        data1 = response1.get_json()
        data2 = response2.get_json()

        assert data1 == data2

    def test_targets_match_model(self, client):
        """Test performance targets are appropriate for detected model."""
        response = client.get('/api/hardware')
        data = response.get_json()

        model_code = data['hardware']['model_code']
        targets = data['performance_targets']

        # Map expected ranges for each model
        expected_ranges = {
            'PI_ZERO_2_W': {'cpu': (25, 35), 'jobs': (1, 1)},
            'PI_3_B': {'cpu': (15, 25), 'jobs': (1, 2)},
            'PI_4_B': {'cpu': (10, 20), 'jobs': (2, 2)},
            'PI_5': {'cpu': (5, 15), 'jobs': (2, 2)},
            'UNKNOWN': {'cpu': (25, 35), 'jobs': (1, 1)},
        }

        if model_code in expected_ranges:
            ranges = expected_ranges[model_code]
            assert ranges['cpu'][0] <= targets['cpu_threshold_percent'] <= ranges['cpu'][1]
            assert ranges['jobs'][0] <= targets['max_concurrent_jobs'] <= ranges['jobs'][1]


class TestApiHardwareWithMockedDetection:
    """Tests with mocked hardware detection for specific scenarios."""

    def test_pi_4_detection(self, app):
        """Test API response with Pi 4 detection mocked."""
        mock_hardware = HardwareInfo(
            model=PiModel.PI_4_B,
            model_name="Raspberry Pi 4 Model B Rev 1.4",
            cpu_count=4,
            ram_mb=4096,
            cpu_max_mhz=1800,
        )
        mock_targets = PerformanceTargets(
            cpu_threshold_percent=15,
            ram_threshold_percent=20,
            max_concurrent_jobs=2,
        )

        app.config['NETSCOPE_HARDWARE_INFO'] = mock_hardware
        app.config['NETSCOPE_PERFORMANCE_TARGETS'] = mock_targets

        with app.test_client() as client:
            response = client.get('/api/hardware')
            data = response.get_json()

        assert data['success'] is True
        assert data['hardware']['model_code'] == 'PI_4_B'
        assert data['hardware']['model'] == "Raspberry Pi 4 Model B Rev 1.4"
        assert data['hardware']['cpu_count'] == 4
        assert data['hardware']['ram_mb'] == 4096
        assert data['performance_targets']['cpu_threshold_percent'] == 15
        assert data['performance_targets']['max_concurrent_jobs'] == 2

    def test_pi_zero_detection(self, app):
        """Test API response with Pi Zero 2 W detection mocked."""
        mock_hardware = HardwareInfo(
            model=PiModel.PI_ZERO_2_W,
            model_name="Raspberry Pi Zero 2 W Rev 1.0",
            cpu_count=4,
            ram_mb=512,
            cpu_max_mhz=1000,
        )
        mock_targets = PerformanceTargets(
            cpu_threshold_percent=30,
            ram_threshold_percent=30,
            max_concurrent_jobs=1,
        )

        app.config['NETSCOPE_HARDWARE_INFO'] = mock_hardware
        app.config['NETSCOPE_PERFORMANCE_TARGETS'] = mock_targets

        with app.test_client() as client:
            response = client.get('/api/hardware')
            data = response.get_json()

        assert data['success'] is True
        assert data['hardware']['model_code'] == 'PI_ZERO_2_W'
        assert data['hardware']['ram_mb'] == 512
        assert data['performance_targets']['cpu_threshold_percent'] == 30
        assert data['performance_targets']['max_concurrent_jobs'] == 1

    def test_detection_failure_returns_500(self, app):
        """Test API returns 500 when detection has failed."""
        app.config['NETSCOPE_HARDWARE_INFO'] = None
        app.config['NETSCOPE_PERFORMANCE_TARGETS'] = None

        with app.test_client() as client:
            response = client.get('/api/hardware')
            data = response.get_json()

        assert response.status_code == 500
        assert data['success'] is False
        assert 'error' in data
        assert data['error']['code'] == 'HARDWARE_DETECTION_FAILED'


class TestApiHardwareJsonFormat:
    """Tests for JSON format compliance."""

    def test_snake_case_keys(self, client):
        """Test all JSON keys use snake_case convention."""
        response = client.get('/api/hardware')
        data = response.get_json()

        def check_snake_case(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    # Check key is snake_case (no camelCase)
                    assert key == key.lower() or key.isupper(), \
                        f"Key '{key}' at {path} is not snake_case"
                    check_snake_case(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_snake_case(item, f"{path}[{i}]")

        check_snake_case(data)

    def test_response_structure_matches_spec(self, client):
        """Test response matches documented API spec structure."""
        response = client.get('/api/hardware')
        data = response.get_json()

        # Expected structure from story spec
        expected_hardware_keys = {'model', 'model_code', 'cpu_count', 'ram_mb', 'cpu_max_mhz'}
        expected_targets_keys = {'cpu_threshold_percent', 'ram_threshold_percent', 'max_concurrent_jobs'}

        assert set(data['hardware'].keys()) == expected_hardware_keys
        assert set(data['performance_targets'].keys()) == expected_targets_keys
