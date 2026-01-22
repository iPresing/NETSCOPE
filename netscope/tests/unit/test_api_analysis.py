"""Unit tests for Analysis API endpoints.

Tests the /api/analysis/four-essentials endpoint.

Story 2.6: Dashboard 4 Cartes Status
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from app.models.capture import (
    CaptureResult,
    CaptureSession,
    CaptureConfig,
    CaptureStatus,
    CaptureSummary,
)
from app.core.analysis.four_essentials import (
    FourEssentialsResult,
    EssentialAnalysis,
    AnalysisStatus,
    reset_four_essentials_analyzer,
)


@pytest.fixture(autouse=True)
def reset_analyzer():
    """Reset FourEssentialsAnalyzer singleton before and after each test."""
    reset_four_essentials_analyzer()
    yield
    reset_four_essentials_analyzer()


@pytest.fixture
def capture_session():
    """Create a sample capture session."""
    return CaptureSession(
        id="cap_20260123_150000",
        config=CaptureConfig(duration=120),
        status=CaptureStatus.COMPLETED,
        start_time=datetime.now(),
    )


@pytest.fixture
def normal_summary():
    """Create a normal capture summary."""
    return CaptureSummary(
        total_packets=100,
        total_bytes=50000,
        unique_ips=5,
        unique_ports=10,
        protocols={"TCP": 70, "UDP": 25, "ICMP": 5},
        top_ips=[
            ("192.168.1.10", 50),
            ("192.168.1.20", 30),
            ("192.168.1.1", 20),
        ],
        top_ports=[
            (80, 40),
            (443, 35),
            (53, 15),
            (22, 10),
        ],
        bytes_per_protocol={"TCP": 35000, "UDP": 12500, "ICMP": 2500},
        duration_actual=60.0,
    )


@pytest.fixture
def capture_result(capture_session, normal_summary):
    """Create a normal capture result."""
    return CaptureResult(
        session=capture_session,
        packets=[],
        summary=normal_summary,
    )


class TestGetFourEssentials:
    """Test GET /api/analysis/four-essentials endpoint."""

    def test_four_essentials_no_capture(self, client):
        """Test endpoint returns null when no capture available."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            mock_manager.return_value.get_latest_result.return_value = None

            response = client.get('/api/analysis/four-essentials')

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True
            assert data['result'] is None
            assert 'Aucune capture disponible' in data['message']

    def test_four_essentials_with_capture(self, client, capture_result):
        """Test endpoint returns FourEssentialsResult when capture exists."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')

                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] is True
                assert data['result'] is not None

                # Verify structure
                result = data['result']
                assert 'capture_id' in result
                assert 'top_ips' in result
                assert 'protocols' in result
                assert 'ports' in result
                assert 'volume' in result
                assert 'overall_status' in result
                assert 'overall_indicator' in result

    def test_four_essentials_response_structure(self, client, capture_result):
        """Test four essentials response has correct structure."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')
                data = json.loads(response.data)

                result = data['result']

                # Check each analysis section
                for section in ['top_ips', 'protocols', 'ports', 'volume']:
                    assert 'name' in result[section]
                    assert 'title' in result[section]
                    assert 'status' in result[section]
                    assert 'indicator' in result[section]
                    assert 'data' in result[section]
                    assert 'message' in result[section]
                    assert 'details' in result[section]

                    # Status should be valid enum value
                    assert result[section]['status'] in ['critical', 'warning', 'normal']

    def test_four_essentials_top_ips_data(self, client, capture_result):
        """Test top_ips data includes expected fields."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')
                data = json.loads(response.data)

                top_ips_data = data['result']['top_ips']['data']
                assert 'ips' in top_ips_data
                assert 'total_unique' in top_ips_data
                assert 'blacklisted_count' in top_ips_data

                # Check IP structure if available
                if len(top_ips_data['ips']) > 0:
                    ip_info = top_ips_data['ips'][0]
                    assert 'ip' in ip_info
                    assert 'count' in ip_info
                    assert 'is_external' in ip_info
                    assert 'is_blacklisted' in ip_info

    def test_four_essentials_protocols_data(self, client, capture_result):
        """Test protocols data includes distribution."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')
                data = json.loads(response.data)

                protocols_data = data['result']['protocols']['data']
                assert 'distribution' in protocols_data
                assert 'total_packets' in protocols_data

    def test_four_essentials_ports_data(self, client, capture_result):
        """Test ports data includes expected fields."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')
                data = json.loads(response.data)

                ports_data = data['result']['ports']['data']
                assert 'ports' in ports_data
                assert 'total_unique' in ports_data
                assert 'suspicious_count' in ports_data
                assert 'suspicious_ports' in ports_data

    def test_four_essentials_volume_data(self, client, capture_result):
        """Test volume data includes expected statistics."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')
                data = json.loads(response.data)

                volume_data = data['result']['volume']['data']
                assert 'total_packets' in volume_data
                assert 'total_bytes' in volume_data
                assert 'bytes_in' in volume_data
                assert 'bytes_out' in volume_data
                assert 'ratio' in volume_data

    def test_four_essentials_with_capture_id(self, client, capture_result):
        """Test endpoint with specific capture_id parameter."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials?capture_id=cap_20260123_150000')

                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] is True

    def test_four_essentials_capture_id_not_found(self, client, capture_result):
        """Test endpoint when capture_id doesn't match latest."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            mock_manager.return_value.get_latest_result.return_value = capture_result

            response = client.get('/api/analysis/four-essentials?capture_id=cap_wrong_id')

            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True
            assert data['result'] is None

    def test_four_essentials_error_handling(self, client):
        """Test endpoint handles errors gracefully."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            mock_manager.side_effect = Exception("Test error")

            response = client.get('/api/analysis/four-essentials')

            assert response.status_code == 500
            data = json.loads(response.data)
            assert data['success'] is False
            assert 'error' in data
            assert data['error']['code'] == 'ANALYSIS_ERROR'


class TestFourEssentialsLatestParameter:
    """Test capture_id=latest parameter behavior."""

    def test_latest_is_default(self, client, capture_result):
        """Test that capture_id defaults to latest."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response1 = client.get('/api/analysis/four-essentials')
                response2 = client.get('/api/analysis/four-essentials?capture_id=latest')

                data1 = json.loads(response1.data)
                data2 = json.loads(response2.data)

                assert data1['result'] == data2['result']


class TestFourEssentialsJSON:
    """Test JSON response format compliance."""

    def test_json_format_spec_compliance(self, client, capture_result):
        """Test response matches API spec from story 2.6."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')

                assert response.content_type == 'application/json'
                data = json.loads(response.data)

                # Verify top-level structure
                assert 'success' in data
                assert isinstance(data['success'], bool)
                assert 'result' in data

                result = data['result']
                if result:
                    # Verify capture_id
                    assert isinstance(result['capture_id'], str)

                    # Verify overall fields
                    assert result['overall_status'] in ['critical', 'warning', 'normal']
                    assert result['overall_indicator'] in ['🔴', '🟡', '🟢']

                    # Verify each analysis has indicator emoji
                    for section in ['top_ips', 'protocols', 'ports', 'volume']:
                        assert result[section]['indicator'] in ['🔴', '🟡', '🟢']


class TestFourEssentialsEdgeCases:
    """Test edge cases for four essentials API (Code Review M4)."""

    def test_capture_with_empty_packets(self, client, capture_session):
        """Test API handles capture with empty packets list."""
        from app.models.capture import CaptureResult, CaptureSummary

        empty_summary = CaptureSummary(
            total_packets=0,
            total_bytes=0,
            unique_ips=0,
            unique_ports=0,
            protocols={},
            top_ips=[],
            top_ports=[],
            bytes_per_protocol={},
            duration_actual=0.0,
        )
        empty_result = CaptureResult(
            session=capture_session,
            packets=[],
            summary=empty_summary,
        )

        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = empty_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')

                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] is True
                assert data['result'] is not None
                # Empty capture should still return valid structure
                assert 'top_ips' in data['result']
                assert 'protocols' in data['result']

    def test_capture_running_status(self, client):
        """Test API handles capture with RUNNING status."""
        from app.models.capture import (
            CaptureResult, CaptureSession, CaptureConfig,
            CaptureStatus, CaptureSummary
        )

        running_session = CaptureSession(
            id="cap_running_123",
            config=CaptureConfig(duration=120),
            status=CaptureStatus.RUNNING,
            start_time=datetime.now(),
        )
        partial_summary = CaptureSummary(
            total_packets=50,
            total_bytes=25000,
            unique_ips=3,
            unique_ports=5,
            protocols={"TCP": 50},
            top_ips=[("192.168.1.10", 50)],
            top_ports=[(80, 50)],
            bytes_per_protocol={"TCP": 25000},
            duration_actual=30.0,
        )
        running_result = CaptureResult(
            session=running_session,
            packets=[],
            summary=partial_summary,
        )

        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = running_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')

                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] is True
                # Running capture should still be analyzable
                assert data['result'] is not None

    def test_capture_with_only_summary_no_packets(self, client, capture_session, normal_summary):
        """Test API handles capture with summary but empty packets (normal case)."""
        from app.models.capture import CaptureResult

        result_no_packets = CaptureResult(
            session=capture_session,
            packets=[],  # No packets, just summary
            summary=normal_summary,
        )

        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = result_no_packets
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')

                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] is True
                assert data['result'] is not None

    def test_capture_with_high_volume(self, client, capture_session):
        """Test API handles high volume capture data."""
        from app.models.capture import CaptureResult, CaptureSummary

        high_volume_summary = CaptureSummary(
            total_packets=100000,
            total_bytes=50000000,  # 50 MB
            unique_ips=500,
            unique_ports=200,
            protocols={"TCP": 70000, "UDP": 25000, "ICMP": 5000},
            top_ips=[("192.168.1." + str(i), 1000 - i * 10) for i in range(10)],
            top_ports=[(80 + i, 5000 - i * 100) for i in range(10)],
            bytes_per_protocol={"TCP": 35000000, "UDP": 12500000, "ICMP": 2500000},
            duration_actual=300.0,
        )
        high_volume_result = CaptureResult(
            session=capture_session,
            packets=[],
            summary=high_volume_summary,
        )

        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = high_volume_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')

                assert response.status_code == 200
                data = json.loads(response.data)
                assert data['success'] is True
                assert data['result'] is not None
                # High volume should be reported in data
                assert data['result']['volume']['data']['total_packets'] == 100000
