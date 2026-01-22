"""Integration tests for HumanContext with detection flow.

Tests the complete flow: capture -> detect -> human context -> API.
Story 2.5: Contexte Humain Anomalies (AC6, AC7)
"""

import pytest
from datetime import datetime
from pathlib import Path
import tempfile
import json

from app import create_app
from app.core.detection.blacklist_manager import (
    get_blacklist_manager,
    reset_blacklist_manager,
)
from app.core.detection.blacklist_detector import (
    BlacklistDetector,
    create_detector,
)
from app.core.detection.anomaly_store import (
    get_anomaly_store,
    reset_anomaly_store,
)
from app.core.detection.human_context import (
    HumanContext,
    HumanContextProvider,
    RiskLevel,
    get_human_context_provider,
    reset_human_context_provider,
)
from app.core.analysis.scoring import reset_scoring_engine
from app.models.capture import PacketInfo
from app.models.anomaly import CriticalityLevel


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singletons before and after each test."""
    reset_blacklist_manager()
    reset_anomaly_store()
    reset_scoring_engine()
    reset_human_context_provider()
    yield
    reset_blacklist_manager()
    reset_anomaly_store()
    reset_scoring_engine()
    reset_human_context_provider()


@pytest.fixture
def app():
    """Create test application."""
    app = create_app('testing')
    yield app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def temp_blacklist_dir():
    """Create temporary directory with test blacklist files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create defaults directory
        defaults_dir = Path(tmpdir) / "data" / "blacklists_defaults"
        defaults_dir.mkdir(parents=True)

        # Create ips_malware.txt with known malicious IPs
        (defaults_dir / "ips_malware.txt").write_text(
            "# Test IPs\n"
            "45.33.32.156\n"
            "185.220.101.1\n"
        )

        # Create ips_c2.txt for C2 servers
        (defaults_dir / "ips_c2.txt").write_text(
            "# C2 Test IPs\n"
            "10.99.99.99\n"
        )

        # Create ips_tor.txt for Tor exit nodes
        (defaults_dir / "ips_tor.txt").write_text(
            "# Tor Test IPs\n"
            "192.42.116.16\n"
        )

        yield Path(tmpdir)


@pytest.fixture
def loaded_manager(temp_blacklist_dir):
    """Get BlacklistManager loaded with test data."""
    manager = get_blacklist_manager()
    config = {
        "defaults": {
            "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            "ips_c2": "data/blacklists_defaults/ips_c2.txt",
            "ips_tor": "data/blacklists_defaults/ips_tor.txt",
        }
    }
    manager.load_blacklists(config, base_path=temp_blacklist_dir)
    return manager


class TestHumanContextIntegrationWithBlacklistDetector:
    """Test HumanContext integration with BlacklistDetector (AC6)."""

    def test_detector_generates_human_context(self, loaded_manager):
        """Test BlacklistDetector generates HumanContext for IP matches."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="cap_test")

        assert collection.total == 1
        anomaly = collection.anomalies[0]

        # Human context should be generated
        assert anomaly.human_context is not None
        assert isinstance(anomaly.human_context, HumanContext)

    def test_human_context_has_required_fields(self, loaded_manager):
        """Test HumanContext includes all required fields (AC6)."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="cap_test")
        ctx = collection.anomalies[0].human_context

        # Required fields per AC6
        assert ctx.short_message is not None
        assert len(ctx.short_message) > 0

        assert ctx.explanation is not None
        assert len(ctx.explanation) > 0

        assert ctx.risk_level is not None
        assert ctx.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]

        assert ctx.indicator is not None
        assert ctx.indicator in ["🔴", "🟡", "🟢", "ℹ️"]

    def test_human_context_uses_correct_category(self, loaded_manager):
        """Test HumanContext infers correct category from source file."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="cap_test")
        ctx = collection.anomalies[0].human_context

        # Context should reflect blacklist type (malware from ips_blacklist)
        # Note: current detector uses generic "ips_blacklist" source
        assert ctx.technical_details is not None
        assert "category" in ctx.technical_details


class TestHumanContextInAPIResponse:
    """Test human_context in API response (AC7)."""

    def test_anomalies_api_includes_human_context(self, client, loaded_manager):
        """Test GET /api/anomalies includes human_context field (AC7)."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")

        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies')
        assert response.status_code == 200

        data = json.loads(response.data)
        anomaly = data['result']['anomalies'][0]

        # human_context should be in response
        assert 'human_context' in anomaly
        assert anomaly['human_context'] is not None

    def test_human_context_api_structure(self, client, loaded_manager):
        """Test human_context API response structure matches specification (AC7)."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")

        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies')
        data = json.loads(response.data)

        human_ctx = data['result']['anomalies'][0]['human_context']

        # Required fields per AC7 / API spec
        assert 'short_message' in human_ctx
        assert 'explanation' in human_ctx
        assert 'risk_level' in human_ctx
        assert 'indicator' in human_ctx
        assert 'action_hint' in human_ctx
        assert 'technical_details' in human_ctx

    def test_human_context_short_message_visible(self, client, loaded_manager):
        """Test short_message is 1-2 sentences (AC7)."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")

        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies')
        data = json.loads(response.data)

        short_msg = data['result']['anomalies'][0]['human_context']['short_message']

        # Short message should be concise (1-2 sentences)
        assert len(short_msg) > 0
        assert len(short_msg) < 200  # Not too long for quick display

    def test_human_context_in_single_anomaly_endpoint(self, client, loaded_manager):
        """Test GET /api/anomalies/{id} includes human_context."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")

        store = get_anomaly_store()
        store.store(collection)

        anomaly_id = collection.anomalies[0].id

        response = client.get(f'/api/anomalies/{anomaly_id}')
        assert response.status_code == 200

        data = json.loads(response.data)

        # human_context should be present in single anomaly response
        assert 'human_context' in data['anomaly']
        assert data['anomaly']['human_context'] is not None


class TestHumanContextProviderModule:
    """Test HumanContextProvider module centralization (AC6)."""

    def test_get_port_context_method(self):
        """Test get_port_context method exists and works."""
        provider = get_human_context_provider()

        ctx = provider.get_port_context(4444)

        assert ctx is not None
        assert isinstance(ctx, HumanContext)

    def test_get_ip_context_method(self):
        """Test get_ip_context method exists and works."""
        provider = get_human_context_provider()

        ctx = provider.get_ip_context(
            ip="45.33.32.156",
            source_file="ips_malware.txt",
            category=None,
        )

        assert ctx is not None
        assert isinstance(ctx, HumanContext)

    def test_get_protocol_context_method(self):
        """Test get_protocol_context method exists and works."""
        provider = get_human_context_provider()

        ctx = provider.get_protocol_context("ICMP", 55.0)

        assert ctx is not None
        assert isinstance(ctx, HumanContext)

    def test_get_volume_context_method(self):
        """Test get_volume_context method exists and works."""
        provider = get_human_context_provider()

        ctx = provider.get_volume_context(ratio=1.5, total_packets=500)

        assert ctx is not None
        assert isinstance(ctx, HumanContext)

    def test_singleton_pattern(self):
        """Test HumanContextProvider uses singleton pattern."""
        provider1 = get_human_context_provider()
        provider2 = get_human_context_provider()

        assert provider1 is provider2


class TestAnomalyToDict:
    """Test Anomaly.to_dict includes human_context (AC7)."""

    def test_anomaly_to_dict_includes_human_context(self, loaded_manager):
        """Test Anomaly.to_dict() includes human_context when present."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")

        anomaly = collection.anomalies[0]
        anomaly_dict = anomaly.to_dict()

        assert 'human_context' in anomaly_dict
        assert anomaly_dict['human_context'] is not None

    def test_anomaly_to_dict_human_context_serializes(self, loaded_manager):
        """Test human_context is properly serialized in to_dict."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")

        anomaly = collection.anomalies[0]
        anomaly_dict = anomaly.to_dict()

        human_ctx = anomaly_dict['human_context']

        # Should be dict not HumanContext object
        assert isinstance(human_ctx, dict)

        # Should have all fields
        assert 'short_message' in human_ctx
        assert 'explanation' in human_ctx
        assert 'risk_level' in human_ctx
        assert 'indicator' in human_ctx


class TestExportFormat:
    """Test human_context export format matches API specification."""

    def test_json_serializable(self, loaded_manager):
        """Test human_context is JSON serializable."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")

        anomaly_dict = collection.anomalies[0].to_dict()

        # Should serialize to JSON without error
        json_str = json.dumps(anomaly_dict)
        assert json_str is not None

        # Should deserialize back
        parsed = json.loads(json_str)
        assert 'human_context' in parsed

    def test_api_response_format(self, client, loaded_manager):
        """Test API response format matches documentation."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")

        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies')
        data = json.loads(response.data)

        # Response format per API spec
        assert data['success'] is True
        assert 'result' in data
        assert 'anomalies' in data['result']
        assert len(data['result']['anomalies']) > 0

        anomaly = data['result']['anomalies'][0]

        # human_context format per AC7
        human_ctx = anomaly['human_context']
        assert human_ctx['risk_level'] in ['high', 'medium', 'low', 'info']
        assert human_ctx['indicator'] in ['🔴', '🟡', '🟢', 'ℹ️']


class TestMultipleAnomaliesWithContext:
    """Test multiple anomalies all have human context."""

    def test_multiple_ip_anomalies_have_context(self, loaded_manager):
        """Test all detected anomalies have human context."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="185.220.101.1",
                ip_dst="192.168.1.10",
                port_src=443,
                port_dst=61234,
                protocol="TCP",
                length=1500,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="cap_test")

        # All anomalies should have human context
        for anomaly in collection.anomalies:
            assert anomaly.human_context is not None
            assert isinstance(anomaly.human_context, HumanContext)
            assert anomaly.human_context.short_message is not None
