"""Integration tests for health score calculation.

Story 3.1: Calcul Score Santé Réseau (FR16, NFR11)
Tests integration with:
- Real AnomalyCollection from detection flow
- Complete capture analysis flow
- JSON serialization for API responses
"""

from datetime import datetime

import pytest

from app.core.analysis.health_score import (
    HealthScoreCalculator,
    get_health_calculator,
    reset_health_calculator,
)
from app.models.anomaly import (
    Anomaly,
    AnomalyCollection,
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
)
from app.models.health_score import HealthScoreResult


@pytest.fixture(autouse=True)
def reset_calculator():
    """Reset singleton before each test."""
    reset_health_calculator()
    yield
    reset_health_calculator()


def _create_realistic_anomaly(
    anomaly_id: str,
    match_type: MatchType,
    matched_value: str,
    source_file: str,
    criticality: CriticalityLevel,
    capture_id: str = "capture_001",
) -> Anomaly:
    """Create a realistic anomaly with full details."""
    match = BlacklistMatch(
        match_type=match_type,
        matched_value=matched_value,
        source_file=source_file,
        context=f"Detected {match_type.value}: {matched_value}",
        criticality=criticality,
        timestamp=datetime.now(),
    )

    score = 85 if criticality == CriticalityLevel.CRITICAL else 65

    return Anomaly(
        id=anomaly_id,
        match=match,
        score=score,
        packet_info={
            "ip_src": "192.168.1.100",
            "ip_dst": matched_value if match_type == MatchType.IP else "8.8.8.8",
            "port_src": 54321,
            "port_dst": 4444 if match_type == MatchType.IP else 80,
            "protocol": "TCP",
        },
        criticality_level=criticality,
        capture_id=capture_id,
        created_at=datetime.now(),
    )


class TestHealthScoreWithRealAnomalyCollection:
    """Test health score with realistic AnomalyCollection objects."""

    def test_integration_with_real_anomaly_collection(self):
        """AC1-3: Calculate score with a realistic anomaly collection."""
        # Create collection mimicking real detection output
        collection = AnomalyCollection(
            anomalies=[
                _create_realistic_anomaly(
                    "anomaly_001",
                    MatchType.IP,
                    "185.220.101.1",  # Known malicious IP
                    "ips_c2.txt",
                    CriticalityLevel.CRITICAL,
                ),
                _create_realistic_anomaly(
                    "anomaly_002",
                    MatchType.DOMAIN,
                    "evil.example.com",
                    "domains_malware.txt",
                    CriticalityLevel.CRITICAL,
                ),
                _create_realistic_anomaly(
                    "anomaly_003",
                    MatchType.TERM,
                    "password",
                    "terms_suspect.txt",
                    CriticalityLevel.WARNING,
                ),
            ],
            capture_id="capture_001",
            analyzed_at=datetime.now(),
        )

        calculator = get_health_calculator()
        result = calculator.calculate(collection)

        # 2 critical (-30) + 1 warning (-5) = 100 - 35 = 65
        assert result.displayed_score == 65
        assert result.real_score == 65
        assert result.critical_count == 2
        assert result.warning_count == 1
        assert result.whitelist_hits == 0

    def test_integration_with_complete_capture(self):
        """Test with a complete capture simulation."""
        # Simulate capture with multiple anomaly types
        collection = AnomalyCollection(
            anomalies=[
                # C2 communication detected
                _create_realistic_anomaly(
                    "anomaly_c2_1",
                    MatchType.IP,
                    "203.0.113.50",
                    "ips_c2.txt",
                    CriticalityLevel.CRITICAL,
                ),
                # Phishing domain access
                _create_realistic_anomaly(
                    "anomaly_phish_1",
                    MatchType.DOMAIN,
                    "login-secure-bank.com",
                    "domains_phishing.txt",
                    CriticalityLevel.CRITICAL,
                ),
                # Suspicious term in traffic
                _create_realistic_anomaly(
                    "anomaly_term_1",
                    MatchType.TERM,
                    "cmd.exe",
                    "terms_suspect.txt",
                    CriticalityLevel.WARNING,
                ),
                _create_realistic_anomaly(
                    "anomaly_term_2",
                    MatchType.TERM,
                    "powershell",
                    "terms_suspect.txt",
                    CriticalityLevel.WARNING,
                ),
            ],
            capture_id="capture_full_test",
            analyzed_at=datetime.now(),
        )

        calculator = HealthScoreCalculator()
        result = calculator.calculate(collection)

        # 2 critical (-30) + 2 warning (-10) = 100 - 40 = 60
        assert result.displayed_score == 60
        assert result.get_status_color() == "warning"

    def test_integration_json_serialization(self):
        """AC: Verify JSON serialization works correctly."""
        collection = AnomalyCollection(anomalies=[
            _create_realistic_anomaly(
                "anomaly_json_test",
                MatchType.IP,
                "1.2.3.4",
                "ips.txt",
                CriticalityLevel.CRITICAL,
            ),
        ])

        calculator = get_health_calculator()
        result = calculator.calculate(collection)
        json_data = result.to_dict()

        # Verify all expected keys exist
        assert "displayed_score" in json_data
        assert "real_score" in json_data
        assert "base_score" in json_data
        assert "critical_count" in json_data
        assert "warning_count" in json_data
        assert "whitelist_hits" in json_data
        assert "whitelist_impact" in json_data
        assert "status_color" in json_data

        # Verify values are correct types (for JSON compatibility)
        assert isinstance(json_data["displayed_score"], int)
        assert isinstance(json_data["real_score"], int)
        assert isinstance(json_data["status_color"], str)

    def test_integration_with_whitelist_flow(self):
        """AC4: Test whitelist integration with real anomaly IDs."""
        collection = AnomalyCollection(
            anomalies=[
                _create_realistic_anomaly(
                    "known_false_positive",
                    MatchType.IP,
                    "192.0.2.1",  # Known test IP - false positive
                    "ips.txt",
                    CriticalityLevel.CRITICAL,
                ),
                _create_realistic_anomaly(
                    "real_threat",
                    MatchType.IP,
                    "185.220.100.240",
                    "ips_c2.txt",
                    CriticalityLevel.CRITICAL,
                ),
                _create_realistic_anomaly(
                    "benign_term",
                    MatchType.TERM,
                    "password",  # False positive in this context
                    "terms.txt",
                    CriticalityLevel.WARNING,
                ),
            ],
            capture_id="whitelist_test",
        )

        calculator = get_health_calculator()

        # Whitelist the false positives
        whitelisted = {"known_false_positive", "benign_term"}
        result = calculator.calculate(collection, whitelisted_ids=whitelisted)

        # Displayed: only 1 critical = 100 - 15 = 85
        assert result.displayed_score == 85
        # Real: 2 critical + 1 warning = 100 - 30 - 5 = 65
        assert result.real_score == 65
        assert result.whitelist_hits == 2
        # Impact: 65 - 85 = -20 (negative = whitelist improves displayed score)
        assert result.whitelist_impact == -20

    def test_integration_healthy_network_simulation(self):
        """AC2: Healthy network simulation returns score > 90."""
        # Empty collection = healthy network
        collection = AnomalyCollection(
            anomalies=[],
            capture_id="healthy_network",
            analyzed_at=datetime.now(),
        )

        calculator = get_health_calculator()
        result = calculator.calculate(collection)

        assert result.displayed_score == 100
        assert result.displayed_score > 90  # AC2
        assert result.get_status_color() == "normal"

    def test_integration_compromised_network_simulation(self):
        """AC3: Compromised network with reverse shell has score < 40."""
        # Simulate reverse shell detection (port 4444 blacklisted)
        collection = AnomalyCollection(
            anomalies=[
                _create_realistic_anomaly(
                    "reverse_shell_1",
                    MatchType.IP,
                    "attacker.evil.com",
                    "ips_c2.txt",
                    CriticalityLevel.CRITICAL,
                ),
                _create_realistic_anomaly(
                    "reverse_shell_2",
                    MatchType.TERM,
                    "meterpreter",
                    "terms_suspect.txt",
                    CriticalityLevel.CRITICAL,
                ),
                _create_realistic_anomaly(
                    "reverse_shell_3",
                    MatchType.TERM,
                    "reverse_shell",
                    "terms_suspect.txt",
                    CriticalityLevel.CRITICAL,
                ),
                _create_realistic_anomaly(
                    "reverse_shell_4",
                    MatchType.IP,
                    "192.0.2.100",
                    "ips_c2.txt",
                    CriticalityLevel.CRITICAL,
                ),
                _create_realistic_anomaly(
                    "reverse_shell_5",
                    MatchType.DOMAIN,
                    "c2.attacker.net",
                    "domains_malware.txt",
                    CriticalityLevel.CRITICAL,
                ),
            ],
            capture_id="compromised",
        )

        calculator = get_health_calculator()
        result = calculator.calculate(collection)

        # 5 critical = 100 - 75 = 25
        assert result.displayed_score == 25
        assert result.displayed_score < 40  # AC3
        assert result.get_status_color() == "critical"

    def test_integration_by_criticality_consistency(self):
        """Verify consistency with AnomalyCollection.by_criticality."""
        collection = AnomalyCollection(
            anomalies=[
                _create_realistic_anomaly("c1", MatchType.IP, "1.1.1.1", "ips.txt", CriticalityLevel.CRITICAL),
                _create_realistic_anomaly("c2", MatchType.IP, "2.2.2.2", "ips.txt", CriticalityLevel.CRITICAL),
                _create_realistic_anomaly("w1", MatchType.TERM, "test", "terms.txt", CriticalityLevel.WARNING),
            ]
        )

        # Get counts from AnomalyCollection
        by_crit = collection.by_criticality

        # Calculate health score
        calculator = get_health_calculator()
        result = calculator.calculate(collection)

        # Verify counts match
        assert result.critical_count == by_crit["critical"]
        assert result.warning_count == by_crit["warning"]
