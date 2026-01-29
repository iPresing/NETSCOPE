"""Unit tests for health score calculation.

Story 3.1: Calcul Score Santé Réseau (FR16, NFR11)
Tests cover:
- AC1: Score calculation with correct deductions
- AC2: Healthy network (score > 90)
- AC3: Compromised network (score < 40)
- AC4: Whitelist exclusion from displayed score
- AC5: Performance < 3 seconds
"""

import time
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


def _create_anomaly(
    anomaly_id: str,
    criticality: CriticalityLevel = CriticalityLevel.CRITICAL,
) -> Anomaly:
    """Helper to create test anomalies."""
    return Anomaly(
        id=anomaly_id,
        match=BlacklistMatch(
            match_type=MatchType.IP,
            matched_value="1.2.3.4",
            source_file="test.txt",
            context="Test anomaly",
            criticality=criticality,
            timestamp=datetime.now(),
        ),
        score=80 if criticality == CriticalityLevel.CRITICAL else 60,
        criticality_level=criticality,
    )


class TestHealthScoreResultValidation:
    """Tests for HealthScoreResult input validation."""

    def test_invalid_displayed_score_negative(self):
        """Negative displayed_score raises ValueError."""
        with pytest.raises(ValueError, match="displayed_score must be 0-100"):
            HealthScoreResult(displayed_score=-1, real_score=50)

    def test_invalid_displayed_score_over_100(self):
        """displayed_score > 100 raises ValueError."""
        with pytest.raises(ValueError, match="displayed_score must be 0-100"):
            HealthScoreResult(displayed_score=101, real_score=50)

    def test_invalid_real_score_negative(self):
        """Negative real_score raises ValueError."""
        with pytest.raises(ValueError, match="real_score must be 0-100"):
            HealthScoreResult(displayed_score=50, real_score=-5)

    def test_invalid_real_score_over_100(self):
        """real_score > 100 raises ValueError."""
        with pytest.raises(ValueError, match="real_score must be 0-100"):
            HealthScoreResult(displayed_score=50, real_score=150)

    def test_invalid_critical_count_negative(self):
        """Negative critical_count raises ValueError."""
        with pytest.raises(ValueError, match="critical_count must be >= 0"):
            HealthScoreResult(displayed_score=50, real_score=50, critical_count=-1)

    def test_invalid_warning_count_negative(self):
        """Negative warning_count raises ValueError."""
        with pytest.raises(ValueError, match="warning_count must be >= 0"):
            HealthScoreResult(displayed_score=50, real_score=50, warning_count=-1)

    def test_invalid_whitelist_hits_negative(self):
        """Negative whitelist_hits raises ValueError."""
        with pytest.raises(ValueError, match="whitelist_hits must be >= 0"):
            HealthScoreResult(displayed_score=50, real_score=50, whitelist_hits=-1)

    def test_boundary_score_zero_valid(self):
        """Score of 0 is valid."""
        result = HealthScoreResult(displayed_score=0, real_score=0)
        assert result.displayed_score == 0
        assert result.get_status_color() == "critical"

    def test_boundary_score_100_valid(self):
        """Score of 100 is valid."""
        result = HealthScoreResult(displayed_score=100, real_score=100)
        assert result.displayed_score == 100
        assert result.get_status_color() == "normal"

    def test_boundary_score_80_is_normal(self):
        """Score of exactly 80 is 'normal' (boundary)."""
        result = HealthScoreResult(displayed_score=80, real_score=80)
        assert result.get_status_color() == "normal"

    def test_boundary_score_79_is_warning(self):
        """Score of 79 is 'warning' (just below normal threshold)."""
        result = HealthScoreResult(displayed_score=79, real_score=79)
        assert result.get_status_color() == "warning"

    def test_boundary_score_50_is_warning(self):
        """Score of exactly 50 is 'warning' (boundary)."""
        result = HealthScoreResult(displayed_score=50, real_score=50)
        assert result.get_status_color() == "warning"

    def test_boundary_score_49_is_critical(self):
        """Score of 49 is 'critical' (just below warning threshold)."""
        result = HealthScoreResult(displayed_score=49, real_score=49)
        assert result.get_status_color() == "critical"


class TestHealthScoreResult:
    """Tests for HealthScoreResult dataclass."""

    def test_get_status_color_normal(self):
        """Score >= 80 returns 'normal' (green)."""
        result = HealthScoreResult(displayed_score=100, real_score=100)
        assert result.get_status_color() == "normal"

        result = HealthScoreResult(displayed_score=80, real_score=80)
        assert result.get_status_color() == "normal"

    def test_get_status_color_warning(self):
        """Score 50-79 returns 'warning' (orange)."""
        result = HealthScoreResult(displayed_score=79, real_score=79)
        assert result.get_status_color() == "warning"

        result = HealthScoreResult(displayed_score=50, real_score=50)
        assert result.get_status_color() == "warning"

    def test_get_status_color_critical(self):
        """Score < 50 returns 'critical' (red)."""
        result = HealthScoreResult(displayed_score=49, real_score=49)
        assert result.get_status_color() == "critical"

        result = HealthScoreResult(displayed_score=0, real_score=0)
        assert result.get_status_color() == "critical"

    def test_to_dict_serialization(self):
        """to_dict() returns correct JSON structure."""
        result = HealthScoreResult(
            displayed_score=85,
            real_score=70,
            base_score=100,
            critical_count=1,
            warning_count=2,
            whitelist_hits=1,
            whitelist_impact=15,
        )

        data = result.to_dict()

        assert data["displayed_score"] == 85
        assert data["real_score"] == 70
        assert data["base_score"] == 100
        assert data["critical_count"] == 1
        assert data["warning_count"] == 2
        assert data["whitelist_hits"] == 1
        assert data["whitelist_impact"] == 15
        assert data["status_color"] == "normal"


class TestHealthScoreCalculator:
    """Tests for HealthScoreCalculator."""

    def test_score_100_no_anomalies_ac2(self):
        """AC2: Healthy network without anomalies has score > 90 (expect 100)."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[])

        result = calculator.calculate(collection)

        assert result.displayed_score == 100
        assert result.real_score == 100
        assert result.displayed_score > 90  # AC2 requirement

    def test_deduction_per_critical_ac1(self):
        """AC1: Each critical anomaly deducts 15 points."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.CRITICAL),
        ])

        result = calculator.calculate(collection)

        assert result.displayed_score == 85  # 100 - 15
        assert result.critical_count == 1

    def test_deduction_per_warning_ac1(self):
        """AC1: Each warning anomaly deducts 5 points."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.WARNING),
        ])

        result = calculator.calculate(collection)

        assert result.displayed_score == 95  # 100 - 5
        assert result.warning_count == 1

    def test_combined_deductions_ac1(self):
        """AC1: Combined deductions work correctly."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.CRITICAL),
            _create_anomaly("a2", CriticalityLevel.CRITICAL),
            _create_anomaly("a3", CriticalityLevel.WARNING),
            _create_anomaly("a4", CriticalityLevel.WARNING),
        ])

        result = calculator.calculate(collection)

        # 100 - (2 * 15) - (2 * 5) = 100 - 30 - 10 = 60
        assert result.displayed_score == 60
        assert result.critical_count == 2
        assert result.warning_count == 2

    def test_score_minimum_zero_ac1(self):
        """AC1: Score minimum is capped at 0."""
        calculator = HealthScoreCalculator()
        # 7 critical anomalies = 7 * 15 = 105 > 100
        collection = AnomalyCollection(anomalies=[
            _create_anomaly(f"a{i}", CriticalityLevel.CRITICAL)
            for i in range(7)
        ])

        result = calculator.calculate(collection)

        assert result.displayed_score == 0
        assert result.real_score == 0

    def test_score_low_with_multiple_critical_ac3(self):
        """AC3: Compromised network with critical anomalies has score < 40."""
        calculator = HealthScoreCalculator()
        # 5 critical = 75 points deducted -> score = 25
        collection = AnomalyCollection(anomalies=[
            _create_anomaly(f"a{i}", CriticalityLevel.CRITICAL)
            for i in range(5)
        ])

        result = calculator.calculate(collection)

        assert result.displayed_score == 25  # 100 - 75
        assert result.displayed_score < 40  # AC3 requirement

    def test_whitelist_excluded_from_displayed_ac4(self):
        """AC4: Whitelisted elements don't reduce displayed score."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("critical_1", CriticalityLevel.CRITICAL),
            _create_anomaly("critical_2", CriticalityLevel.CRITICAL),
            _create_anomaly("warning_1", CriticalityLevel.WARNING),
        ])

        # Whitelist one critical anomaly
        result = calculator.calculate(collection, whitelisted_ids={"critical_1"})

        # Displayed: 1 critical + 1 warning = 100 - 15 - 5 = 80
        assert result.displayed_score == 80
        # Real: 2 critical + 1 warning = 100 - 30 - 5 = 65
        assert result.real_score == 65
        assert result.whitelist_hits == 1

    def test_real_score_vs_displayed_different_ac4(self):
        """AC4: Real score includes all anomalies, differs from displayed."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("c1", CriticalityLevel.CRITICAL),
            _create_anomaly("c2", CriticalityLevel.CRITICAL),
            _create_anomaly("c3", CriticalityLevel.CRITICAL),
        ])

        # Whitelist 2 out of 3 critical
        result = calculator.calculate(collection, whitelisted_ids={"c1", "c2"})

        # Displayed: 1 critical = 100 - 15 = 85
        assert result.displayed_score == 85
        # Real: 3 critical = 100 - 45 = 55
        assert result.real_score == 55
        assert result.whitelist_hits == 2
        # Impact: 55 - 85 = -30 (negative means whitelist improves displayed score)
        assert result.whitelist_impact == -30

    def test_whitelist_impact_calculation(self):
        """Whitelist impact correctly calculated."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.CRITICAL),
        ])

        # Whitelist the only anomaly
        result = calculator.calculate(collection, whitelisted_ids={"a1"})

        assert result.displayed_score == 100
        assert result.real_score == 85
        # Impact: 85 - 100 = -15 (negative = whitelist improves displayed score)
        assert result.whitelist_impact == -15

    def test_normal_anomalies_no_deduction(self):
        """Normal criticality anomalies don't affect score."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.NORMAL),
            _create_anomaly("a2", CriticalityLevel.NORMAL),
        ])

        result = calculator.calculate(collection)

        assert result.displayed_score == 100
        assert result.real_score == 100

    def test_custom_config(self):
        """Custom configuration is applied correctly."""
        config = {
            "base_score": 80,
            "decay_per_critical": 20,
            "decay_per_warning": 10,
        }
        calculator = HealthScoreCalculator(config)
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.CRITICAL),
        ])

        result = calculator.calculate(collection)

        assert result.displayed_score == 60  # 80 - 20
        assert result.base_score == 80

    def test_performance_under_3_seconds_ac5(self):
        """AC5: Score calculation completes in < 3 seconds."""
        calculator = HealthScoreCalculator()
        # Create 1000 anomalies for performance test
        collection = AnomalyCollection(anomalies=[
            _create_anomaly(f"a{i}", CriticalityLevel.CRITICAL if i % 2 == 0 else CriticalityLevel.WARNING)
            for i in range(1000)
        ])

        start_time = time.time()
        result = calculator.calculate(collection)
        elapsed = time.time() - start_time

        assert elapsed < 3.0  # AC5 requirement
        assert result.displayed_score == 0  # Many anomalies = 0 score


class TestHealthScoreCalculatorEdgeCases:
    """Tests for edge cases and error conditions in HealthScoreCalculator."""

    def test_empty_anomaly_collection(self):
        """Empty collection returns perfect score."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[])

        result = calculator.calculate(collection)

        assert result.displayed_score == 100
        assert result.real_score == 100
        assert result.critical_count == 0
        assert result.warning_count == 0

    def test_whitelist_with_nonexistent_ids(self):
        """Whitelist IDs not in collection are ignored."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.CRITICAL),
        ])

        # Whitelist contains ID not in collection
        result = calculator.calculate(collection, whitelisted_ids={"nonexistent_id", "a1"})

        # Only a1 should be whitelisted, nonexistent_id ignored
        assert result.whitelist_hits == 1
        assert result.displayed_score == 100  # a1 whitelisted

    def test_whitelist_empty_set(self):
        """Empty whitelist set works same as None."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.CRITICAL),
        ])

        result_none = calculator.calculate(collection, whitelisted_ids=None)
        result_empty = calculator.calculate(collection, whitelisted_ids=set())

        assert result_none.displayed_score == result_empty.displayed_score
        assert result_none.whitelist_hits == result_empty.whitelist_hits == 0

    def test_config_with_zero_decay(self):
        """Config with zero decay means no deduction."""
        config = {"decay_per_critical": 0, "decay_per_warning": 0}
        calculator = HealthScoreCalculator(config)
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.CRITICAL),
            _create_anomaly("a2", CriticalityLevel.WARNING),
        ])

        result = calculator.calculate(collection)

        assert result.displayed_score == 100  # No deductions

    def test_config_with_high_decay(self):
        """Config with high decay quickly reaches zero."""
        config = {"decay_per_critical": 50, "decay_per_warning": 25}
        calculator = HealthScoreCalculator(config)
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("a1", CriticalityLevel.CRITICAL),
            _create_anomaly("a2", CriticalityLevel.CRITICAL),
            _create_anomaly("a3", CriticalityLevel.WARNING),
        ])

        result = calculator.calculate(collection)

        # 100 - 50 - 50 - 25 = -25, capped at 0
        assert result.displayed_score == 0

    def test_all_anomalies_whitelisted(self):
        """When all anomalies whitelisted, displayed score is perfect."""
        calculator = HealthScoreCalculator()
        collection = AnomalyCollection(anomalies=[
            _create_anomaly("c1", CriticalityLevel.CRITICAL),
            _create_anomaly("c2", CriticalityLevel.CRITICAL),
            _create_anomaly("w1", CriticalityLevel.WARNING),
        ])

        result = calculator.calculate(
            collection,
            whitelisted_ids={"c1", "c2", "w1"}
        )

        assert result.displayed_score == 100
        assert result.real_score == 100 - 30 - 5  # 65
        assert result.whitelist_hits == 3
        assert result.whitelist_impact == -35  # 65 - 100


class TestHealthScoreSingleton:
    """Tests for singleton pattern."""

    def test_get_health_calculator_singleton(self):
        """get_health_calculator returns same instance."""
        calc1 = get_health_calculator()
        calc2 = get_health_calculator()

        assert calc1 is calc2

    def test_reset_health_calculator(self):
        """reset_health_calculator clears the singleton."""
        calc1 = get_health_calculator()
        reset_health_calculator()
        calc2 = get_health_calculator()

        assert calc1 is not calc2

    def test_singleton_with_config(self):
        """Singleton initialized with config on first call."""
        config = {"base_score": 50}
        calc = get_health_calculator(config)
        collection = AnomalyCollection(anomalies=[])

        result = calc.calculate(collection)

        assert result.displayed_score == 50
