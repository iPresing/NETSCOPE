"""Unit tests for health score history tracking.

Story 3.5: Evolution Score Entre Captures (FR20)
Tests cover:
- AC1: Score evolution display (current, previous, delta)
- AC2: Positive indicator (improvement)
- AC3: Negative indicator (degradation)
- AC4: First capture (no history)
- AC5: Correct reflection after corrections

Test cases per story Tasks/Subtasks:
- 8.2: record() stores entries correctly
- 8.3: get_latest(2) returns 2 most recent scores
- 8.4: get_evolution() calculates delta correctly
- 8.5: direction "up" when score increases
- 8.6: direction "down" when score decreases
- 8.7: direction "stable" when score identical
- 8.8: first capture returns null for previous
- 8.9: FIFO limit of 10 entries
"""

import pytest
from datetime import datetime, timezone

from app.models.health_score import HealthScoreResult
from app.models.health_score_history import HealthScoreEntry, ScoreEvolution
from app.services.health_score_history import (
    HealthScoreHistoryStore,
    get_health_score_history,
    reset_health_score_history,
)


@pytest.fixture(autouse=True)
def reset_history():
    """Reset singleton before each test."""
    reset_health_score_history()
    yield
    reset_health_score_history()


def _create_health_result(
    displayed_score: int,
    real_score: int | None = None,
    critical_count: int = 0,
    warning_count: int = 0,
    whitelist_hits: int = 0,
) -> HealthScoreResult:
    """Helper to create HealthScoreResult for tests."""
    if real_score is None:
        real_score = displayed_score
    return HealthScoreResult(
        displayed_score=displayed_score,
        real_score=real_score,
        critical_count=critical_count,
        warning_count=warning_count,
        whitelist_hits=whitelist_hits,
    )


class TestHealthScoreEntry:
    """Tests for HealthScoreEntry dataclass."""

    def test_to_dict_serialization(self):
        """to_dict() returns correct JSON structure."""
        now = datetime.now(timezone.utc)
        entry = HealthScoreEntry(
            capture_id="cap_123",
            displayed_score=85,
            real_score=70,
            critical_count=1,
            warning_count=2,
            whitelist_hits=1,
            timestamp=now,
        )

        data = entry.to_dict()

        assert data["capture_id"] == "cap_123"
        assert data["displayed_score"] == 85
        assert data["real_score"] == 70
        assert data["critical_count"] == 1
        assert data["warning_count"] == 2
        assert data["whitelist_hits"] == 1
        assert data["timestamp"] == now.isoformat()


class TestScoreEvolution:
    """Tests for ScoreEvolution dataclass."""

    def test_to_dict_with_previous(self):
        """to_dict() serializes evolution with previous score."""
        evolution = ScoreEvolution(
            current_score=88,
            previous_score=73,
            delta=15,
            direction="up",
            message="Amelioration de 15 pts",
        )

        data = evolution.to_dict()

        assert data["current_score"] == 88
        assert data["previous_score"] == 73
        assert data["delta"] == 15
        assert data["direction"] == "up"
        assert data["message"] == "Amelioration de 15 pts"

    def test_to_dict_first_capture(self):
        """to_dict() serializes first capture with null previous."""
        evolution = ScoreEvolution(
            current_score=85,
            previous_score=None,
            delta=0,
            direction="stable",
            message="Premiere capture",
        )

        data = evolution.to_dict()

        assert data["current_score"] == 85
        assert data["previous_score"] is None
        assert data["delta"] == 0
        assert data["direction"] == "stable"


class TestHealthScoreHistoryStoreRecord:
    """Tests for HealthScoreHistoryStore.record() - Task 8.2."""

    def test_record_stores_entry_correctly(self):
        """Task 8.2: record() stores entries correctly."""
        store = HealthScoreHistoryStore()
        result = _create_health_result(85, 70, 1, 2, 1)

        store.record("cap_001", result)

        assert store.get_history_count() == 1
        latest = store.get_latest(1)
        assert len(latest) == 1
        assert latest[0].capture_id == "cap_001"
        assert latest[0].displayed_score == 85
        assert latest[0].real_score == 70

    def test_record_multiple_entries(self):
        """Multiple records are stored in order."""
        store = HealthScoreHistoryStore()

        store.record("cap_001", _create_health_result(80))
        store.record("cap_002", _create_health_result(85))
        store.record("cap_003", _create_health_result(90))

        assert store.get_history_count() == 3


class TestHealthScoreHistoryStoreGetLatest:
    """Tests for HealthScoreHistoryStore.get_latest() - Task 8.3."""

    def test_get_latest_returns_most_recent_first(self):
        """Task 8.3: get_latest(2) returns 2 most recent scores, most recent first."""
        store = HealthScoreHistoryStore()

        store.record("cap_001", _create_health_result(70))
        store.record("cap_002", _create_health_result(75))
        store.record("cap_003", _create_health_result(80))

        latest = store.get_latest(2)

        assert len(latest) == 2
        assert latest[0].capture_id == "cap_003"  # Most recent first
        assert latest[0].displayed_score == 80
        assert latest[1].capture_id == "cap_002"
        assert latest[1].displayed_score == 75

    def test_get_latest_empty_store(self):
        """get_latest() returns empty list for empty store."""
        store = HealthScoreHistoryStore()

        latest = store.get_latest(2)

        assert latest == []

    def test_get_latest_less_than_requested(self):
        """get_latest() returns available entries if less than requested."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(80))

        latest = store.get_latest(5)

        assert len(latest) == 1


class TestHealthScoreHistoryStoreEvolution:
    """Tests for HealthScoreHistoryStore.get_evolution() - Tasks 8.4-8.8."""

    def test_evolution_delta_correct(self):
        """Task 8.4: get_evolution() calculates delta correctly."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(70))
        store.record("cap_002", _create_health_result(85))

        evolution = store.get_evolution()

        assert evolution is not None
        assert evolution.current_score == 85
        assert evolution.previous_score == 70
        assert evolution.delta == 15

    def test_evolution_direction_up_when_improved(self):
        """Task 8.5: direction "up" when score increases (AC2)."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(60))
        store.record("cap_002", _create_health_result(75))

        evolution = store.get_evolution()

        assert evolution.direction == "up"
        assert evolution.delta == 15
        assert "Amelioration" in evolution.message

    def test_evolution_direction_down_when_degraded(self):
        """Task 8.6: direction "down" when score decreases (AC3)."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(90))
        store.record("cap_002", _create_health_result(70))

        evolution = store.get_evolution()

        assert evolution.direction == "down"
        assert evolution.delta == -20
        assert "Degradation" in evolution.message

    def test_evolution_direction_stable_when_identical(self):
        """Task 8.7: direction "stable" when score identical."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(80))
        store.record("cap_002", _create_health_result(80))

        evolution = store.get_evolution()

        assert evolution.direction == "stable"
        assert evolution.delta == 0
        assert "stable" in evolution.message.lower()

    def test_evolution_first_capture_null_previous(self):
        """Task 8.8: first capture returns null for previous (AC4)."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(85))

        evolution = store.get_evolution()

        assert evolution is not None
        assert evolution.current_score == 85
        assert evolution.previous_score is None
        assert evolution.delta == 0
        assert evolution.direction == "stable"
        assert "Premiere" in evolution.message

    def test_evolution_no_history_returns_none(self):
        """get_evolution() returns None with no history."""
        store = HealthScoreHistoryStore()

        evolution = store.get_evolution()

        assert evolution is None


class TestHealthScoreHistoryStoreDeduplication:
    """Tests for capture deduplication (review fix H2/M3)."""

    def test_duplicate_capture_id_not_recorded(self):
        """Repeated record() with same capture_id is ignored."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(80))
        store.record("cap_001", _create_health_result(80))
        store.record("cap_001", _create_health_result(80))

        assert store.get_history_count() == 1

    def test_different_capture_ids_recorded(self):
        """Different capture_ids are recorded normally."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(80))
        store.record("cap_002", _create_health_result(85))

        assert store.get_history_count() == 2

    def test_same_id_after_different_still_deduped(self):
        """Re-recording same capture_id after a different one is allowed (not consecutive)."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(80))
        store.record("cap_002", _create_health_result(85))
        store.record("cap_002", _create_health_result(85))

        assert store.get_history_count() == 2

    def test_evolution_correct_despite_polling_duplicates(self):
        """Evolution stays correct when polling sends repeated requests."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(60))
        store.record("cap_002", _create_health_result(85))

        # Simulate polling hitting same capture 5 times
        for _ in range(5):
            store.record("cap_002", _create_health_result(85))

        assert store.get_history_count() == 2
        evolution = store.get_evolution()
        assert evolution.delta == 25
        assert evolution.direction == "up"


class TestHealthScoreHistoryStoreFIFO:
    """Tests for FIFO limit - Task 8.9."""

    def test_fifo_limit_10_entries(self):
        """Task 8.9: FIFO limit of 10 entries maintained."""
        store = HealthScoreHistoryStore()

        # Add 15 entries
        for i in range(15):
            store.record(f"cap_{i:03d}", _create_health_result(50 + i))

        # Should only have 10 entries
        assert store.get_history_count() == 10

        # Should have the most recent 10 (cap_005 to cap_014)
        latest = store.get_latest(10)
        assert latest[0].capture_id == "cap_014"  # Most recent
        assert latest[0].displayed_score == 64
        assert latest[-1].capture_id == "cap_005"  # Oldest remaining
        assert latest[-1].displayed_score == 55

    def test_fifo_oldest_evicted(self):
        """FIFO evicts oldest entries when limit exceeded."""
        store = HealthScoreHistoryStore()

        # Add 12 entries
        for i in range(12):
            store.record(f"cap_{i:03d}", _create_health_result(60 + i))

        # First 2 (cap_000, cap_001) should be evicted
        latest = store.get_latest(10)
        capture_ids = [entry.capture_id for entry in latest]

        assert "cap_000" not in capture_ids
        assert "cap_001" not in capture_ids
        assert "cap_002" in capture_ids


class TestHealthScoreHistoryStoreClear:
    """Tests for clear functionality."""

    def test_clear_removes_all_entries(self):
        """clear() removes all history entries."""
        store = HealthScoreHistoryStore()
        store.record("cap_001", _create_health_result(80))
        store.record("cap_002", _create_health_result(85))

        store.clear()

        assert store.get_history_count() == 0
        assert store.get_latest(2) == []
        assert store.get_evolution() is None


class TestHealthScoreHistorySingleton:
    """Tests for singleton pattern."""

    def test_get_health_score_history_singleton(self):
        """get_health_score_history returns same instance."""
        store1 = get_health_score_history()
        store2 = get_health_score_history()

        assert store1 is store2

    def test_reset_health_score_history(self):
        """reset_health_score_history clears the singleton."""
        store1 = get_health_score_history()
        store1.record("cap_001", _create_health_result(80))

        reset_health_score_history()

        store2 = get_health_score_history()
        assert store2.get_history_count() == 0
        assert store1 is not store2


class TestHealthScoreHistoryIntegration:
    """Integration-style unit tests for complete workflows."""

    def test_ac5_correction_reflected_in_new_capture(self):
        """AC5: New capture reflects improvement after correction."""
        store = HealthScoreHistoryStore()

        # Initial capture with low score (problem detected)
        store.record("cap_001", _create_health_result(
            displayed_score=55,
            critical_count=3,
        ))

        # After user fixes problems and runs new capture
        store.record("cap_002", _create_health_result(
            displayed_score=90,
            critical_count=0,
        ))

        evolution = store.get_evolution()

        assert evolution.direction == "up"
        assert evolution.delta == 35
        assert evolution.current_score == 90
        assert evolution.previous_score == 55

    def test_multiple_captures_evolution_tracking(self):
        """Track evolution across multiple captures."""
        store = HealthScoreHistoryStore()

        # Simulate network health over multiple captures
        scores = [60, 65, 70, 68, 75, 80, 85, 82, 88, 92]

        for i, score in enumerate(scores):
            store.record(f"cap_{i:03d}", _create_health_result(score))

        # Check final evolution
        evolution = store.get_evolution()
        assert evolution.current_score == 92
        assert evolution.previous_score == 88
        assert evolution.delta == 4
        assert evolution.direction == "up"
