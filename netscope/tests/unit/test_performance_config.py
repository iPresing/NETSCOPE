"""Unit tests for performance_config service."""

import pytest
from unittest.mock import patch, MagicMock

from app.services.performance_config import (
    PerformanceTargets,
    get_performance_targets,
    get_current_targets,
    reset_performance_targets,
    PERFORMANCE_TARGETS_MAP,
)
from app.services.hardware_detection import (
    PiModel,
    HardwareInfo,
    reset_hardware_info,
)


class TestPerformanceTargets:
    """Tests for PerformanceTargets dataclass."""

    def test_performance_targets_creation(self):
        """Test creating PerformanceTargets."""
        targets = PerformanceTargets(
            cpu_threshold_percent=20,
            ram_threshold_percent=25,
            max_concurrent_jobs=2,
        )

        assert targets.cpu_threshold_percent == 20
        assert targets.ram_threshold_percent == 25
        assert targets.max_concurrent_jobs == 2

    def test_performance_targets_to_dict(self):
        """Test PerformanceTargets to_dict conversion."""
        targets = PerformanceTargets(
            cpu_threshold_percent=15,
            ram_threshold_percent=20,
            max_concurrent_jobs=2,
        )

        result = targets.to_dict()

        assert result["cpu_threshold_percent"] == 15
        assert result["ram_threshold_percent"] == 20
        assert result["max_concurrent_jobs"] == 2


class TestPerformanceTargetsMap:
    """Tests for PERFORMANCE_TARGETS_MAP."""

    def test_map_contains_all_pi_models(self):
        """Test that targets exist for all Pi models."""
        for model in PiModel:
            assert model in PERFORMANCE_TARGETS_MAP, f"Missing targets for {model}"

    def test_pi_zero_2_has_conservative_targets(self):
        """Test Pi Zero 2 W has conservative (high threshold) targets."""
        targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_ZERO_2_W]

        assert targets.cpu_threshold_percent == 30
        assert targets.ram_threshold_percent == 30
        assert targets.max_concurrent_jobs == 1

    def test_pi_3_has_moderate_targets(self):
        """Test Pi 3 has moderate targets."""
        targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_3_B]

        assert targets.cpu_threshold_percent == 20
        assert targets.ram_threshold_percent == 25
        assert targets.max_concurrent_jobs == 2

    def test_pi_4_has_comfortable_targets(self):
        """Test Pi 4 has comfortable (lower threshold) targets."""
        targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_4_B]

        assert targets.cpu_threshold_percent == 15
        assert targets.ram_threshold_percent == 20
        assert targets.max_concurrent_jobs == 2

    def test_pi_5_has_excellent_targets(self):
        """Test Pi 5 has excellent (lowest threshold) targets."""
        targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_5]

        assert targets.cpu_threshold_percent == 10
        assert targets.ram_threshold_percent == 15
        assert targets.max_concurrent_jobs == 2

    def test_unknown_has_conservative_targets(self):
        """Test unknown model uses conservative targets like Pi Zero."""
        targets = PERFORMANCE_TARGETS_MAP[PiModel.UNKNOWN]

        # Should match Pi Zero 2 W for safety
        assert targets.cpu_threshold_percent == 30
        assert targets.ram_threshold_percent == 30
        assert targets.max_concurrent_jobs == 1

    def test_targets_thresholds_scale_with_power(self):
        """Test that more powerful Pi models have lower thresholds."""
        zero_targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_ZERO_2_W]
        pi3_targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_3_B]
        pi4_targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_4_B]
        pi5_targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_5]

        # CPU thresholds should decrease with more power
        assert zero_targets.cpu_threshold_percent >= pi3_targets.cpu_threshold_percent
        assert pi3_targets.cpu_threshold_percent >= pi4_targets.cpu_threshold_percent
        assert pi4_targets.cpu_threshold_percent >= pi5_targets.cpu_threshold_percent


class TestGetPerformanceTargets:
    """Tests for get_performance_targets function."""

    def setup_method(self):
        """Reset singletons before each test."""
        reset_performance_targets()
        reset_hardware_info()

    def teardown_method(self):
        """Reset singletons after each test."""
        reset_performance_targets()
        reset_hardware_info()

    def test_get_targets_with_explicit_model(self):
        """Test getting targets for an explicitly specified model."""
        targets = get_performance_targets(PiModel.PI_4_B)

        assert targets.cpu_threshold_percent == 15
        assert targets.max_concurrent_jobs == 2

    def test_get_targets_for_each_model(self):
        """Test getting targets for each Pi model."""
        for model in PiModel:
            targets = get_performance_targets(model)

            assert targets is not None
            assert targets.cpu_threshold_percent > 0
            assert targets.ram_threshold_percent > 0
            assert targets.max_concurrent_jobs >= 1

    def test_get_targets_uses_detected_hardware_when_none(self):
        """Test that None model parameter uses detected hardware."""
        mock_hardware = HardwareInfo(
            model=PiModel.PI_5,
            model_name="Raspberry Pi 5",
            cpu_count=4,
            ram_mb=8192,
            cpu_max_mhz=2400,
        )

        with patch(
            "app.services.performance_config.get_hardware_info",
            return_value=mock_hardware
        ):
            targets = get_performance_targets(None)

        assert targets.cpu_threshold_percent == 10  # Pi 5 threshold
        assert targets.max_concurrent_jobs == 2


class TestGetCurrentTargets:
    """Tests for get_current_targets function."""

    def setup_method(self):
        """Reset singletons before each test."""
        reset_performance_targets()
        reset_hardware_info()

    def teardown_method(self):
        """Reset singletons after each test."""
        reset_performance_targets()
        reset_hardware_info()

    def test_get_current_targets_returns_cached(self):
        """Test that get_current_targets returns cached result."""
        mock_hardware = HardwareInfo(
            model=PiModel.PI_4_B,
            model_name="Raspberry Pi 4 Model B",
            cpu_count=4,
            ram_mb=4096,
            cpu_max_mhz=1800,
        )

        with patch(
            "app.services.performance_config.get_hardware_info",
            return_value=mock_hardware
        ):
            first_result = get_current_targets()

        # Second call should return cached result
        with patch(
            "app.services.performance_config.get_hardware_info",
            side_effect=Exception("Should not be called")
        ):
            second_result = get_current_targets()

        assert first_result is second_result

    def test_reset_clears_cache(self):
        """Test that reset_performance_targets clears the cache."""
        mock_hardware_pi4 = HardwareInfo(
            model=PiModel.PI_4_B,
            model_name="Raspberry Pi 4 Model B",
            cpu_count=4,
            ram_mb=4096,
            cpu_max_mhz=1800,
        )
        mock_hardware_pi5 = HardwareInfo(
            model=PiModel.PI_5,
            model_name="Raspberry Pi 5",
            cpu_count=4,
            ram_mb=8192,
            cpu_max_mhz=2400,
        )

        with patch(
            "app.services.performance_config.get_hardware_info",
            return_value=mock_hardware_pi4
        ):
            first_result = get_current_targets()

        assert first_result.cpu_threshold_percent == 15  # Pi 4

        # Reset and get new targets
        reset_performance_targets()

        with patch(
            "app.services.performance_config.get_hardware_info",
            return_value=mock_hardware_pi5
        ):
            second_result = get_current_targets()

        assert second_result.cpu_threshold_percent == 10  # Pi 5
        assert first_result is not second_result


class TestTargetsConsistency:
    """Tests for overall targets consistency."""

    def test_max_jobs_at_least_one(self):
        """Test that all models have at least 1 max concurrent job."""
        for model, targets in PERFORMANCE_TARGETS_MAP.items():
            assert targets.max_concurrent_jobs >= 1, f"{model} should have at least 1 job"

    def test_thresholds_are_percentages(self):
        """Test that thresholds are valid percentages (1-100)."""
        for model, targets in PERFORMANCE_TARGETS_MAP.items():
            assert 1 <= targets.cpu_threshold_percent <= 100, \
                f"{model} CPU threshold should be 1-100"
            assert 1 <= targets.ram_threshold_percent <= 100, \
                f"{model} RAM threshold should be 1-100"

    def test_pi_zero_most_restrictive(self):
        """Test that Pi Zero 2 W has the most restrictive single job limit."""
        zero_targets = PERFORMANCE_TARGETS_MAP[PiModel.PI_ZERO_2_W]

        # Pi Zero should have the lowest job limit
        assert zero_targets.max_concurrent_jobs == 1

        # Other models should have equal or higher limits
        for model, targets in PERFORMANCE_TARGETS_MAP.items():
            if model != PiModel.PI_ZERO_2_W and model != PiModel.UNKNOWN:
                assert targets.max_concurrent_jobs >= zero_targets.max_concurrent_jobs
