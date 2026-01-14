"""Unit tests for hardware_detection service."""

import pytest
from unittest.mock import patch, mock_open

from app.services.hardware_detection import (
    PiModel,
    HardwareInfo,
    detect_pi_model,
    get_hardware_info,
    reset_hardware_info,
    _parse_model_name,
    _read_device_tree_model,
    _read_cpuinfo_model,
    _map_revision_to_model_name,
    _create_hardware_info,
    REVISION_MAP,
    HARDWARE_SPECS,
)


class TestPiModel:
    """Tests for PiModel enum."""

    def test_pi_model_values_exist(self):
        """Test that all expected Pi models exist."""
        assert PiModel.PI_ZERO_2_W.value == "PI_ZERO_2_W"
        assert PiModel.PI_3_B.value == "PI_3_B"
        assert PiModel.PI_4_B.value == "PI_4_B"
        assert PiModel.PI_5.value == "PI_5"
        assert PiModel.UNKNOWN.value == "UNKNOWN"


class TestHardwareInfo:
    """Tests for HardwareInfo dataclass."""

    def test_hardware_info_to_dict(self):
        """Test HardwareInfo to_dict conversion."""
        info = HardwareInfo(
            model=PiModel.PI_4_B,
            model_name="Raspberry Pi 4 Model B",
            cpu_count=4,
            ram_mb=4096,
            cpu_max_mhz=1800,
        )

        result = info.to_dict()

        assert result["model"] == "Raspberry Pi 4 Model B"
        assert result["model_code"] == "PI_4_B"
        assert result["cpu_count"] == 4
        assert result["ram_mb"] == 4096
        assert result["cpu_max_mhz"] == 1800


class TestParseModelName:
    """Tests for _parse_model_name function."""

    def test_parse_pi_zero_2_w(self):
        """Test parsing Pi Zero 2 W model name."""
        assert _parse_model_name("Raspberry Pi Zero 2 W Rev 1.0") == PiModel.PI_ZERO_2_W
        assert _parse_model_name("raspberry pi zero 2 w") == PiModel.PI_ZERO_2_W

    def test_parse_pi_3_b(self):
        """Test parsing Pi 3 B model name."""
        assert _parse_model_name("Raspberry Pi 3 Model B Rev 1.2") == PiModel.PI_3_B
        assert _parse_model_name("Raspberry Pi 3 Model B+") == PiModel.PI_3_B

    def test_parse_pi_4_b(self):
        """Test parsing Pi 4 B model name."""
        assert _parse_model_name("Raspberry Pi 4 Model B Rev 1.4") == PiModel.PI_4_B
        assert _parse_model_name("raspberry pi 4 model b") == PiModel.PI_4_B

    def test_parse_pi_5(self):
        """Test parsing Pi 5 model name."""
        assert _parse_model_name("Raspberry Pi 5 Model B Rev 1.0") == PiModel.PI_5
        assert _parse_model_name("raspberry pi 5") == PiModel.PI_5

    def test_parse_unknown_model(self):
        """Test parsing unknown model name returns UNKNOWN."""
        assert _parse_model_name("Unknown Device") == PiModel.UNKNOWN
        assert _parse_model_name("Raspberry Pi 2 Model B") == PiModel.UNKNOWN


class TestReadDeviceTreeModel:
    """Tests for _read_device_tree_model function."""

    def test_read_device_tree_success(self):
        """Test successful device tree read."""
        mock_content = "Raspberry Pi 4 Model B Rev 1.4\x00"

        with patch("builtins.open", mock_open(read_data=mock_content)):
            result = _read_device_tree_model()

        assert result == "Raspberry Pi 4 Model B Rev 1.4"

    def test_read_device_tree_file_not_found(self):
        """Test device tree file not found returns None."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = _read_device_tree_model()

        assert result is None

    def test_read_device_tree_permission_error(self):
        """Test device tree permission denied returns None."""
        with patch("builtins.open", side_effect=PermissionError):
            result = _read_device_tree_model()

        assert result is None


class TestReadCpuinfoModel:
    """Tests for _read_cpuinfo_model function."""

    def test_read_cpuinfo_with_model_line(self):
        """Test reading model from cpuinfo Model line."""
        cpuinfo_content = """processor	: 0
model name	: ARMv7 Processor rev 3 (v7l)
BogoMIPS	: 108.00
Hardware	: BCM2711
Revision	: c03111
Model		: Raspberry Pi 4 Model B Rev 1.1
"""
        with patch("builtins.open", mock_open(read_data=cpuinfo_content)):
            result = _read_cpuinfo_model()

        assert result == "Raspberry Pi 4 Model B Rev 1.1"

    def test_read_cpuinfo_with_revision_only(self):
        """Test reading model from cpuinfo Revision code when no Model line."""
        cpuinfo_content = """processor	: 0
model name	: ARMv7 Processor rev 3 (v7l)
Hardware	: BCM2711
Revision	: c03111
"""
        with patch("builtins.open", mock_open(read_data=cpuinfo_content)):
            result = _read_cpuinfo_model()

        assert result == "Raspberry Pi 4 Model B"

    def test_read_cpuinfo_file_not_found(self):
        """Test cpuinfo file not found returns None."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = _read_cpuinfo_model()

        assert result is None


class TestMapRevisionToModelName:
    """Tests for _map_revision_to_model_name function."""

    def test_map_pi_4_revision(self):
        """Test mapping Pi 4 revision codes."""
        assert _map_revision_to_model_name("c03111") == "Raspberry Pi 4 Model B"
        assert _map_revision_to_model_name("b03114") == "Raspberry Pi 4 Model B"

    def test_map_pi_zero_2_revision(self):
        """Test mapping Pi Zero 2 W revision code."""
        assert _map_revision_to_model_name("902120") == "Raspberry Pi Zero 2 W"

    def test_map_pi_5_revision(self):
        """Test mapping Pi 5 revision codes."""
        assert _map_revision_to_model_name("c04170") == "Raspberry Pi 5"

    def test_map_unknown_revision(self):
        """Test mapping unknown revision returns None."""
        assert _map_revision_to_model_name("unknown123") is None


class TestCreateHardwareInfo:
    """Tests for _create_hardware_info function."""

    def test_create_hardware_info_pi_4(self):
        """Test creating HardwareInfo for Pi 4."""
        with patch("os.cpu_count", return_value=4):
            result = _create_hardware_info(PiModel.PI_4_B, "Raspberry Pi 4 Model B")

        assert result.model == PiModel.PI_4_B
        assert result.model_name == "Raspberry Pi 4 Model B"
        assert result.cpu_count == 4
        assert result.ram_mb == HARDWARE_SPECS[PiModel.PI_4_B]["ram_mb"]
        assert result.cpu_max_mhz == HARDWARE_SPECS[PiModel.PI_4_B]["cpu_max_mhz"]

    def test_create_hardware_info_unknown_uses_defaults(self):
        """Test creating HardwareInfo for unknown model uses conservative defaults."""
        with patch("os.cpu_count", return_value=4):
            result = _create_hardware_info(PiModel.UNKNOWN, "Unknown")

        assert result.model == PiModel.UNKNOWN
        assert result.ram_mb == HARDWARE_SPECS[PiModel.UNKNOWN]["ram_mb"]
        assert result.cpu_max_mhz == HARDWARE_SPECS[PiModel.UNKNOWN]["cpu_max_mhz"]


class TestDetectPiModel:
    """Tests for detect_pi_model function."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_hardware_info()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_hardware_info()

    def test_detect_from_device_tree(self):
        """Test detection from device tree file."""
        mock_content = "Raspberry Pi 4 Model B Rev 1.4\x00"

        with patch("builtins.open", mock_open(read_data=mock_content)):
            with patch("os.cpu_count", return_value=4):
                result = detect_pi_model()

        assert result.model == PiModel.PI_4_B
        assert result.model_name == "Raspberry Pi 4 Model B Rev 1.4"

    def test_detect_fallback_to_cpuinfo(self):
        """Test fallback to cpuinfo when device tree fails."""
        cpuinfo_content = """processor	: 0
Model		: Raspberry Pi 3 Model B
"""
        # First call raises FileNotFoundError (device tree)
        # Second call returns cpuinfo content
        def mock_open_fn(path, *args, **kwargs):
            if "devicetree" in path:
                raise FileNotFoundError
            return mock_open(read_data=cpuinfo_content)()

        with patch("builtins.open", side_effect=mock_open_fn):
            with patch("os.cpu_count", return_value=4):
                result = detect_pi_model()

        assert result.model == PiModel.PI_3_B

    def test_detect_fallback_to_unknown(self):
        """Test fallback to unknown when all detection fails."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            with patch("os.cpu_count", return_value=4):
                result = detect_pi_model()

        assert result.model == PiModel.UNKNOWN

    def test_singleton_returns_cached_result(self):
        """Test that subsequent calls return cached result."""
        mock_content = "Raspberry Pi 5 Model B\x00"

        with patch("builtins.open", mock_open(read_data=mock_content)):
            with patch("os.cpu_count", return_value=4):
                first_result = detect_pi_model()

        # Second call should return same instance without reading files
        with patch("builtins.open", side_effect=Exception("Should not be called")):
            second_result = detect_pi_model()

        assert first_result is second_result


class TestGetHardwareInfo:
    """Tests for get_hardware_info function."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_hardware_info()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_hardware_info()

    def test_get_hardware_info_calls_detect(self):
        """Test get_hardware_info calls detect_pi_model."""
        mock_content = "Raspberry Pi 4 Model B\x00"

        with patch("builtins.open", mock_open(read_data=mock_content)):
            with patch("os.cpu_count", return_value=4):
                result = get_hardware_info()

        assert result.model == PiModel.PI_4_B


class TestRevisionMap:
    """Tests for REVISION_MAP completeness."""

    def test_revision_map_contains_main_models(self):
        """Test that revision map contains revisions for all main models."""
        pi_4_revisions = [k for k, v in REVISION_MAP.items() if v == PiModel.PI_4_B]
        pi_3_revisions = [k for k, v in REVISION_MAP.items() if v == PiModel.PI_3_B]
        pi_zero_2_revisions = [k for k, v in REVISION_MAP.items() if v == PiModel.PI_ZERO_2_W]
        pi_5_revisions = [k for k, v in REVISION_MAP.items() if v == PiModel.PI_5]

        assert len(pi_4_revisions) > 0, "Should have Pi 4 revisions"
        assert len(pi_3_revisions) > 0, "Should have Pi 3 revisions"
        assert len(pi_zero_2_revisions) > 0, "Should have Pi Zero 2 W revisions"
        assert len(pi_5_revisions) > 0, "Should have Pi 5 revisions"


class TestHardwareSpecs:
    """Tests for HARDWARE_SPECS completeness."""

    def test_hardware_specs_contains_all_models(self):
        """Test that hardware specs exist for all Pi models."""
        for model in PiModel:
            assert model in HARDWARE_SPECS, f"Missing specs for {model}"
            specs = HARDWARE_SPECS[model]
            assert "cpu_count" in specs
            assert "ram_mb" in specs
            assert "cpu_max_mhz" in specs

    def test_hardware_specs_values_are_reasonable(self):
        """Test that hardware specs have reasonable values."""
        for model, specs in HARDWARE_SPECS.items():
            assert specs["cpu_count"] >= 1, f"{model} should have at least 1 CPU"
            assert specs["ram_mb"] >= 256, f"{model} should have at least 256MB RAM"
            assert specs["cpu_max_mhz"] >= 700, f"{model} should have at least 700MHz CPU"
