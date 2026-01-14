"""Hardware detection service for Raspberry Pi model identification.

Detects the Raspberry Pi model and provides hardware information
for adapting performance parameters.
"""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class PiModel(Enum):
    """Raspberry Pi model identifiers."""
    PI_ZERO_2_W = "PI_ZERO_2_W"
    PI_3_B = "PI_3_B"
    PI_4_B = "PI_4_B"
    PI_5 = "PI_5"
    UNKNOWN = "UNKNOWN"


# Mapping of revision codes to Pi models (main revisions)
REVISION_MAP = {
    # Pi Zero 2 W
    "902120": PiModel.PI_ZERO_2_W,
    # Pi 3 B
    "a02082": PiModel.PI_3_B,
    "a22082": PiModel.PI_3_B,
    "a32082": PiModel.PI_3_B,
    "a52082": PiModel.PI_3_B,
    # Pi 3 B+
    "a020d3": PiModel.PI_3_B,
    # Pi 4 B (various RAM sizes)
    "a03111": PiModel.PI_4_B,
    "b03111": PiModel.PI_4_B,
    "b03112": PiModel.PI_4_B,
    "b03114": PiModel.PI_4_B,
    "b03115": PiModel.PI_4_B,
    "c03111": PiModel.PI_4_B,
    "c03112": PiModel.PI_4_B,
    "c03114": PiModel.PI_4_B,
    "c03115": PiModel.PI_4_B,
    "d03114": PiModel.PI_4_B,
    "d03115": PiModel.PI_4_B,
    # Pi 5
    "c04170": PiModel.PI_5,
    "d04170": PiModel.PI_5,
}

# Default hardware specs per model
HARDWARE_SPECS = {
    PiModel.PI_ZERO_2_W: {"cpu_count": 4, "ram_mb": 512, "cpu_max_mhz": 1000},
    PiModel.PI_3_B: {"cpu_count": 4, "ram_mb": 1024, "cpu_max_mhz": 1400},
    PiModel.PI_4_B: {"cpu_count": 4, "ram_mb": 4096, "cpu_max_mhz": 1800},
    PiModel.PI_5: {"cpu_count": 4, "ram_mb": 8192, "cpu_max_mhz": 2400},
    PiModel.UNKNOWN: {"cpu_count": 4, "ram_mb": 512, "cpu_max_mhz": 1000},
}


@dataclass
class HardwareInfo:
    """Hardware information container."""
    model: PiModel
    model_name: str
    cpu_count: int
    ram_mb: int
    cpu_max_mhz: int

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "model": self.model_name,
            "model_code": self.model.value,
            "cpu_count": self.cpu_count,
            "ram_mb": self.ram_mb,
            "cpu_max_mhz": self.cpu_max_mhz,
        }


# Singleton instance
_hardware_info: Optional[HardwareInfo] = None


def detect_pi_model() -> HardwareInfo:
    """Detect Raspberry Pi model and return hardware info.

    Uses singleton pattern to avoid repeated detection.
    First tries /sys/firmware/devicetree/base/model,
    then falls back to /proc/cpuinfo.

    Returns:
        HardwareInfo: Detected hardware information
    """
    global _hardware_info

    if _hardware_info is not None:
        return _hardware_info

    # Try device tree first (most reliable)
    model_name = _read_device_tree_model()

    # Fallback to cpuinfo
    if not model_name:
        model_name = _read_cpuinfo_model()

    # Parse model and create HardwareInfo
    if model_name:
        pi_model = _parse_model_name(model_name)
        _hardware_info = _create_hardware_info(pi_model, model_name)
        logger.info(
            f"Pi model detected "
            f"(model={model_name}, cpu_count={_hardware_info.cpu_count}, "
            f"ram_mb={_hardware_info.ram_mb})"
        )
    else:
        # Fallback to conservative defaults
        _hardware_info = _create_hardware_info(PiModel.UNKNOWN, "Unknown")
        logger.warning(
            "Could not detect Pi model, using defaults (reason=detection_failed)"
        )

    return _hardware_info


def get_hardware_info() -> HardwareInfo:
    """Get cached hardware info (calls detect if not cached).

    Returns:
        HardwareInfo: Cached or newly detected hardware information
    """
    return detect_pi_model()


def reset_hardware_info() -> None:
    """Reset the cached hardware info (useful for testing)."""
    global _hardware_info
    _hardware_info = None


def _read_device_tree_model() -> Optional[str]:
    """Read model from /sys/firmware/devicetree/base/model.

    Returns:
        Model string or None if not available
    """
    model_path = "/sys/firmware/devicetree/base/model"
    try:
        with open(model_path, "r") as f:
            # Remove null bytes that may be present
            return f.read().strip().rstrip("\x00")
    except FileNotFoundError:
        logger.debug(
            f"Device tree model file not found (path={model_path})"
        )
        return None
    except PermissionError:
        logger.debug(
            f"Permission denied reading device tree (path={model_path})"
        )
        return None
    except Exception as e:
        logger.debug(
            f"Error reading device tree (path={model_path}, error={str(e)})"
        )
        return None


def _read_cpuinfo_model() -> Optional[str]:
    """Read model from /proc/cpuinfo.

    Tries to read the Model line first, then falls back to Revision code.

    Returns:
        Model string or None if not available
    """
    cpuinfo_path = "/proc/cpuinfo"
    try:
        with open(cpuinfo_path, "r") as f:
            model_line = None
            revision_line = None

            for line in f:
                if line.startswith("Model"):
                    model_line = line.split(":")[1].strip()
                elif line.startswith("Revision"):
                    revision_line = line.split(":")[1].strip()

            # Prefer Model line if available
            if model_line:
                return model_line

            # Fall back to revision code mapping
            if revision_line:
                return _map_revision_to_model_name(revision_line)

            return None
    except FileNotFoundError:
        logger.debug(
            f"cpuinfo file not found (path={cpuinfo_path})"
        )
        return None
    except Exception as e:
        logger.debug(
            f"Error reading cpuinfo (path={cpuinfo_path}, error={str(e)})"
        )
        return None


def _map_revision_to_model_name(revision: str) -> Optional[str]:
    """Map revision code to model name.

    Args:
        revision: Revision code from cpuinfo

    Returns:
        Model name string or None if unknown
    """
    pi_model = REVISION_MAP.get(revision.lower())
    if pi_model:
        model_names = {
            PiModel.PI_ZERO_2_W: "Raspberry Pi Zero 2 W",
            PiModel.PI_3_B: "Raspberry Pi 3 Model B",
            PiModel.PI_4_B: "Raspberry Pi 4 Model B",
            PiModel.PI_5: "Raspberry Pi 5",
        }
        return model_names.get(pi_model)
    return None


def _parse_model_name(model_name: str) -> PiModel:
    """Parse model name string to PiModel enum.

    Args:
        model_name: Full model name string

    Returns:
        PiModel enum value
    """
    model_lower = model_name.lower()

    if "zero 2" in model_lower:
        return PiModel.PI_ZERO_2_W
    elif "pi 5" in model_lower or "raspberry pi 5" in model_lower:
        return PiModel.PI_5
    elif "pi 4" in model_lower or "raspberry pi 4" in model_lower:
        return PiModel.PI_4_B
    elif "pi 3" in model_lower or "raspberry pi 3" in model_lower:
        return PiModel.PI_3_B

    return PiModel.UNKNOWN


def _create_hardware_info(pi_model: PiModel, model_name: str) -> HardwareInfo:
    """Create HardwareInfo with appropriate specs for the model.

    Args:
        pi_model: Detected PiModel enum
        model_name: Human-readable model name

    Returns:
        HardwareInfo with specs for the model
    """
    specs = HARDWARE_SPECS.get(pi_model, HARDWARE_SPECS[PiModel.UNKNOWN])

    # Try to get actual CPU count from os
    try:
        actual_cpu_count = os.cpu_count() or specs["cpu_count"]
    except Exception:
        actual_cpu_count = specs["cpu_count"]

    return HardwareInfo(
        model=pi_model,
        model_name=model_name,
        cpu_count=actual_cpu_count,
        ram_mb=specs["ram_mb"],
        cpu_max_mhz=specs["cpu_max_mhz"],
    )
