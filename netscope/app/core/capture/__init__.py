# Network capture module

from app.core.capture.tcpdump_manager import (
    TcpdumpManager,
    get_tcpdump_manager,
    reset_tcpdump_manager,
    is_windows,
    get_wsl_path,
)
from app.core.capture.packet_parser import (
    parse_capture_file,
    get_capture_statistics,
    SCAPY_AVAILABLE,
    DPKT_AVAILABLE,
)
from app.core.capture.bpf_filters import (
    build_default_filter,
    validate_filter,
    combine_filters,
    build_capture_filter,
    DEFAULT_BPF_FILTER,
)
from app.core.capture.interface_detector import (
    InterfaceType,
    NetworkInterface,
    detect_interfaces,
    get_recommended_interface,
    get_current_ip,
)

__all__ = [
    # TcpdumpManager
    "TcpdumpManager",
    "get_tcpdump_manager",
    "reset_tcpdump_manager",
    "is_windows",
    "get_wsl_path",
    # Packet Parser
    "parse_capture_file",
    "get_capture_statistics",
    "SCAPY_AVAILABLE",
    "DPKT_AVAILABLE",
    # BPF Filters
    "build_default_filter",
    "validate_filter",
    "combine_filters",
    "build_capture_filter",
    "DEFAULT_BPF_FILTER",
    # Interface Detector
    "InterfaceType",
    "NetworkInterface",
    "detect_interfaces",
    "get_recommended_interface",
    "get_current_ip",
]
