"""TcpdumpManager module for NETSCOPE.

Manages tcpdump capture process with support for both Linux and Windows (via WSL).
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from app.models.capture import (
    CaptureConfig,
    CaptureError,
    CaptureResult,
    CaptureSession,
    CaptureStatus,
    CAPTURE_ALREADY_RUNNING,
    CAPTURE_FAILED,
    CAPTURE_INTERFACE_NOT_FOUND,
    CAPTURE_NOT_RUNNING,
    DEFAULT_CAPTURE_DURATION,
    validate_duration,
)
from app.core.capture.bpf_filters import validate_filter, DEFAULT_BPF_FILTER
from app.core.capture.interface_detector import (
    detect_interfaces,
    get_recommended_interface,
    NetworkInterface,
)
from app.services.thread_manager import get_thread_manager

logger = logging.getLogger(__name__)


def is_windows() -> bool:
    """Detect if running on Windows.

    Returns:
        True if running on Windows, False otherwise
    """
    return platform.system() == "Windows"


def get_wsl_path(windows_path: str) -> str:
    """Convert Windows path to WSL path.

    Args:
        windows_path: Windows-style path (e.g., 'C:\\Users\\...')

    Returns:
        WSL-style path (e.g., '/mnt/c/Users/...')

    Example:
        get_wsl_path("C:\\Users\\timit\\Documents")
        # Returns: "/mnt/c/Users/timit/Documents"
    """
    # Normalize path separators
    path = windows_path.replace("\\", "/")

    # Convert drive letter
    if len(path) >= 2 and path[1] == ":":
        drive = path[0].lower()
        path = f"/mnt/{drive}{path[2:]}"

    return path


def get_windows_path_from_wsl(wsl_path: str) -> str:
    """Convert WSL path back to Windows path.

    Args:
        wsl_path: WSL-style path (e.g., '/mnt/c/Users/...')

    Returns:
        Windows-style path (e.g., 'C:\\Users\\...')
    """
    if wsl_path.startswith("/mnt/") and len(wsl_path) > 6:
        drive = wsl_path[5].upper()
        rest = wsl_path[6:].replace("/", "\\")
        return f"{drive}:{rest}"
    return wsl_path


class TcpdumpManager:
    """Manages tcpdump capture process.

    Singleton class that handles starting, stopping, and monitoring
    tcpdump captures. Supports both direct Linux execution and
    WSL execution on Windows.
    """

    _instance: Optional["TcpdumpManager"] = None
    _process: Optional[subprocess.Popen] = None
    _current_session: Optional[CaptureSession] = None
    _monitor_thread: Optional[threading.Thread] = None
    _latest_result: Optional[CaptureResult] = None
    _stop_requested: bool = False

    def __new__(cls) -> "TcpdumpManager":
        """Singleton pattern implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize TcpdumpManager."""
        if getattr(self, "_initialized", False):
            return

        self._process = None
        self._current_session = None
        self._monitor_thread = None
        self._latest_result = None
        self._stop_requested = False
        self._data_dir = self._ensure_data_directory()
        self._initialized = True

        logger.info(
            f"TcpdumpManager initialized "
            f"(platform={platform.system()}, data_dir={self._data_dir})"
        )

    def _ensure_data_directory(self) -> Path:
        """Ensure capture data directory exists.

        Returns:
            Path to data directory
        """
        # Get project root and create data/captures directory
        # Use relative path from current working directory
        data_dir = Path("data/captures")

        if is_windows():
            # On Windows, use absolute path for WSL compatibility
            cwd = Path.cwd()
            data_dir = cwd / "data" / "captures"

        data_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Data directory ensured (path={data_dir})")
        return data_dir

    def start_capture(
        self,
        duration: int = DEFAULT_CAPTURE_DURATION,
        interface: str = "auto",
        bpf_filter: str | None = None,
        on_complete: Callable[[CaptureResult], None] | None = None,
    ) -> CaptureSession:
        """Start a tcpdump capture.

        Args:
            duration: Capture duration in seconds (30-600)
            interface: Network interface name or "auto" for auto-detect
            bpf_filter: BPF filter string (None for default)
            on_complete: Optional callback when capture completes

        Returns:
            CaptureSession object with session details

        Raises:
            CaptureError: If capture cannot be started
        """
        # Validate duration
        duration = validate_duration(duration)

        # Validate filter
        bpf_filter = validate_filter(bpf_filter)

        # Acquire exclusive capture lock
        tm = get_thread_manager()
        if not tm.acquire_capture_lock(blocking=False):
            logger.warning("Capture already running, rejecting new request")
            raise CaptureError(
                code=CAPTURE_ALREADY_RUNNING,
                message="Une capture est d\u00e9j\u00e0 en cours",
                details={"current_session": self._current_session.id if self._current_session else None},
            )

        try:
            # Resolve interface
            resolved_interface = self._resolve_interface(interface)

            # Generate capture file path
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            capture_id = f"cap_{timestamp}"
            capture_path = self._data_dir / f"{capture_id}.pcap"

            # Create session
            config = CaptureConfig(
                duration=duration,
                interface=resolved_interface,
                bpf_filter=bpf_filter,
            )
            session = CaptureSession(
                id=capture_id,
                config=config,
                status=CaptureStatus.RUNNING,
                start_time=datetime.utcnow(),
                capture_path=capture_path,
            )

            # Build and execute command
            cmd = self._build_tcpdump_command(
                interface=resolved_interface,
                output_path=str(capture_path),
                duration=duration,
                bpf_filter=bpf_filter,
            )

            logger.info(
                f"Starting capture "
                f"(capture_id={capture_id}, interface={resolved_interface}, "
                f"duration={duration}, filter={bpf_filter})"
            )

            # Start subprocess (shell=False for security - command is always a list)
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            session.pid = self._process.pid

            self._current_session = session
            self._stop_requested = False

            # Register thread with ThreadManager
            thread_name = f"capture-tcpdump-{timestamp}"
            self._monitor_thread = threading.Thread(
                target=self._monitor_capture,
                args=(duration, on_complete),
                name=thread_name,
                daemon=True,
            )
            tm.register_thread(thread_name, self._monitor_thread)
            self._monitor_thread.start()

            logger.info(
                f"Capture started successfully "
                f"(capture_id={capture_id}, pid={session.pid})"
            )

            return session

        except CaptureError:
            tm.release_capture_lock()
            raise
        except Exception as e:
            tm.release_capture_lock()
            logger.error(f"Capture failed to start (error={str(e)})")
            raise CaptureError(
                code=CAPTURE_FAILED,
                message=f"Failed to start capture: {str(e)}",
                details={"error": str(e)},
            )

    def stop_capture(self) -> CaptureSession:
        """Stop the current capture.

        Returns:
            The stopped CaptureSession

        Raises:
            CaptureError: If no capture is running
        """
        if self._current_session is None or not self._current_session.is_running:
            raise CaptureError(
                code=CAPTURE_NOT_RUNNING,
                message="Aucune capture en cours",
            )

        logger.info(f"Stopping capture (capture_id={self._current_session.id})")

        self._stop_requested = True

        # Terminate the process
        if self._process is not None:
            try:
                self._process.terminate()
                # Give it a moment to terminate gracefully
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("Capture process did not terminate, killing")
                self._process.kill()
            except Exception as e:
                logger.error(f"Error terminating capture process (error={str(e)})")

        # Update session status
        self._current_session.status = CaptureStatus.STOPPED
        self._current_session.end_time = datetime.utcnow()

        logger.info(
            f"Capture stopped "
            f"(capture_id={self._current_session.id}, "
            f"duration={self._current_session.duration_elapsed:.1f}s)"
        )

        return self._current_session

    def get_status(self) -> CaptureSession | None:
        """Get current capture status.

        Returns:
            Current CaptureSession or None if no capture
        """
        return self._current_session

    def get_latest_result(self) -> CaptureResult | None:
        """Get the result of the last completed capture.

        Returns:
            CaptureResult or None if no completed capture
        """
        return self._latest_result

    def is_running(self) -> bool:
        """Check if a capture is currently running.

        Returns:
            True if capture is running, False otherwise
        """
        return (
            self._current_session is not None
            and self._current_session.status == CaptureStatus.RUNNING
        )

    def _resolve_interface(self, interface: str) -> str:
        """Resolve interface name.

        Args:
            interface: Interface name or "auto"

        Returns:
            Resolved interface name

        Raises:
            CaptureError: If interface not found
        """
        if interface == "auto":
            interfaces = detect_interfaces()
            recommended = get_recommended_interface(interfaces)
            if recommended is None:
                logger.warning("No network interface found for auto-detection")
                # Default to eth0 for WSL
                if is_windows():
                    return "eth0"
                raise CaptureError(
                    code=CAPTURE_INTERFACE_NOT_FOUND,
                    message="Aucune interface r\u00e9seau disponible",
                )
            logger.info(f"Auto-selected interface (interface={recommended.name})")
            return recommended.name

        # Validate interface exists (skip on Windows as we use WSL interfaces)
        if not is_windows():
            interfaces = detect_interfaces()
            if not any(i.name == interface for i in interfaces):
                logger.warning(f"Interface not found (interface={interface})")
                raise CaptureError(
                    code=CAPTURE_INTERFACE_NOT_FOUND,
                    message=f"Interface '{interface}' introuvable",
                    details={"interface": interface},
                )

        return interface

    def _build_tcpdump_command(
        self,
        interface: str,
        output_path: str,
        duration: int,
        bpf_filter: str,
    ) -> list[str]:
        """Build tcpdump command.

        Args:
            interface: Network interface name
            output_path: Path to save capture file
            duration: Capture duration in seconds
            bpf_filter: BPF filter string

        Returns:
            Command as list of arguments (always list, never shell string for security)
        """
        if is_windows():
            # On Windows: wrap with WSL using list format (avoids shell=True)
            wsl_output_path = get_wsl_path(output_path)
            wsl_cwd = get_wsl_path(str(Path.cwd()))

            # Build the bash command string that will be passed to WSL
            # Note: The inner command is a string passed to bash -c, but
            # the outer command is a list passed to subprocess (shell=False)
            bash_cmd = (
                f"cd '{wsl_cwd}' && "
                f"sudo tcpdump -i {interface} -s 100 "
                f"-w '{wsl_output_path}' "
                f"-G {duration} -W 1 '{bpf_filter}'"
            )

            # Return as list to avoid shell=True security risk
            cmd = ["wsl", "-e", "bash", "-c", bash_cmd]

            logger.debug(f"Built WSL command (cmd={cmd})")
            return cmd
        else:
            # On Linux: direct command
            cmd = [
                "sudo", "tcpdump",
                "-i", interface,
                "-s", "100",  # Headers-only (100 bytes)
                "-w", output_path,
                "-G", str(duration),
                "-W", "1",
                bpf_filter,
            ]
            logger.debug(f"Built Linux command (cmd={' '.join(cmd)})")
            return cmd

    def _monitor_capture(
        self,
        duration: int,
        on_complete: Callable[[CaptureResult], None] | None = None,
    ) -> None:
        """Monitor capture process and handle completion.

        Args:
            duration: Expected capture duration
            on_complete: Callback when capture completes
        """
        try:
            # Wait for process to complete
            if self._process is not None:
                # Wait with timeout slightly longer than duration
                timeout = duration + 30
                try:
                    stdout, stderr = self._process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Capture timed out after {timeout}s, terminating")
                    self._process.kill()
                    stdout, stderr = self._process.communicate()

                returncode = self._process.returncode

                # Log any stderr output
                if stderr:
                    stderr_text = stderr.decode("utf-8", errors="ignore")
                    if stderr_text.strip():
                        logger.debug(f"tcpdump stderr: {stderr_text}")

                # Update session status
                if self._current_session is not None:
                    self._current_session.end_time = datetime.utcnow()

                    if self._stop_requested:
                        self._current_session.status = CaptureStatus.STOPPED
                    elif returncode == 0 or returncode == -15:  # -15 = SIGTERM
                        self._current_session.status = CaptureStatus.COMPLETED
                        logger.info(
                            f"Capture completed successfully "
                            f"(capture_id={self._current_session.id})"
                        )
                    else:
                        self._current_session.status = CaptureStatus.ERROR
                        self._current_session.error_message = f"tcpdump exited with code {returncode}"
                        logger.error(
                            f"Capture failed "
                            f"(capture_id={self._current_session.id}, code={returncode})"
                        )

                    # Parse results if file exists
                    result = self._create_result()
                    self._latest_result = result

                    # Call completion callback
                    if on_complete and result:
                        try:
                            on_complete(result)
                        except Exception as e:
                            logger.error(f"Capture completion callback failed (error={str(e)})")

        except Exception as e:
            logger.error(f"Error monitoring capture (error={str(e)})")
            if self._current_session is not None:
                self._current_session.status = CaptureStatus.ERROR
                self._current_session.error_message = str(e)
                self._current_session.end_time = datetime.utcnow()

        finally:
            # Release capture lock
            tm = get_thread_manager()
            tm.release_capture_lock()

            # Unregister thread
            if self._monitor_thread is not None:
                tm.unregister_thread(self._monitor_thread.name)

            # Clean up process reference
            self._process = None

    def _create_result(self) -> CaptureResult | None:
        """Create CaptureResult from current session.

        Automatically parses the capture file if it exists and the capture
        completed successfully.

        Returns:
            CaptureResult or None if no session
        """
        if self._current_session is None:
            return None

        from app.models.capture import CaptureResult, CaptureSummary
        from app.core.capture.packet_parser import parse_capture_file

        packets = []
        summary = CaptureSummary(
            duration_actual=self._current_session.duration_elapsed,
        )

        # Parse capture file if it exists and capture was successful
        capture_path = self._current_session.capture_path
        if (
            capture_path is not None
            and capture_path.exists()
            and self._current_session.status in (CaptureStatus.COMPLETED, CaptureStatus.STOPPED)
        ):
            try:
                packets, summary = parse_capture_file(capture_path)
                # Preserve the actual duration from session
                summary.duration_actual = self._current_session.duration_elapsed
                logger.info(
                    f"Parsed capture file "
                    f"(capture_id={self._current_session.id}, packets={len(packets)})"
                )
            except Exception as e:
                logger.warning(
                    f"Failed to parse capture file "
                    f"(capture_id={self._current_session.id}, error={str(e)})"
                )

        result = CaptureResult(
            session=self._current_session,
            packets=packets,
            summary=summary,
        )

        return result


# Module-level singleton accessor
_tcpdump_manager: Optional[TcpdumpManager] = None


def get_tcpdump_manager() -> TcpdumpManager:
    """Get the TcpdumpManager singleton instance.

    Returns:
        TcpdumpManager instance
    """
    global _tcpdump_manager

    if _tcpdump_manager is None:
        _tcpdump_manager = TcpdumpManager()

    return _tcpdump_manager


def reset_tcpdump_manager() -> None:
    """Reset the TcpdumpManager singleton (for testing)."""
    global _tcpdump_manager
    _tcpdump_manager = None
    TcpdumpManager._instance = None
