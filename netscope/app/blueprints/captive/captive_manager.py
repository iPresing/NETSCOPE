"""Captive portal state manager for NETSCOPE.

Tracks released client IPs and manages the global captive portal
toggle (DNS hijack + iptables DNAT) via the system toggle script.
"""

import logging
import subprocess
import threading

logger = logging.getLogger(__name__)

_captive_manager: 'CaptiveManager | None' = None
_lock = threading.Lock()

TOGGLE_SCRIPT = '/usr/local/sbin/netscope-captive-toggle.sh'


class CaptiveManager:
    """Manages captive portal state and client releases.

    The captive portal starts active at boot. When any client is
    released, the global DNS hijack and DNAT rules are disabled,
    allowing all clients to browse normally.
    """

    def __init__(self) -> None:
        self._released_ips: set[str] = set()
        self._captive_active: bool = True
        self._lock = threading.Lock()

    def is_captive_active(self) -> bool:
        """Check if captive portal mode is globally active."""
        return self._captive_active

    def is_released(self, client_ip: str) -> bool:
        """Check if a client IP has been released from the portal."""
        with self._lock:
            return client_ip in self._released_ips

    def release_client(self, client_ip: str) -> bool:
        """Release a client and disable captive mode globally.

        Args:
            client_ip: The client IP address to release.

        Returns:
            True if release succeeded.
        """
        with self._lock:
            self._released_ips.add(client_ip)
            should_disable = self._captive_active
            if should_disable:
                self._captive_active = False

        if should_disable:
            self._disable_captive()

        logger.info('Client %s released from captive portal', client_ip)
        return True

    def get_status(self) -> dict:
        """Get current captive portal status."""
        with self._lock:
            return {
                'captive_active': self._captive_active,
                'released_clients': len(self._released_ips),
            }

    def _disable_captive(self) -> None:
        """Disable captive mode globally via system toggle script."""
        try:
            result = subprocess.run(
                [TOGGLE_SCRIPT, 'disable'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info('Captive portal disabled via toggle script')
            else:
                logger.warning(
                    'Captive toggle script returned %d: %s',
                    result.returncode,
                    result.stderr.strip(),
                )
        except FileNotFoundError:
            logger.info(
                'Toggle script not found at %s (not running on Pi)',
                TOGGLE_SCRIPT,
            )
        except subprocess.TimeoutExpired:
            logger.error('Captive toggle script timed out')
        except Exception as e:
            logger.error('Failed to run captive toggle: %s', str(e))


def get_captive_manager() -> CaptiveManager:
    """Get or create the singleton CaptiveManager."""
    global _captive_manager
    if _captive_manager is None:
        with _lock:
            if _captive_manager is None:
                _captive_manager = CaptiveManager()
    return _captive_manager


def reset_captive_manager() -> None:
    """Reset the singleton (for testing)."""
    global _captive_manager
    with _lock:
        _captive_manager = None
