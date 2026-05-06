"""Update service for checking GitHub releases.

Provides version comparison and update availability detection
via the GitHub Releases API.
"""

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import requests

from app.services.version_service import get_version_service

logger = logging.getLogger(__name__)

GITHUB_API_TIMEOUT = 10
USER_AGENT = "NETSCOPE-Updater/0.1.0"


class UpdateErrorCode(Enum):
    """Error codes for update check failures."""
    NETWORK_ERROR = "NETWORK_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    GITHUB_ERROR = "GITHUB_ERROR"
    PARSE_ERROR = "PARSE_ERROR"


@dataclass
class UpdateCheckResult:
    """Result of an update availability check."""
    update_available: bool
    current_version: str
    latest_version: Optional[str] = None
    changelog: Optional[str] = None
    published_at: Optional[str] = None
    release_url: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[UpdateErrorCode] = None

    def to_dict(self) -> dict:
        result = {
            "update_available": self.update_available,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "changelog": self.changelog,
            "published_at": self.published_at,
            "release_url": self.release_url,
        }
        if self.error:
            result["error"] = self.error
            result["error_code"] = self.error_code.value if self.error_code else None
        return result


def parse_version(v: str) -> tuple:
    """Parse 'v1.2.3' or '1.2.3-beta' into comparable tuple."""
    clean = v.strip().lstrip('v')
    clean = clean.split('-')[0].split('+')[0]
    return tuple(int(x) for x in clean.split('.'))


_instance: Optional['UpdateService'] = None


class UpdateService:
    """Singleton service for checking GitHub releases."""

    def __init__(self, github_repo: str, check_url_template: str):
        self._github_repo = github_repo
        self._check_url = check_url_template.format(repo=github_repo)

    def check_for_update(self) -> UpdateCheckResult:
        """Check GitHub API for latest release and compare versions."""
        current_version = get_version_service().get_version()

        try:
            response = requests.get(
                self._check_url,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": USER_AGENT,
                },
                timeout=GITHUB_API_TIMEOUT,
            )
        except requests.Timeout:
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Délai de connexion dépassé. Réessayez plus tard.",
                error_code=UpdateErrorCode.NETWORK_ERROR,
            )
        except requests.ConnectionError:
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Impossible de contacter GitHub. Vérifiez votre connexion internet.",
                error_code=UpdateErrorCode.NETWORK_ERROR,
            )

        if response.status_code in (403, 429):
            retry_msg = self._format_rate_limit_message(response)
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error=retry_msg,
                error_code=UpdateErrorCode.RATE_LIMITED,
            )

        if response.status_code == 404:
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Dépôt GitHub introuvable. Vérifiez la configuration.",
                error_code=UpdateErrorCode.GITHUB_ERROR,
            )

        if response.status_code != 200:
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error=f"Erreur GitHub (HTTP {response.status_code}).",
                error_code=UpdateErrorCode.GITHUB_ERROR,
            )

        try:
            data = response.json()
            tag_name = data["tag_name"]
            latest_version = tag_name.lstrip('v').strip()
            changelog = data.get("body", "")
            published_at = data.get("published_at", "")
            release_url = data.get("html_url", "")
        except (ValueError, KeyError, TypeError):
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Réponse inattendue de GitHub.",
                error_code=UpdateErrorCode.PARSE_ERROR,
            )

        try:
            update_available = parse_version(latest_version) > parse_version(current_version)
        except (ValueError, TypeError):
            return UpdateCheckResult(
                update_available=False,
                current_version=current_version,
                error="Réponse inattendue de GitHub.",
                error_code=UpdateErrorCode.PARSE_ERROR,
            )

        return UpdateCheckResult(
            update_available=update_available,
            current_version=current_version,
            latest_version=latest_version,
            changelog=changelog,
            published_at=published_at,
            release_url=release_url,
        )

    @staticmethod
    def _format_rate_limit_message(response: requests.Response) -> str:
        reset_timestamp = response.headers.get("X-RateLimit-Reset")
        if reset_timestamp:
            try:
                reset_time = int(reset_timestamp)
                minutes_remaining = max(1, int((reset_time - time.time()) / 60))
                return (
                    f"Limite de requêtes GitHub atteinte. "
                    f"Réessayez dans {minutes_remaining} minutes."
                )
            except (ValueError, TypeError):
                pass
        return "Limite de requêtes GitHub atteinte. Réessayez plus tard."


def get_update_service() -> UpdateService:
    """Get or create the UpdateService singleton."""
    global _instance
    if _instance is None:
        import yaml
        from pathlib import Path

        config_path = Path(__file__).parent.parent.parent / 'data' / 'config' / 'netscope.yaml'
        update_config = {}
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f) or {}
            update_config = config_data.get('update', {})

        github_repo = update_config.get('github_repo', 'iPresing/NETSCOPE')
        check_url = update_config.get(
            'check_url',
            'https://api.github.com/repos/{repo}/releases/latest'
        )
        _instance = UpdateService(github_repo=github_repo, check_url_template=check_url)
    return _instance


def reset_update_service() -> None:
    """Reset singleton for testing."""
    global _instance
    _instance = None
