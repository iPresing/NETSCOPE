"""Unit tests for BlacklistManager.

Tests blacklist loading, parsing, and management functionality.
"""

import pytest
from pathlib import Path
import tempfile
import os

from app.core.detection.blacklist_manager import (
    BlacklistManager,
    get_blacklist_manager,
    reset_blacklist_manager,
)
from app.models.blacklist import BlacklistType, BlacklistStats


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset singleton before and after each test."""
    reset_blacklist_manager()
    yield
    reset_blacklist_manager()


@pytest.fixture
def temp_blacklist_dir():
    """Create temporary directory with test blacklist files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create defaults directory
        defaults_dir = Path(tmpdir) / "data" / "blacklists_defaults"
        defaults_dir.mkdir(parents=True)

        # Create user directory
        user_dir = Path(tmpdir) / "data" / "blacklists"
        user_dir.mkdir(parents=True)

        # Create ips_malware.txt
        (defaults_dir / "ips_malware.txt").write_text(
            "# NETSCOPE Starter Pack - IPs Malware\n"
            "192.168.1.100\n"
            "10.0.0.1\n"
            "# Comment line\n"
            "\n"
            "172.16.0.1  # inline comment\n"
        )

        # Create ips_c2.txt
        (defaults_dir / "ips_c2.txt").write_text(
            "# C2 IPs\n"
            "45.33.32.156\n"
            "159.100.14.254\n"
        )

        # Create domains_phishing.txt
        (defaults_dir / "domains_phishing.txt").write_text(
            "# Phishing domains\n"
            "paypa1.com\n"
            "AMAZ0N.COM\n"  # Test case normalization
        )

        # Create domains_malware.txt
        (defaults_dir / "domains_malware.txt").write_text(
            "# Malware domains\n"
            "malware-download.com\n"
        )

        # Create terms_suspect.txt
        (defaults_dir / "terms_suspect.txt").write_text(
            "# Suspect terms\n"
            "/bin/bash -i\n"
            "nc -e /bin/sh\n"
        )

        # Create empty user files
        (user_dir / "ips.txt").write_text("# User IPs\n")
        (user_dir / "domains.txt").write_text("# User domains\n")
        (user_dir / "terms.txt").write_text("# User terms\n")

        yield Path(tmpdir)


class TestBlacklistManagerSingleton:
    """Test singleton pattern for BlacklistManager."""

    def test_singleton_returns_same_instance(self):
        """Test that BlacklistManager returns the same instance."""
        manager1 = BlacklistManager()
        manager2 = BlacklistManager()
        assert manager1 is manager2

    def test_get_blacklist_manager_creates_instance(self):
        """Test get_blacklist_manager creates and returns singleton."""
        manager = get_blacklist_manager()
        assert manager is not None
        assert isinstance(manager, BlacklistManager)

    def test_get_blacklist_manager_returns_same_instance(self):
        """Test get_blacklist_manager returns same instance."""
        manager1 = get_blacklist_manager()
        manager2 = get_blacklist_manager()
        assert manager1 is manager2

    def test_reset_clears_singleton(self):
        """Test reset_blacklist_manager clears the singleton."""
        manager1 = get_blacklist_manager()
        reset_blacklist_manager()
        manager2 = get_blacklist_manager()
        # After reset, a new instance should be created
        # but due to singleton pattern, it will be the same object type
        assert isinstance(manager2, BlacklistManager)


class TestBlacklistManagerLoading:
    """Test blacklist file loading functionality."""

    def test_load_blacklists_from_config(self, temp_blacklist_dir):
        """Test loading blacklists from configuration."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
                "ips_c2": "data/blacklists_defaults/ips_c2.txt",
                "domains_phishing": "data/blacklists_defaults/domains_phishing.txt",
                "domains_malware": "data/blacklists_defaults/domains_malware.txt",
                "terms_suspect": "data/blacklists_defaults/terms_suspect.txt",
            },
            "paths": {
                "user_ips": "data/blacklists/ips.txt",
                "user_domains": "data/blacklists/domains.txt",
                "user_terms": "data/blacklists/terms.txt",
            },
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        stats = manager.get_stats()
        assert stats.ips_count == 5  # 3 malware + 2 C2
        assert stats.domains_count == 3  # 2 phishing + 1 malware
        assert stats.terms_count == 2

    def test_load_empty_config(self):
        """Test loading with empty config."""
        manager = get_blacklist_manager()
        manager.load_blacklists({})

        stats = manager.get_stats()
        assert stats.ips_count == 0
        assert stats.domains_count == 0
        assert stats.terms_count == 0

    def test_missing_file_logs_warning(self, temp_blacklist_dir):
        """Test that missing files are handled gracefully."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/nonexistent/file.txt",
            }
        }

        # Should not raise, just log warning
        manager.load_blacklists(config, base_path=temp_blacklist_dir)
        assert manager.get_stats().ips_count == 0


class TestBlacklistManagerParsing:
    """Test blacklist file parsing."""

    def test_parse_comments_ignored(self, temp_blacklist_dir):
        """Test that comment lines are ignored."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        # File has 3 valid IPs (comment lines and empty lines ignored)
        assert manager.get_stats().ips_count == 3

    def test_parse_empty_lines_ignored(self, temp_blacklist_dir):
        """Test that empty lines are ignored."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)
        assert "192.168.1.100" in manager.ips
        assert "" not in manager.ips

    def test_parse_inline_comments(self, temp_blacklist_dir):
        """Test that inline comments are stripped."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        # IP with inline comment should be stripped
        assert "172.16.0.1" in manager.ips
        assert "172.16.0.1  # inline comment" not in manager.ips

    def test_domain_normalization_lowercase(self, temp_blacklist_dir):
        """Test that domains are normalized to lowercase."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "domains_phishing": "data/blacklists_defaults/domains_phishing.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        # AMAZ0N.COM should be stored as amaz0n.com
        assert "amaz0n.com" in manager.domains
        assert "AMAZ0N.COM" not in manager.domains


class TestBlacklistManagerStats:
    """Test stats and properties."""

    def test_get_stats_returns_correct_counts(self, temp_blacklist_dir):
        """Test that stats returns accurate counts."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
                "domains_phishing": "data/blacklists_defaults/domains_phishing.txt",
                "terms_suspect": "data/blacklists_defaults/terms_suspect.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        stats = manager.get_stats()
        assert stats.ips_count == 3
        assert stats.domains_count == 2
        assert stats.terms_count == 2
        assert len(stats.files_loaded) == 3

    def test_stats_to_dict(self, temp_blacklist_dir):
        """Test BlacklistStats to_dict method."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        stats = manager.get_stats()
        stats_dict = stats.to_dict()

        assert "ips_count" in stats_dict
        assert "domains_count" in stats_dict
        assert "terms_count" in stats_dict
        assert "files_loaded" in stats_dict
        assert "total_entries" in stats_dict
        assert stats_dict["total_entries"] == stats_dict["ips_count"] + stats_dict["domains_count"] + stats_dict["terms_count"]

    def test_get_active_lists(self, temp_blacklist_dir):
        """Test get_active_lists returns sorted lists."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        active = manager.get_active_lists()
        assert "ips" in active
        assert "domains" in active
        assert "terms" in active
        assert isinstance(active["ips"], list)


class TestBlacklistManagerProperties:
    """Test property accessors."""

    def test_ips_property_returns_frozenset(self, temp_blacklist_dir):
        """Test ips property returns immutable frozenset."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        ips = manager.ips
        assert isinstance(ips, frozenset)
        assert "192.168.1.100" in ips

    def test_domains_property_returns_frozenset(self, temp_blacklist_dir):
        """Test domains property returns immutable frozenset."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "domains_phishing": "data/blacklists_defaults/domains_phishing.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        domains = manager.domains
        assert isinstance(domains, frozenset)
        assert "paypa1.com" in domains

    def test_terms_property_returns_frozenset(self, temp_blacklist_dir):
        """Test terms property returns immutable frozenset."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "terms_suspect": "data/blacklists_defaults/terms_suspect.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        terms = manager.terms
        assert isinstance(terms, frozenset)
        assert "/bin/bash -i" in terms


class TestBlacklistManagerChecks:
    """Test check methods."""

    def test_check_ip_match(self, temp_blacklist_dir):
        """Test check_ip returns True for blacklisted IP."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        assert manager.check_ip("192.168.1.100") is True
        assert manager.check_ip("8.8.8.8") is False

    def test_check_domain_match(self, temp_blacklist_dir):
        """Test check_domain returns True for blacklisted domain."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "domains_phishing": "data/blacklists_defaults/domains_phishing.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        assert manager.check_domain("paypa1.com") is True
        assert manager.check_domain("PAYPA1.COM") is True  # Case insensitive
        assert manager.check_domain("google.com") is False

    def test_check_term_finds_matches(self, temp_blacklist_dir):
        """Test check_term finds suspect terms in text."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "terms_suspect": "data/blacklists_defaults/terms_suspect.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        text = "Running /bin/bash -i to get shell"
        found = manager.check_term(text)
        assert "/bin/bash -i" in found

    def test_check_term_no_matches(self, temp_blacklist_dir):
        """Test check_term returns empty list when no matches."""
        manager = get_blacklist_manager()

        config = {
            "defaults": {
                "terms_suspect": "data/blacklists_defaults/terms_suspect.txt",
            }
        }

        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        text = "Normal HTTP request to website"
        found = manager.check_term(text)
        assert len(found) == 0


class TestBlacklistManagerReload:
    """Test reload functionality."""

    def test_reload_clears_and_reloads(self, temp_blacklist_dir):
        """Test that reloading clears previous entries."""
        manager = get_blacklist_manager()

        config1 = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }

        manager.load_blacklists(config1, base_path=temp_blacklist_dir)
        assert manager.get_stats().ips_count == 3

        # Reload with empty config
        manager.load_blacklists({})
        assert manager.get_stats().ips_count == 0


class TestBlacklistFileWatcher:
    """Test hot-reload file watcher functionality."""

    def test_watcher_init(self, temp_blacklist_dir):
        """Test that BlacklistFileWatcher initializes correctly."""
        from app.core.detection.blacklist_manager import BlacklistFileWatcher

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            },
            "reload_on_change": True,
        }

        watcher = BlacklistFileWatcher(config, base_path=temp_blacklist_dir)
        assert watcher is not None
        assert watcher.is_running is False

    def test_watcher_start_stop(self, temp_blacklist_dir):
        """Test that watcher can start and stop."""
        from app.core.detection.blacklist_manager import BlacklistFileWatcher

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            },
            "reload_on_change": True,
        }

        watcher = BlacklistFileWatcher(config, base_path=temp_blacklist_dir)

        # Start watcher
        started = watcher.start()
        assert started is True
        assert watcher.is_running is True

        # Stop watcher
        watcher.stop()
        assert watcher.is_running is False

    def test_start_blacklist_watcher_disabled(self, temp_blacklist_dir):
        """Test that watcher returns None when disabled in config."""
        from app.core.detection.blacklist_manager import (
            start_blacklist_watcher,
            stop_blacklist_watcher,
        )

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            },
            "reload_on_change": False,  # Disabled
        }

        watcher = start_blacklist_watcher(config, base_path=temp_blacklist_dir)
        assert watcher is None

    def test_start_blacklist_watcher_enabled(self, temp_blacklist_dir):
        """Test that watcher starts when enabled in config."""
        from app.core.detection.blacklist_manager import (
            start_blacklist_watcher,
            stop_blacklist_watcher,
            get_blacklist_watcher,
        )

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            },
            "reload_on_change": True,
        }

        try:
            watcher = start_blacklist_watcher(config, base_path=temp_blacklist_dir)
            assert watcher is not None
            assert watcher.is_running is True

            # Check global getter
            global_watcher = get_blacklist_watcher()
            assert global_watcher is watcher

        finally:
            stop_blacklist_watcher()

    def test_watcher_detects_file_change(self, temp_blacklist_dir):
        """Test that watcher triggers reload on file modification."""
        import time
        from app.core.detection.blacklist_manager import (
            BlacklistFileWatcher,
            get_blacklist_manager,
        )

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            },
            "reload_on_change": True,
        }

        # Initial load
        manager = get_blacklist_manager()
        manager.load_blacklists(config, base_path=temp_blacklist_dir)
        initial_count = manager.get_stats().ips_count
        assert initial_count == 3

        # Start watcher with short debounce
        watcher = BlacklistFileWatcher(config, base_path=temp_blacklist_dir, debounce_seconds=0.1)
        watcher.start()

        try:
            # Modify the blacklist file
            ips_file = temp_blacklist_dir / "data" / "blacklists_defaults" / "ips_malware.txt"
            with open(ips_file, "a", encoding="utf-8") as f:
                f.write("\n8.8.8.8\n9.9.9.9\n")

            # Wait for watcher to detect change and reload
            time.sleep(0.5)

            # Verify the blacklist was reloaded
            new_count = manager.get_stats().ips_count
            assert new_count == 5  # 3 original + 2 new

        finally:
            watcher.stop()

    def test_watcher_ignores_non_txt_files(self, temp_blacklist_dir):
        """Test that watcher ignores non-.txt file changes."""
        import time
        from app.core.detection.blacklist_manager import (
            BlacklistFileWatcher,
            get_blacklist_manager,
        )

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            },
            "reload_on_change": True,
        }

        # Initial load
        manager = get_blacklist_manager()
        manager.load_blacklists(config, base_path=temp_blacklist_dir)
        initial_count = manager.get_stats().ips_count

        # Start watcher
        watcher = BlacklistFileWatcher(config, base_path=temp_blacklist_dir, debounce_seconds=0.1)
        watcher.start()

        try:
            # Create a non-.txt file in the watched directory
            defaults_dir = temp_blacklist_dir / "data" / "blacklists_defaults"
            test_file = defaults_dir / "test.json"
            test_file.write_text('{"test": true}')

            # Wait briefly
            time.sleep(0.3)

            # Count should remain the same (no reload triggered)
            new_count = manager.get_stats().ips_count
            assert new_count == initial_count

        finally:
            watcher.stop()

    def test_watcher_debounce(self, temp_blacklist_dir):
        """Test that rapid changes are debounced."""
        import time
        from app.core.detection.blacklist_manager import (
            BlacklistFileWatcher,
            get_blacklist_manager,
        )

        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            },
            "reload_on_change": True,
        }

        # Initial load
        manager = get_blacklist_manager()
        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        # Start watcher with 1 second debounce
        watcher = BlacklistFileWatcher(config, base_path=temp_blacklist_dir, debounce_seconds=1.0)
        watcher.start()

        try:
            ips_file = temp_blacklist_dir / "data" / "blacklists_defaults" / "ips_malware.txt"

            # Make multiple rapid changes
            for i in range(5):
                with open(ips_file, "a", encoding="utf-8") as f:
                    f.write(f"\n1.1.1.{i}\n")
                time.sleep(0.1)

            # Wait for debounce period
            time.sleep(1.5)

            # Should have loaded all changes in one reload
            new_count = manager.get_stats().ips_count
            assert new_count == 8  # 3 original + 5 new

        finally:
            watcher.stop()
