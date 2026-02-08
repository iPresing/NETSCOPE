"""Unit tests for WhitelistManager (Story 3.6, Task 2 + Task 9).

Tests cover:
- AC1: add() with IP, Port, IP:Port type inference
- AC2: get_all() returns complete list
- AC3: remove() by ID
- AC4: save()/load() JSON persistence
- Validation: reject duplicates, invalid formats
- is_whitelisted() matching
- get_whitelisted_anomaly_ids() returns correct IDs
- infer_entry_type() detection
"""

import json
from pathlib import Path

import pytest

from app.models.whitelist import WhitelistEntryType
from app.services.whitelist_manager import WhitelistManager


@pytest.fixture
def wl_file(tmp_path):
    """Create a temporary whitelist JSON file."""
    filepath = tmp_path / "whitelist.json"
    data = {"entries": [], "version": "1.0", "last_updated": None}
    filepath.write_text(json.dumps(data), encoding="utf-8")
    return filepath


@pytest.fixture
def manager(wl_file):
    """Create a WhitelistManager with temp file."""
    return WhitelistManager(wl_file)


class TestWhitelistManagerAdd:
    """Tests for add() method."""

    def test_add_ip(self, manager):
        """AC1: add() creates entry with IP type."""
        entry = manager.add("192.168.1.100", "Serveur local")
        assert entry.value == "192.168.1.100"
        assert entry.entry_type == WhitelistEntryType.IP
        assert entry.reason == "Serveur local"
        assert entry.id.startswith("wl_")

    def test_add_port(self, manager):
        """AC1: add() creates entry with PORT type."""
        entry = manager.add("8080")
        assert entry.value == "8080"
        assert entry.entry_type == WhitelistEntryType.PORT

    def test_add_ip_port(self, manager):
        """AC1: add() creates entry with IP_PORT type."""
        entry = manager.add("192.168.1.100:8080")
        assert entry.value == "192.168.1.100:8080"
        assert entry.entry_type == WhitelistEntryType.IP_PORT

    def test_add_domain(self, manager):
        """add() creates entry with DOMAIN type."""
        entry = manager.add("malware-site.local")
        assert entry.value == "malware-site.local"
        assert entry.entry_type == WhitelistEntryType.DOMAIN

    def test_add_domain_with_port_normalizes(self, manager):
        """add() strips port from domain:port and stores domain only."""
        entry = manager.add("malware-site.local:53")
        assert entry.value == "malware-site.local"
        assert entry.entry_type == WhitelistEntryType.DOMAIN

    def test_add_domain_lowercased(self, manager):
        """add() lowercases domain values."""
        entry = manager.add("MalWare.COM")
        assert entry.value == "malware.com"
        assert entry.entry_type == WhitelistEntryType.DOMAIN

    def test_add_rejects_invalid_format(self, manager):
        """add() rejects invalid format."""
        with pytest.raises(ValueError, match="Format invalide"):
            manager.add("!!!invalid!!!")

    def test_add_rejects_duplicate(self, manager):
        """add() rejects duplicate value."""
        manager.add("192.168.1.100")
        with pytest.raises(ValueError, match="Doublon"):
            manager.add("192.168.1.100")

    def test_add_rejects_invalid_ip_in_ip_port(self, manager):
        """add() rejects invalid IP in IP:Port."""
        with pytest.raises(ValueError, match="Format invalide"):
            manager.add("999.999.999.999:80")

    def test_add_rejects_invalid_port_in_ip_port(self, manager):
        """add() rejects invalid port in IP:Port."""
        with pytest.raises(ValueError, match="Port invalide"):
            manager.add("192.168.1.1:99999")

    def test_add_rejects_port_out_of_range(self, manager):
        """add() rejects port outside 1-65535."""
        with pytest.raises(ValueError, match="Port hors limites"):
            manager.add("0")

    def test_add_rejects_empty_value(self, manager):
        """add() rejects empty string."""
        with pytest.raises(ValueError, match="Valeur vide"):
            manager.add("")

    def test_add_rejects_whitespace_only(self, manager):
        """add() rejects whitespace-only string."""
        with pytest.raises(ValueError, match="Valeur vide"):
            manager.add("   ")


class TestWhitelistManagerRemove:
    """Tests for remove() method."""

    def test_remove_by_id(self, manager):
        """AC3: remove() deletes by ID."""
        entry = manager.add("192.168.1.100")
        removed = manager.remove(entry.id)
        assert removed.id == entry.id
        assert len(manager.get_all()) == 0

    def test_remove_nonexistent_id(self, manager):
        """remove() raises KeyError for unknown ID."""
        with pytest.raises(KeyError, match="non trouvee"):
            manager.remove("wl_nonexistent")


class TestWhitelistManagerGetAll:
    """Tests for get_all() method."""

    def test_get_all_empty(self, manager):
        """get_all() returns empty list initially."""
        assert manager.get_all() == []

    def test_get_all_returns_complete_list(self, manager):
        """AC2: get_all() returns all entries."""
        manager.add("192.168.1.1")
        manager.add("8080")
        manager.add("10.0.0.1:443")
        entries = manager.get_all()
        assert len(entries) == 3

    def test_get_all_returns_copy(self, manager):
        """get_all() returns a copy, not the internal list."""
        manager.add("192.168.1.1")
        entries = manager.get_all()
        entries.clear()
        assert len(manager.get_all()) == 1


class TestWhitelistManagerGetById:
    """Tests for get_by_id() method."""

    def test_get_by_id_found(self, manager):
        entry = manager.add("192.168.1.100")
        result = manager.get_by_id(entry.id)
        assert result is not None
        assert result.id == entry.id

    def test_get_by_id_not_found(self, manager):
        result = manager.get_by_id("wl_nonexistent")
        assert result is None


class TestWhitelistManagerIsWhitelisted:
    """Tests for is_whitelisted() method."""

    def test_is_whitelisted_ip_match(self, manager):
        """is_whitelisted() matches IP."""
        manager.add("192.168.1.100")
        assert manager.is_whitelisted(ip="192.168.1.100") is True

    def test_is_whitelisted_ip_no_match(self, manager):
        manager.add("192.168.1.100")
        assert manager.is_whitelisted(ip="10.0.0.1") is False

    def test_is_whitelisted_port_match(self, manager):
        """is_whitelisted() matches Port."""
        manager.add("8080")
        assert manager.is_whitelisted(port=8080) is True

    def test_is_whitelisted_port_no_match(self, manager):
        manager.add("8080")
        assert manager.is_whitelisted(port=9090) is False

    def test_is_whitelisted_ip_port_match(self, manager):
        """is_whitelisted() matches IP:Port combination."""
        manager.add("192.168.1.100:8080")
        assert manager.is_whitelisted(ip="192.168.1.100", port=8080) is True

    def test_is_whitelisted_ip_port_partial_no_match(self, manager):
        """IP:Port entry does not match IP alone."""
        manager.add("192.168.1.100:8080")
        assert manager.is_whitelisted(ip="192.168.1.100") is False

    def test_is_whitelisted_domain_match(self, manager):
        """is_whitelisted() matches domain (case-insensitive)."""
        manager.add("malware.com")
        assert manager.is_whitelisted(domain="malware.com") is True
        assert manager.is_whitelisted(domain="MalWare.COM") is True

    def test_is_whitelisted_domain_no_match(self, manager):
        manager.add("malware.com")
        assert manager.is_whitelisted(domain="safe.com") is False

    def test_is_whitelisted_empty(self, manager):
        """Empty whitelist matches nothing."""
        assert manager.is_whitelisted(ip="192.168.1.100") is False


class TestWhitelistManagerPersistence:
    """Tests for save()/load() JSON persistence."""

    def test_save_and_load_roundtrip(self, wl_file):
        """AC4: Persistence JSON correcte."""
        manager1 = WhitelistManager(wl_file)
        manager1.add("192.168.1.100", "Serveur")
        manager1.add("8080", "Port dev")

        # Create new manager from same file
        manager2 = WhitelistManager(wl_file)
        entries = manager2.get_all()
        assert len(entries) == 2
        assert entries[0].value == "192.168.1.100"
        assert entries[0].reason == "Serveur"
        assert entries[1].value == "8080"

    def test_load_nonexistent_file(self, tmp_path):
        """load() handles missing file gracefully."""
        manager = WhitelistManager(tmp_path / "missing.json")
        assert manager.get_all() == []

    def test_save_creates_directory(self, tmp_path):
        """save() creates parent directory if needed."""
        filepath = tmp_path / "subdir" / "whitelist.json"
        manager = WhitelistManager(filepath)
        manager.add("192.168.1.1")
        assert filepath.exists()

    def test_load_corrupt_json(self, tmp_path):
        """load() handles corrupt JSON gracefully."""
        filepath = tmp_path / "corrupt.json"
        filepath.write_text("not valid json", encoding="utf-8")
        manager = WhitelistManager(filepath)
        assert manager.get_all() == []

    def test_save_updates_last_updated(self, wl_file):
        """save() updates last_updated timestamp."""
        manager = WhitelistManager(wl_file)
        manager.add("192.168.1.1")
        data = json.loads(wl_file.read_text(encoding="utf-8"))
        assert data["last_updated"] is not None
        assert data["version"] == "1.0"


class TestWhitelistManagerGetWhitelistedAnomalyIds:
    """Tests for get_whitelisted_anomaly_ids() method."""

    def test_returns_matching_ids_from_dicts(self, manager):
        """get_whitelisted_anomaly_ids() matches dict anomalies."""
        manager.add("192.168.1.100")
        anomalies = [
            {"id": "a1", "ip": "192.168.1.100", "port": 80},
            {"id": "a2", "ip": "10.0.0.1", "port": 80},
        ]
        result = manager.get_whitelisted_anomaly_ids(anomalies)
        assert result == {"a1"}

    def test_returns_empty_for_no_matches(self, manager):
        manager.add("192.168.1.100")
        anomalies = [
            {"id": "a1", "ip": "10.0.0.1", "port": 80},
        ]
        result = manager.get_whitelisted_anomaly_ids(anomalies)
        assert result == set()

    def test_matches_port_entries(self, manager):
        manager.add("8080")
        anomalies = [
            {"id": "a1", "ip": "10.0.0.1", "port": 8080},
            {"id": "a2", "ip": "10.0.0.2", "port": 443},
        ]
        result = manager.get_whitelisted_anomaly_ids(anomalies)
        assert result == {"a1"}

    def test_matches_ip_port_entries(self, manager):
        manager.add("192.168.1.100:8080")
        anomalies = [
            {"id": "a1", "ip": "192.168.1.100", "port": 8080},
            {"id": "a2", "ip": "192.168.1.100", "port": 443},
        ]
        result = manager.get_whitelisted_anomaly_ids(anomalies)
        assert result == {"a1"}

    def test_matches_object_anomalies(self, manager):
        """get_whitelisted_anomaly_ids() matches object anomalies with packet_info."""
        manager.add("192.168.1.100")

        class MockMatch:
            def __init__(self, match_type_value, matched_value):
                self.match_type = type('MT', (), {'value': match_type_value})()
                self.matched_value = matched_value

        class MockAnomaly:
            def __init__(self, id, packet_info, match):
                self.id = id
                self.packet_info = packet_info
                self.match = match

        anomalies = [
            MockAnomaly("a1", {"ip_src": "192.168.1.100", "port_dst": 80}, MockMatch("ip", "192.168.1.100")),
            MockAnomaly("a2", {"ip_src": "10.0.0.1", "port_dst": 80}, MockMatch("ip", "10.0.0.1")),
        ]
        result = manager.get_whitelisted_anomaly_ids(anomalies)
        assert result == {"a1"}

    def test_matches_domain_anomalies(self, manager):
        """get_whitelisted_anomaly_ids() matches domain anomalies."""
        manager.add("malware-site.local")

        class MockMatch:
            def __init__(self, match_type_value, matched_value):
                self.match_type = type('MT', (), {'value': match_type_value})()
                self.matched_value = matched_value

        class MockAnomaly:
            def __init__(self, id, packet_info, match):
                self.id = id
                self.packet_info = packet_info
                self.match = match

        anomalies = [
            MockAnomaly("a1", {"ip_src": "192.168.1.10", "ip_dst": "10.0.0.1", "port_dst": 53}, MockMatch("domain", "malware-site.local")),
            MockAnomaly("a2", {"ip_src": "192.168.1.10", "ip_dst": "10.0.0.2", "port_dst": 53}, MockMatch("domain", "safe-site.com")),
        ]
        result = manager.get_whitelisted_anomaly_ids(anomalies)
        assert result == {"a1"}

    def test_matches_domain_dict_anomalies(self, manager):
        """get_whitelisted_anomaly_ids() matches domain in dict anomalies."""
        manager.add("evil.example.com")
        anomalies = [
            {"id": "a1", "domain": "evil.example.com", "ip": None, "port": None},
            {"id": "a2", "domain": "good.example.com", "ip": None, "port": None},
        ]
        result = manager.get_whitelisted_anomaly_ids(anomalies)
        assert result == {"a1"}

    def test_matches_blacklisted_dst_ip_with_port(self, manager):
        """get_whitelisted_anomaly_ids() matches when blacklisted IP is destination (ip_port entry)."""
        manager.add("8.8.8.8:4444")

        class MockMatch:
            def __init__(self, match_type_value, matched_value):
                self.match_type = type('MT', (), {'value': match_type_value})()
                self.matched_value = matched_value

        class MockAnomaly:
            def __init__(self, id, packet_info, match):
                self.id = id
                self.packet_info = packet_info
                self.match = match

        # IP blacklistee en destination, IP locale en source
        anomalies = [
            MockAnomaly("a1", {"ip_src": "192.168.1.10", "ip_dst": "8.8.8.8", "port_src": 54321, "port_dst": 4444}, MockMatch("ip", "8.8.8.8")),
            MockAnomaly("a2", {"ip_src": "192.168.1.10", "ip_dst": "1.1.1.1", "port_src": 54322, "port_dst": 53}, MockMatch("ip", "1.1.1.1")),
        ]
        result = manager.get_whitelisted_anomaly_ids(anomalies)
        assert result == {"a1"}
