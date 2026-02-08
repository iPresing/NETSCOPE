"""Unit tests for whitelist model (Story 3.6, Task 1).

Tests cover:
- WhitelistEntryType enum values
- WhitelistEntry to_dict() serialization
- WhitelistEntry from_dict() deserialization
- infer_entry_type() detection for IP, Port, IP:Port
- create_entry() factory function
"""

from datetime import datetime, timezone

import pytest

from app.models.whitelist import (
    WhitelistEntry,
    WhitelistEntryType,
    create_entry,
    infer_entry_type,
)


class TestWhitelistEntryType:
    """Tests for WhitelistEntryType enum."""

    def test_ip_value(self):
        assert WhitelistEntryType.IP.value == "ip"

    def test_port_value(self):
        assert WhitelistEntryType.PORT.value == "port"

    def test_ip_port_value(self):
        assert WhitelistEntryType.IP_PORT.value == "ip_port"


class TestWhitelistEntry:
    """Tests for WhitelistEntry dataclass."""

    def _make_entry(self, **kwargs):
        defaults = {
            "id": "wl_abc12345",
            "value": "192.168.1.100",
            "entry_type": WhitelistEntryType.IP,
            "reason": "Serveur local",
            "created_at": datetime(2026, 2, 7, 10, 30, 0, tzinfo=timezone.utc),
        }
        defaults.update(kwargs)
        return WhitelistEntry(**defaults)

    def test_to_dict_ip(self):
        entry = self._make_entry()
        result = entry.to_dict()
        assert result["id"] == "wl_abc12345"
        assert result["value"] == "192.168.1.100"
        assert result["entry_type"] == "ip"
        assert result["reason"] == "Serveur local"
        assert "2026-02-07" in result["created_at"]

    def test_to_dict_port(self):
        entry = self._make_entry(
            value="8080",
            entry_type=WhitelistEntryType.PORT,
        )
        result = entry.to_dict()
        assert result["entry_type"] == "port"
        assert result["value"] == "8080"

    def test_to_dict_ip_port(self):
        entry = self._make_entry(
            value="192.168.1.100:8080",
            entry_type=WhitelistEntryType.IP_PORT,
        )
        result = entry.to_dict()
        assert result["entry_type"] == "ip_port"
        assert result["value"] == "192.168.1.100:8080"

    def test_from_dict(self):
        data = {
            "id": "wl_abc12345",
            "value": "192.168.1.100",
            "entry_type": "ip",
            "reason": "Serveur local",
            "created_at": "2026-02-07T10:30:00+00:00",
        }
        entry = WhitelistEntry.from_dict(data)
        assert entry.id == "wl_abc12345"
        assert entry.value == "192.168.1.100"
        assert entry.entry_type == WhitelistEntryType.IP
        assert entry.reason == "Serveur local"
        assert entry.created_at.year == 2026

    def test_from_dict_missing_reason(self):
        data = {
            "id": "wl_xyz",
            "value": "8080",
            "entry_type": "port",
            "created_at": "2026-02-07T10:30:00+00:00",
        }
        entry = WhitelistEntry.from_dict(data)
        assert entry.reason == ""

    def test_roundtrip_serialization(self):
        original = self._make_entry()
        serialized = original.to_dict()
        restored = WhitelistEntry.from_dict(serialized)
        assert restored.id == original.id
        assert restored.value == original.value
        assert restored.entry_type == original.entry_type
        assert restored.reason == original.reason


class TestInferEntryType:
    """Tests for infer_entry_type() function."""

    def test_ip_address(self):
        assert infer_entry_type("192.168.1.100") == WhitelistEntryType.IP

    def test_port_number(self):
        assert infer_entry_type("8080") == WhitelistEntryType.PORT

    def test_port_min(self):
        assert infer_entry_type("1") == WhitelistEntryType.PORT

    def test_port_max(self):
        assert infer_entry_type("65535") == WhitelistEntryType.PORT

    def test_ip_port_combination(self):
        assert infer_entry_type("192.168.1.100:8080") == WhitelistEntryType.IP_PORT

    def test_ip_port_with_standard_port(self):
        assert infer_entry_type("10.0.0.1:443") == WhitelistEntryType.IP_PORT

    def test_non_numeric_treated_as_ip(self):
        assert infer_entry_type("10.0.0.1") == WhitelistEntryType.IP


class TestCreateEntry:
    """Tests for create_entry() factory function."""

    def test_creates_ip_entry(self):
        entry = create_entry("192.168.1.100", "Serveur test")
        assert entry.value == "192.168.1.100"
        assert entry.entry_type == WhitelistEntryType.IP
        assert entry.reason == "Serveur test"
        assert entry.id.startswith("wl_")
        assert entry.created_at is not None

    def test_creates_port_entry(self):
        entry = create_entry("8080")
        assert entry.value == "8080"
        assert entry.entry_type == WhitelistEntryType.PORT
        assert entry.reason == ""

    def test_creates_ip_port_entry(self):
        entry = create_entry("192.168.1.100:8080")
        assert entry.value == "192.168.1.100:8080"
        assert entry.entry_type == WhitelistEntryType.IP_PORT

    def test_strips_whitespace(self):
        entry = create_entry("  192.168.1.100  ", "  Raison  ")
        assert entry.value == "192.168.1.100"
        assert entry.reason == "Raison"

    def test_unique_ids(self):
        entry1 = create_entry("192.168.1.1")
        entry2 = create_entry("192.168.1.2")
        assert entry1.id != entry2.id
