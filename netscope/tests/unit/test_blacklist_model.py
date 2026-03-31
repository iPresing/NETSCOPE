"""Tests unitaires pour le modèle blacklist user (Story 4b.6)."""

from datetime import datetime, timezone

import pytest

from app.models.blacklist import (
    BlacklistType,
    UserBlacklistEntry,
    create_user_blacklist_entry,
    infer_entry_type,
    validate_value,
)


class TestBlacklistType:
    """Tests de l'enum BlacklistType."""

    def test_types_values(self):
        assert BlacklistType.IP.value == "ip"
        assert BlacklistType.DOMAIN.value == "domain"
        assert BlacklistType.TERM.value == "term"

    def test_from_value(self):
        assert BlacklistType("ip") == BlacklistType.IP
        assert BlacklistType("domain") == BlacklistType.DOMAIN
        assert BlacklistType("term") == BlacklistType.TERM

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            BlacklistType("invalid")


class TestUserBlacklistEntry:
    """Tests de la dataclass UserBlacklistEntry."""

    def _make_entry(self, **overrides):
        defaults = {
            "id": "bl_abc12345",
            "entry_type": BlacklistType.IP,
            "value": "192.168.1.100",
            "reason": "Serveur suspect",
            "created_at": datetime(2026, 3, 30, 12, 0, 0, tzinfo=timezone.utc),
        }
        defaults.update(overrides)
        return UserBlacklistEntry(**defaults)

    def test_creation(self):
        entry = self._make_entry()
        assert entry.id == "bl_abc12345"
        assert entry.entry_type == BlacklistType.IP
        assert entry.value == "192.168.1.100"
        assert entry.reason == "Serveur suspect"

    def test_to_dict(self):
        entry = self._make_entry()
        d = entry.to_dict()
        assert d["id"] == "bl_abc12345"
        assert d["entry_type"] == "ip"
        assert d["value"] == "192.168.1.100"
        assert d["reason"] == "Serveur suspect"
        assert "created_at" in d

    def test_from_dict(self):
        data = {
            "id": "bl_xyz99999",
            "entry_type": "domain",
            "value": "evil.com",
            "reason": "Domaine malveillant",
            "created_at": "2026-03-30T12:00:00+00:00",
        }
        entry = UserBlacklistEntry.from_dict(data)
        assert entry.id == "bl_xyz99999"
        assert entry.entry_type == BlacklistType.DOMAIN
        assert entry.value == "evil.com"
        assert entry.reason == "Domaine malveillant"
        assert entry.created_at.tzinfo is not None

    def test_from_dict_missing_reason_defaults_empty(self):
        data = {
            "id": "bl_noreaso1",
            "entry_type": "term",
            "value": "malware",
            "created_at": "2026-03-30T12:00:00+00:00",
        }
        entry = UserBlacklistEntry.from_dict(data)
        assert entry.reason == ""

    def test_roundtrip_serialization(self):
        entry = self._make_entry()
        roundtrip = UserBlacklistEntry.from_dict(entry.to_dict())
        assert roundtrip.id == entry.id
        assert roundtrip.entry_type == entry.entry_type
        assert roundtrip.value == entry.value
        assert roundtrip.reason == entry.reason

    def test_to_dict_term_type(self):
        entry = self._make_entry(entry_type=BlacklistType.TERM, value="malware")
        d = entry.to_dict()
        assert d["entry_type"] == "term"
        assert d["value"] == "malware"


class TestValidateValue:
    """Tests de validate_value."""

    # IP valides
    @pytest.mark.parametrize("ip", [
        "192.168.1.1",
        "10.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "1.2.3.4",
    ])
    def test_valid_ip(self, ip):
        assert validate_value(BlacklistType.IP, ip) is True

    # IP invalides
    @pytest.mark.parametrize("ip", [
        "256.1.1.1",
        "192.168.1",
        "192.168.1.1.1",
        "abc.def.ghi.jkl",
        "",
        "   ",
        "not-an-ip",
    ])
    def test_invalid_ip(self, ip):
        assert validate_value(BlacklistType.IP, ip) is False

    # Domaines valides (RFC 1123)
    @pytest.mark.parametrize("domain", [
        "evil.com",
        "malware.example.org",
        "sub.domain.co.uk",
        "a.b",
        "test-domain.net",
    ])
    def test_valid_domain(self, domain):
        assert validate_value(BlacklistType.DOMAIN, domain) is True

    # Domaines invalides
    @pytest.mark.parametrize("domain", [
        "",
        "   ",
        "-invalid.com",
        "invalid-.com",
        "a" * 254,  # trop long
        "123.456",  # pas de lettres
    ])
    def test_invalid_domain(self, domain):
        assert validate_value(BlacklistType.DOMAIN, domain) is False

    # Termes valides
    @pytest.mark.parametrize("term", [
        "malware",
        "ab",  # minimum 2 chars
        "x" * 200,  # maximum 200 chars
        "trojan horse",
        "C2 server",
    ])
    def test_valid_term(self, term):
        assert validate_value(BlacklistType.TERM, term) is True

    # Termes invalides
    @pytest.mark.parametrize("term", [
        "",
        "a",  # trop court
        "x" * 201,  # trop long
        "   ",
    ])
    def test_invalid_term(self, term):
        assert validate_value(BlacklistType.TERM, term) is False


class TestInferEntryType:
    """Tests de infer_entry_type."""

    def test_infer_ip(self):
        assert infer_entry_type("192.168.1.1") == BlacklistType.IP
        assert infer_entry_type("10.0.0.1") == BlacklistType.IP

    def test_infer_domain(self):
        assert infer_entry_type("evil.com") == BlacklistType.DOMAIN
        assert infer_entry_type("malware.example.org") == BlacklistType.DOMAIN

    def test_infer_term(self):
        assert infer_entry_type("malware") == BlacklistType.TERM
        assert infer_entry_type("trojan horse") == BlacklistType.TERM
        assert infer_entry_type("C2") == BlacklistType.TERM

    def test_infer_strips_whitespace(self):
        assert infer_entry_type("  192.168.1.1  ") == BlacklistType.IP
        assert infer_entry_type("  evil.com  ") == BlacklistType.DOMAIN

    def test_numeric_string_is_term(self):
        assert infer_entry_type("12345") == BlacklistType.TERM


class TestCreateUserBlacklistEntry:
    """Tests de la factory create_user_blacklist_entry."""

    def test_create_with_auto_type(self):
        entry = create_user_blacklist_entry("192.168.1.1")
        assert entry.entry_type == BlacklistType.IP
        assert entry.value == "192.168.1.1"
        assert entry.id.startswith("bl_")
        assert len(entry.id) == 11  # bl_ + 8 hex chars
        assert entry.created_at.tzinfo is not None

    def test_create_with_explicit_type(self):
        entry = create_user_blacklist_entry("test", entry_type=BlacklistType.TERM)
        assert entry.entry_type == BlacklistType.TERM

    def test_create_with_reason(self):
        entry = create_user_blacklist_entry("evil.com", reason="  Site malveillant  ")
        assert entry.reason == "Site malveillant"

    def test_create_strips_whitespace(self):
        entry = create_user_blacklist_entry("  192.168.1.1  ")
        assert entry.value == "192.168.1.1"

    def test_create_unique_ids(self):
        e1 = create_user_blacklist_entry("1.2.3.4")
        e2 = create_user_blacklist_entry("5.6.7.8")
        assert e1.id != e2.id

    def test_create_domain_entry(self):
        entry = create_user_blacklist_entry("malware.example.org")
        assert entry.entry_type == BlacklistType.DOMAIN
        assert entry.value == "malware.example.org"

    def test_create_term_entry(self):
        entry = create_user_blacklist_entry("suspicious payload")
        assert entry.entry_type == BlacklistType.TERM
