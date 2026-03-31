"""Tests unitaires pour BlacklistUserManager (Story 4b.6)."""

import json
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.models.blacklist import BlacklistType, UserBlacklistEntry
from app.services.blacklist_user_manager import (
    BlacklistUserManager,
    MAX_USER_BLACKLIST_ENTRIES,
    reset_blacklist_user_manager,
)


@pytest.fixture
def tmp_json(tmp_path):
    """Chemin temporaire pour le fichier JSON user blacklist."""
    return tmp_path / "user_blacklist.json"


@pytest.fixture
def manager(tmp_json):
    """Instance BlacklistUserManager avec fichier temporaire."""
    return BlacklistUserManager(tmp_json)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset le singleton après chaque test."""
    yield
    reset_blacklist_user_manager()


@pytest.fixture
def mock_blacklist_manager():
    """Mock le BlacklistManager pour éviter les dépendances."""
    mock = MagicMock()
    mock.check_ip.return_value = False
    mock.check_domain.return_value = False
    mock.terms = frozenset()
    mock.merge_user_entries = MagicMock()
    with patch(
        "app.core.detection.blacklist_manager.get_blacklist_manager",
        return_value=mock,
    ):
        yield mock


class TestBlacklistUserManagerInit:
    """Tests d'initialisation."""

    def test_init_empty_no_file(self, manager):
        assert manager.get_all() == []

    def test_init_loads_existing_file(self, tmp_json):
        data = {
            "entries": [
                {
                    "id": "bl_test0001",
                    "entry_type": "ip",
                    "value": "1.2.3.4",
                    "reason": "test",
                    "created_at": "2026-03-30T12:00:00+00:00",
                }
            ],
            "version": 1,
        }
        tmp_json.write_text(json.dumps(data), encoding="utf-8")
        mgr = BlacklistUserManager(tmp_json)
        assert len(mgr.get_all()) == 1
        assert mgr.get_all()[0].value == "1.2.3.4"

    def test_init_handles_corrupt_json(self, tmp_json):
        tmp_json.write_text("not valid json", encoding="utf-8")
        mgr = BlacklistUserManager(tmp_json)
        assert mgr.get_all() == []


class TestBlacklistUserManagerAdd:
    """Tests d'ajout d'entrées."""

    def test_add_ip(self, manager, mock_blacklist_manager):
        entry = manager.add("192.168.1.100", entry_type=BlacklistType.IP)
        assert entry.value == "192.168.1.100"
        assert entry.entry_type == BlacklistType.IP
        assert entry.id.startswith("bl_")

    def test_add_domain(self, manager, mock_blacklist_manager):
        entry = manager.add("evil.com", entry_type=BlacklistType.DOMAIN)
        assert entry.value == "evil.com"
        assert entry.entry_type == BlacklistType.DOMAIN

    def test_add_term(self, manager, mock_blacklist_manager):
        entry = manager.add("malware payload", entry_type=BlacklistType.TERM)
        assert entry.value == "malware payload"
        assert entry.entry_type == BlacklistType.TERM

    def test_add_auto_detect_type(self, manager, mock_blacklist_manager):
        entry = manager.add("10.0.0.1")
        assert entry.entry_type == BlacklistType.IP

    def test_add_with_reason(self, manager, mock_blacklist_manager):
        entry = manager.add("evil.com", entry_type=BlacklistType.DOMAIN, reason="Phishing")
        assert entry.reason == "Phishing"

    def test_add_persists_to_file(self, manager, tmp_json, mock_blacklist_manager):
        manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        data = json.loads(tmp_json.read_text(encoding="utf-8"))
        assert len(data["entries"]) == 1
        assert data["entries"][0]["value"] == "1.2.3.4"
        assert data["version"] == 1

    def test_add_creates_directory(self, tmp_path, mock_blacklist_manager):
        deep_path = tmp_path / "sub" / "dir" / "user_blacklist.json"
        mgr = BlacklistUserManager(deep_path)
        mgr.add("1.2.3.4", entry_type=BlacklistType.IP)
        assert deep_path.exists()

    def test_add_triggers_reload(self, manager, mock_blacklist_manager):
        manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        mock_blacklist_manager.merge_user_entries.assert_called_once()


class TestBlacklistUserManagerDuplicate:
    """Tests de détection de doublons."""

    def test_duplicate_user_entry_rejected(self, manager, mock_blacklist_manager):
        manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        with pytest.raises(ValueError, match="Doublon"):
            manager.add("1.2.3.4", entry_type=BlacklistType.IP)

    def test_duplicate_domain_case_insensitive(self, manager, mock_blacklist_manager):
        manager.add("Evil.Com", entry_type=BlacklistType.DOMAIN)
        with pytest.raises(ValueError, match="Doublon"):
            manager.add("evil.com", entry_type=BlacklistType.DOMAIN)

    def test_duplicate_default_ip_rejected(self, manager, mock_blacklist_manager):
        mock_blacklist_manager.check_ip.return_value = True
        with pytest.raises(ValueError, match="blacklists par défaut"):
            manager.add("1.2.3.4", entry_type=BlacklistType.IP)

    def test_duplicate_default_domain_rejected(self, manager, mock_blacklist_manager):
        mock_blacklist_manager.check_domain.return_value = True
        with pytest.raises(ValueError, match="blacklists par défaut"):
            manager.add("evil.com", entry_type=BlacklistType.DOMAIN)

    def test_duplicate_default_term_rejected(self, manager, mock_blacklist_manager):
        mock_blacklist_manager.terms = frozenset({"malware"})
        with pytest.raises(ValueError, match="blacklists par défaut"):
            manager.add("malware", entry_type=BlacklistType.TERM)


class TestBlacklistUserManagerValidation:
    """Tests de validation."""

    def test_invalid_ip_rejected(self, manager, mock_blacklist_manager):
        with pytest.raises(ValueError, match="Valeur invalide"):
            manager.add("999.999.999.999", entry_type=BlacklistType.IP)

    def test_invalid_domain_rejected(self, manager, mock_blacklist_manager):
        with pytest.raises(ValueError, match="Valeur invalide"):
            manager.add("-invalid", entry_type=BlacklistType.DOMAIN)

    def test_invalid_term_too_short(self, manager, mock_blacklist_manager):
        with pytest.raises(ValueError, match="Valeur invalide"):
            manager.add("a", entry_type=BlacklistType.TERM)

    def test_invalid_term_too_long(self, manager, mock_blacklist_manager):
        with pytest.raises(ValueError, match="Valeur invalide"):
            manager.add("x" * 201, entry_type=BlacklistType.TERM)

    def test_empty_value_rejected(self, manager, mock_blacklist_manager):
        with pytest.raises(ValueError):
            manager.add("   ", entry_type=BlacklistType.IP)


class TestBlacklistUserManagerLimit:
    """Tests de limite d'entrées."""

    def test_limit_reached(self, manager, mock_blacklist_manager):
        # Remplir directement la liste interne
        for i in range(MAX_USER_BLACKLIST_ENTRIES):
            entry = UserBlacklistEntry(
                id=f"bl_{i:08d}",
                entry_type=BlacklistType.IP,
                value=f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}",
                reason="",
                created_at=manager._entries[0].created_at if manager._entries else __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            )
            manager._entries.append(entry)

        with pytest.raises(ValueError, match="Limite atteinte"):
            manager.add("99.99.99.99", entry_type=BlacklistType.IP)


class TestBlacklistUserManagerRemove:
    """Tests de suppression."""

    def test_remove_existing(self, manager, mock_blacklist_manager):
        entry = manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        removed = manager.remove(entry.id)
        assert removed.value == "1.2.3.4"
        assert len(manager.get_all()) == 0

    def test_remove_persists(self, manager, tmp_json, mock_blacklist_manager):
        entry = manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        manager.remove(entry.id)
        data = json.loads(tmp_json.read_text(encoding="utf-8"))
        assert len(data["entries"]) == 0

    def test_remove_nonexistent_raises(self, manager):
        with pytest.raises(KeyError, match="non trouvée"):
            manager.remove("bl_doesnotexist")

    def test_remove_triggers_reload(self, manager, mock_blacklist_manager):
        entry = manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        mock_blacklist_manager.merge_user_entries.reset_mock()
        manager.remove(entry.id)
        mock_blacklist_manager.merge_user_entries.assert_called_once()


class TestBlacklistUserManagerGetters:
    """Tests des getters."""

    def test_get_all_returns_copy(self, manager, mock_blacklist_manager):
        manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        entries = manager.get_all()
        entries.clear()
        assert len(manager.get_all()) == 1

    def test_get_by_id_found(self, manager, mock_blacklist_manager):
        entry = manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        found = manager.get_by_id(entry.id)
        assert found is not None
        assert found.value == "1.2.3.4"

    def test_get_by_id_not_found(self, manager):
        assert manager.get_by_id("bl_nonexist") is None


class TestBlacklistUserManagerThreadSafety:
    """Tests de thread-safety."""

    def test_concurrent_adds(self, manager, mock_blacklist_manager):
        errors = []

        def add_entry(idx):
            try:
                manager.add(
                    f"10.0.{idx // 256}.{idx % 256}",
                    entry_type=BlacklistType.IP,
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=add_entry, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(manager.get_all()) == 20


class TestBlacklistUserManagerPersistence:
    """Tests de persistance et rechargement."""

    def test_reload_preserves_entries(self, manager, tmp_json, mock_blacklist_manager):
        manager.add("1.2.3.4", entry_type=BlacklistType.IP)
        manager.add("evil.com", entry_type=BlacklistType.DOMAIN)

        # Recharger depuis le fichier
        mgr2 = BlacklistUserManager(tmp_json)
        assert len(mgr2.get_all()) == 2

    def test_save_load_roundtrip(self, manager, tmp_json, mock_blacklist_manager):
        manager.add("1.2.3.4", entry_type=BlacklistType.IP, reason="Test IP")
        manager.add("evil.com", entry_type=BlacklistType.DOMAIN, reason="Test domain")
        manager.add("suspicious", entry_type=BlacklistType.TERM, reason="Test term")

        mgr2 = BlacklistUserManager(tmp_json)
        entries = mgr2.get_all()
        assert len(entries) == 3
        assert entries[0].reason == "Test IP"
        assert entries[1].reason == "Test domain"
        assert entries[2].reason == "Test term"
