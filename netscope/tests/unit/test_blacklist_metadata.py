"""Tests du parser de métadonnées .meta.yaml des blacklists par défaut.

Story 4b.9 — AC2 : `BlacklistManager.get_defaults_metadata()` parse les
fichiers .meta.yaml compagnons et retourne une liste structurée. Les
fichiers absents ou corrompus ne doivent PAS interrompre le chargement.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.core.detection.blacklist_manager import (
    BlacklistManager,
    get_blacklist_manager,
    reset_blacklist_manager,
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_blacklist_manager()
    yield
    reset_blacklist_manager()


@pytest.fixture
def temp_defaults_dir():
    """Crée un dossier temporaire simulant data/blacklists_defaults/."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        defaults_dir = root / "data" / "blacklists_defaults"
        defaults_dir.mkdir(parents=True)

        (defaults_dir / "ips_malware.txt").write_text(
            "# header\n"
            "1.2.3.4\n"
            "5.6.7.8\n",
            encoding="utf-8",
        )
        (defaults_dir / "ips_malware.meta.yaml").write_text(
            'name: ips_malware\n'
            'category: ip\n'
            'description: Test description\n'
            'sources:\n'
            '  - name: IPsum\n'
            '    url: https://example.org/ipsum\n'
            '    license: Unlicense\n'
            'last_updated: "2026-04-08T00:00:00+00:00"\n'
            'entries_count: 999\n',
            encoding="utf-8",
        )

        # Un fichier .txt sans .meta.yaml pour tester la rétrocompat
        (defaults_dir / "domains_malware.txt").write_text(
            "evil.com\nphish.org\n", encoding="utf-8"
        )

        yield root


def _load_manager(root: Path) -> BlacklistManager:
    config = {
        "defaults": {
            "ips_malware": str(root / "data" / "blacklists_defaults" / "ips_malware.txt"),
            "domains_malware": str(root / "data" / "blacklists_defaults" / "domains_malware.txt"),
        }
    }
    manager = get_blacklist_manager()
    manager.load_blacklists(config, base_path=root)
    return manager


def test_get_defaults_metadata_returns_list(temp_defaults_dir):
    manager = _load_manager(temp_defaults_dir)
    metadata = manager.get_defaults_metadata()
    assert isinstance(metadata, list)


def test_metadata_parses_valid_yaml(temp_defaults_dir):
    manager = _load_manager(temp_defaults_dir)
    metadata = manager.get_defaults_metadata()
    names = {m["name"] for m in metadata}
    assert "ips_malware" in names


def test_metadata_contains_required_fields(temp_defaults_dir):
    manager = _load_manager(temp_defaults_dir)
    metadata = manager.get_defaults_metadata()
    ips = next(m for m in metadata if m["name"] == "ips_malware")
    assert ips["category"] == "ip"
    assert ips["description"] == "Test description"
    assert ips["file"] == "ips_malware.txt"
    assert isinstance(ips["sources"], list)
    assert ips["sources"][0]["name"] == "IPsum"
    assert ips["sources"][0]["license"] == "Unlicense"
    assert "last_updated" in ips


def test_metadata_entries_count_is_recomputed_from_txt(temp_defaults_dir):
    """entries_count doit refléter le contenu réel du .txt, pas la valeur yaml."""
    manager = _load_manager(temp_defaults_dir)
    metadata = manager.get_defaults_metadata()
    ips = next(m for m in metadata if m["name"] == "ips_malware")
    # Le .txt contient 2 entrées réelles, le yaml dit 999 → doit être 2
    assert ips["entries_count"] == 2


def test_metadata_skips_files_without_meta_yaml(temp_defaults_dir, caplog):
    """Fichier .txt sans .meta.yaml : ne casse pas, juste warning + omission."""
    manager = _load_manager(temp_defaults_dir)
    metadata = manager.get_defaults_metadata()
    names = {m["name"] for m in metadata}
    assert "domains_malware" not in names  # absent car pas de .meta.yaml
    # ips_malware (qui a son .meta.yaml) toujours présent
    assert "ips_malware" in names


def test_metadata_handles_corrupted_yaml(temp_defaults_dir):
    """Un .meta.yaml corrompu ne doit pas crasher get_defaults_metadata."""
    bad_yaml = temp_defaults_dir / "data" / "blacklists_defaults" / "domains_malware.meta.yaml"
    bad_yaml.write_text("not: [valid: yaml: content", encoding="utf-8")

    manager = _load_manager(temp_defaults_dir)
    # Ne doit pas lever d'exception
    metadata = manager.get_defaults_metadata()
    names = {m["name"] for m in metadata}
    # domains_malware est omis à cause du parse error
    assert "domains_malware" not in names
    # ips_malware (valide) toujours présent
    assert "ips_malware" in names


def test_get_entries_by_file_returns_mapping(temp_defaults_dir):
    """Story 4b.9 : get_entries_by_file() retourne un mapping filename -> entries."""
    manager = _load_manager(temp_defaults_dir)
    by_file = manager.get_entries_by_file()
    assert isinstance(by_file, dict)
    assert "ips_malware.txt" in by_file
    assert "domains_malware.txt" in by_file
    assert "1.2.3.4" in by_file["ips_malware.txt"]


def test_real_defaults_metadata_loads(tmp_path, monkeypatch):
    """Intégration : charger les vrais fichiers du projet et parser les métas."""
    project_root = Path(__file__).resolve().parent.parent.parent
    defaults_dir = project_root / "data" / "blacklists_defaults"
    if not defaults_dir.exists():
        pytest.skip("Real defaults dir not found")

    config = {
        "defaults": {
            "ips_malware": str(defaults_dir / "ips_malware.txt"),
            "ips_c2": str(defaults_dir / "ips_c2.txt"),
            "domains_malware": str(defaults_dir / "domains_malware.txt"),
            "domains_phishing": str(defaults_dir / "domains_phishing.txt"),
            "terms_suspect": str(defaults_dir / "terms_suspect.txt"),
        }
    }
    manager = get_blacklist_manager()
    manager.load_blacklists(config, base_path=project_root)

    metadata = manager.get_defaults_metadata()
    # Les 5 fichiers ont un .meta.yaml
    assert len(metadata) == 5

    names = {m["name"] for m in metadata}
    assert {
        "ips_malware", "ips_c2", "domains_malware",
        "domains_phishing", "terms_suspect",
    }.issubset(names)

    # Chaque entrée a au moins 2 sources (AC1)
    for meta in metadata:
        assert len(meta["sources"]) >= 2, (
            f"{meta['name']} n'a que {len(meta['sources'])} source(s) (minimum 2)"
        )

    # entries_count cohérent avec le contenu
    for meta in metadata:
        assert meta["entries_count"] >= 50, (
            f"{meta['name']}: {meta['entries_count']} entrées < 50 (AC3)"
        )
