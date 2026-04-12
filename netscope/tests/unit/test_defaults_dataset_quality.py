"""Tests de qualité du dataset blacklists par défaut.

Story 4b.9 — AC6 : vérifier que les fichiers enrichis respectent les
contraintes de format, dédoublonnage interne, absence d'IPs privées et
de TLDs réservés, et les seuils minimums de volume.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pytest

from app.models.blacklist import (
    BlacklistType,
    infer_entry_type,
    validate_value,
)


DEFAULTS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "blacklists_defaults"

IP_FILES = ["ips_malware.txt", "ips_c2.txt"]
DOMAIN_FILES = ["domains_malware.txt", "domains_phishing.txt"]
TERM_FILES = ["terms_suspect.txt"]
ALL_FILES = IP_FILES + DOMAIN_FILES + TERM_FILES

RESERVED_TLDS = (".local", ".localhost", ".example", ".invalid", ".test")

# Seuils AC3
MIN_ENTRIES_PER_FILE = 50
MIN_TOTAL_ENTRIES = 500


def _load_entries(path: Path) -> list[str]:
    """Parse un fichier .txt : une entrée par ligne, # pour commentaires."""
    entries: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if line:
                entries.append(line)
    return entries


def test_defaults_dir_exists() -> None:
    assert DEFAULTS_DIR.is_dir(), f"Dossier manquant: {DEFAULTS_DIR}"


@pytest.mark.parametrize("filename", ALL_FILES)
def test_file_exists_and_not_empty(filename: str) -> None:
    path = DEFAULTS_DIR / filename
    assert path.exists(), f"Fichier manquant: {filename}"
    assert path.stat().st_size > 0, f"Fichier vide: {filename}"


@pytest.mark.parametrize("filename", ALL_FILES)
def test_file_has_minimum_entries(filename: str) -> None:
    entries = _load_entries(DEFAULTS_DIR / filename)
    assert len(entries) >= MIN_ENTRIES_PER_FILE, (
        f"{filename} contient {len(entries)} entrées "
        f"(minimum AC3: {MIN_ENTRIES_PER_FILE})"
    )


def test_total_entries_reaches_threshold() -> None:
    total = sum(len(_load_entries(DEFAULTS_DIR / f)) for f in ALL_FILES)
    assert total >= MIN_TOTAL_ENTRIES, (
        f"Total {total} entrées < seuil AC3 {MIN_TOTAL_ENTRIES}"
    )


@pytest.mark.parametrize("filename", ALL_FILES)
def test_no_internal_duplicates(filename: str) -> None:
    entries = _load_entries(DEFAULTS_DIR / filename)
    assert len(entries) == len(set(entries)), (
        f"{filename} contient des doublons internes"
    )


@pytest.mark.parametrize("filename", IP_FILES)
def test_ip_files_have_valid_public_ips(filename: str) -> None:
    entries = _load_entries(DEFAULTS_DIR / filename)
    for entry in entries:
        assert validate_value(BlacklistType.IP, entry), (
            f"{filename}: IP invalide '{entry}'"
        )
        ip = ipaddress.ip_address(entry)
        assert not ip.is_private, f"{filename}: IP privée '{entry}' (RFC1918)"
        assert not ip.is_loopback, f"{filename}: IP loopback '{entry}'"
        assert not ip.is_link_local, f"{filename}: IP link-local '{entry}'"
        assert not ip.is_multicast, f"{filename}: IP multicast '{entry}'"
        assert not ip.is_reserved, f"{filename}: IP réservée '{entry}'"


@pytest.mark.parametrize("filename", DOMAIN_FILES)
def test_domain_files_have_valid_domains(filename: str) -> None:
    entries = _load_entries(DEFAULTS_DIR / filename)
    for entry in entries:
        assert validate_value(BlacklistType.DOMAIN, entry), (
            f"{filename}: domaine invalide '{entry}'"
        )
        low = entry.lower()
        for tld in RESERVED_TLDS:
            assert not low.endswith(tld), (
                f"{filename}: TLD réservé '{entry}' (se termine par {tld})"
            )


@pytest.mark.parametrize("filename", TERM_FILES)
def test_term_files_have_valid_terms(filename: str) -> None:
    entries = _load_entries(DEFAULTS_DIR / filename)
    for entry in entries:
        assert validate_value(BlacklistType.TERM, entry), (
            f"{filename}: terme invalide '{entry}'"
        )
        assert 2 <= len(entry) <= 200, (
            f"{filename}: longueur hors bornes '{entry}' ({len(entry)})"
        )


def test_no_cross_file_ip_duplicates() -> None:
    """ips_malware et ips_c2 ne doivent pas se chevaucher."""
    set_malware = set(_load_entries(DEFAULTS_DIR / "ips_malware.txt"))
    set_c2 = set(_load_entries(DEFAULTS_DIR / "ips_c2.txt"))
    overlap = set_malware & set_c2
    assert not overlap, f"IPs en double entre malware et c2: {sorted(overlap)[:5]}"


def test_no_cross_file_domain_duplicates() -> None:
    """domains_malware et domains_phishing ne doivent pas se chevaucher."""
    set_malware = set(_load_entries(DEFAULTS_DIR / "domains_malware.txt"))
    set_phishing = set(_load_entries(DEFAULTS_DIR / "domains_phishing.txt"))
    overlap = set_malware & set_phishing
    assert not overlap, (
        f"Domaines en double entre malware et phishing: {sorted(overlap)[:5]}"
    )


@pytest.mark.parametrize("filename", ALL_FILES)
def test_file_under_size_limit(filename: str) -> None:
    """Les fichiers .txt doivent rester < 1 MB (règle #21 Epic 4)."""
    path = DEFAULTS_DIR / filename
    size_mb = path.stat().st_size / (1024 * 1024)
    assert size_mb < 1.0, (
        f"{filename} dépasse 1 MB ({size_mb:.2f} MB) — envisager Git LFS "
        f"ou découpage (règle #21)"
    )
