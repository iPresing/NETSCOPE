"""Tests unitaires du script CLI app.tools.refresh_blacklists.

Story 4b.9 — AC5 : téléchargement HTTPS, parsing, validation,
dédoublonnage, mode dry-run, gestion d'erreurs propres.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from app.tools import refresh_blacklists as rb


class TestParsers:
    def test_parse_plain_text_ip_ignores_comments_and_empty(self) -> None:
        body = "# header\n\n8.8.8.8\n1.1.1.1  # inline\n"
        out = rb.parse_plain_text_ip(body)
        assert "8.8.8.8" in out
        assert "1.1.1.1" in out

    def test_parse_plain_text_ip_rejects_private(self) -> None:
        body = "10.0.0.1\n192.168.1.1\n172.16.0.1\n127.0.0.1\n8.8.8.8\n"
        out = rb.parse_plain_text_ip(body)
        assert out == ["8.8.8.8"]

    def test_parse_plain_text_ip_rejects_reserved(self) -> None:
        body = "224.0.0.1\n0.0.0.0\n169.254.1.1\n1.1.1.1\n"
        out = rb.parse_plain_text_ip(body)
        assert out == ["1.1.1.1"]

    def test_parse_plain_text_ip_accepts_cidr_slash32(self) -> None:
        body = "8.8.8.8/32\n"
        out = rb.parse_plain_text_ip(body)
        assert out == ["8.8.8.8"]

    def test_parse_plain_text_ip_rejects_cidr_block(self) -> None:
        body = "8.8.8.0/24\n"
        out = rb.parse_plain_text_ip(body)
        assert out == []

    def test_parse_plain_text_domain_ignores_reserved_tlds(self) -> None:
        body = "evil.com\nlocalhost.local\nphish.org\nbadsite.example\n"
        out = rb.parse_plain_text_domain(body)
        assert "evil.com" in out
        assert "phish.org" in out
        assert "localhost.local" not in out
        assert "badsite.example" not in out

    def test_parse_plain_text_domain_hosts_format(self) -> None:
        body = "0.0.0.0 evil.com\n127.0.0.1 phish.org\n"
        out = rb.parse_plain_text_domain(body)
        assert "evil.com" in out
        assert "phish.org" in out

    def test_parse_plain_text_domain_adblock_format(self) -> None:
        body = "||evil.com^\n||phish.org^|\n"
        out = rb.parse_plain_text_domain(body)
        assert "evil.com" in out
        assert "phish.org" in out


class TestValidators:
    def test_is_usable_ip_public(self) -> None:
        assert rb._is_usable_ip("8.8.8.8") is True

    def test_is_usable_ip_private(self) -> None:
        assert rb._is_usable_ip("192.168.1.1") is False

    def test_is_usable_ip_invalid(self) -> None:
        assert rb._is_usable_ip("not.an.ip") is False

    def test_is_usable_domain_valid(self) -> None:
        assert rb._is_usable_domain("evil.com") is True

    def test_is_usable_domain_reserved_tld(self) -> None:
        assert rb._is_usable_domain("something.local") is False
        assert rb._is_usable_domain("x.example") is False

    def test_is_usable_domain_too_short(self) -> None:
        assert rb._is_usable_domain("a") is False


class TestFetch:
    def test_fetch_rejects_non_https(self) -> None:
        with pytest.raises(ValueError):
            rb.fetch("http://evil.com/feed.txt")


@pytest.fixture
def fake_defaults_dir():
    """Un dossier défaut avec manifest factice pour tests end-to-end."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "data" / "blacklists_defaults"
        d.mkdir(parents=True)

        # Un fichier existant avec une entrée déjà dedans
        (d / "ips_malware.txt").write_text(
            "# header\n9.9.9.9\n", encoding="utf-8"
        )
        (d / "ips_malware.meta.yaml").write_text(
            "name: ips_malware\ncategory: ip\nsources: []\nlast_updated: '2026-01-01'\nentries_count: 1\n",
            encoding="utf-8",
        )

        (d / "manifest.yaml").write_text(
            "sources:\n"
            "  - name: fake_ipsum\n"
            "    url: https://fake.example.com/ipsum.txt\n"
            "    parser: plain_text_ip\n"
            "    target: ips_malware.txt\n"
            "    max_entries: 10\n"
            "    license: Unlicense\n",
            encoding="utf-8",
        )
        yield d


class TestRefreshFlow:
    def test_load_manifest(self, fake_defaults_dir):
        sources = rb.load_manifest(fake_defaults_dir)
        assert len(sources) == 1
        assert sources[0].name == "fake_ipsum"
        assert sources[0].parser == "plain_text_ip"
        assert sources[0].max_entries == 10

    def test_refresh_dry_run_does_not_modify_files(self, fake_defaults_dir):
        before = (fake_defaults_dir / "ips_malware.txt").read_text(encoding="utf-8")
        with patch.object(
            rb,
            "fetch",
            return_value="# feed\n1.1.1.1\n2.2.2.2\n10.0.0.1\n",
        ):
            results = rb.refresh(fake_defaults_dir, dry_run=True)
        after = (fake_defaults_dir / "ips_malware.txt").read_text(encoding="utf-8")
        assert before == after
        # Mais le résultat a bien enregistré 2 entrées publiques (10.0.0.1 rejeté)
        assert results[0].accepted == 2

    def test_refresh_writes_merged_entries(self, fake_defaults_dir):
        with patch.object(
            rb,
            "fetch",
            return_value="1.1.1.1\n2.2.2.2\n",
        ):
            rb.refresh(fake_defaults_dir, dry_run=False)
        content = (fake_defaults_dir / "ips_malware.txt").read_text(encoding="utf-8")
        assert "9.9.9.9" in content  # existant préservé
        assert "1.1.1.1" in content  # ajouté
        assert "2.2.2.2" in content

    def test_refresh_deduplicates(self, fake_defaults_dir):
        with patch.object(
            rb,
            "fetch",
            return_value="9.9.9.9\n1.1.1.1\n1.1.1.1\n",
        ):
            rb.refresh(fake_defaults_dir, dry_run=False)
        content = (fake_defaults_dir / "ips_malware.txt").read_text(encoding="utf-8")
        # 9.9.9.9 et 1.1.1.1 chacun une seule fois
        assert content.count("9.9.9.9") == 1
        assert content.count("1.1.1.1") == 1

    def test_refresh_handles_fetch_error(self, fake_defaults_dir):
        import urllib.error
        with patch.object(
            rb, "fetch",
            side_effect=urllib.error.URLError("network down"),
        ):
            results = rb.refresh(fake_defaults_dir, dry_run=False)
        assert len(results[0].errors) == 1
        # Fichier existant intact (pas de corruption)
        content = (fake_defaults_dir / "ips_malware.txt").read_text(encoding="utf-8")
        assert "9.9.9.9" in content

    def test_refresh_source_filter(self, fake_defaults_dir):
        with patch.object(rb, "fetch", return_value="1.1.1.1\n"):
            results = rb.refresh(
                fake_defaults_dir, source_filter="fake_ipsum", dry_run=True,
            )
        assert len(results) == 1

    def test_refresh_unknown_source_filter_raises(self, fake_defaults_dir):
        with pytest.raises(ValueError):
            rb.refresh(
                fake_defaults_dir, source_filter="nope", dry_run=True,
            )


class TestCli:
    def test_main_missing_defaults_dir_returns_2(self, monkeypatch):
        def raiser():
            raise FileNotFoundError("nope")
        monkeypatch.setattr(rb, "_find_defaults_dir", raiser)
        exit_code = rb.main(["--dry-run"])
        assert exit_code == 2
