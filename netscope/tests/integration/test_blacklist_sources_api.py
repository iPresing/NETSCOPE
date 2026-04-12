"""Tests d'intégration de l'endpoint GET /api/blacklists/sources.

Story 4b.9 — AC2/AC4 : l'API expose les métadonnées des blacklists par
défaut au format standard {success, result, error}.
"""

from __future__ import annotations


def test_sources_endpoint_returns_200(client):
    resp = client.get("/api/blacklists/sources")
    assert resp.status_code == 200


def test_sources_endpoint_standard_format(client):
    resp = client.get("/api/blacklists/sources")
    data = resp.get_json()
    assert data["success"] is True
    assert "result" in data
    assert "sources" in data["result"]
    assert "count" in data["result"]


def test_sources_endpoint_returns_list(client):
    resp = client.get("/api/blacklists/sources")
    data = resp.get_json()
    sources = data["result"]["sources"]
    assert isinstance(sources, list)
    # En contexte test, la config testing charge les defaults du projet
    if sources:
        first = sources[0]
        assert "name" in first
        assert "category" in first
        assert "file" in first
        assert "sources" in first
        assert isinstance(first["sources"], list)
        assert "entries_count" in first
        assert "last_updated" in first


def test_active_endpoint_includes_by_file(client):
    """Story 4b.9 : /active retourne désormais by_file pour attribution UI."""
    resp = client.get("/api/blacklists/active")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    result = data["result"]
    assert "ips" in result
    assert "domains" in result
    assert "terms" in result
    assert "by_file" in result
    assert isinstance(result["by_file"], dict)


def test_sources_count_matches_sources_list_length(client):
    resp = client.get("/api/blacklists/sources")
    data = resp.get_json()
    assert data["result"]["count"] == len(data["result"]["sources"])


def test_sources_contain_license_info(client):
    """AC7 : chaque source doit citer sa licence."""
    resp = client.get("/api/blacklists/sources")
    data = resp.get_json()
    for meta in data["result"]["sources"]:
        for src in meta.get("sources", []):
            assert "name" in src
            assert "url" in src
            assert "license" in src
            assert src["license"], f"Licence vide pour {src.get('name')}"
