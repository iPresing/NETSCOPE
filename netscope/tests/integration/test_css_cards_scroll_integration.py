"""Tests d'intégration — Story 4b.2: Fix CSS Cards & Scroll Fluide.

Vérifie que les pages HTML contiennent les classes et structures
CSS attendues pour le scroll et le layout responsive.
"""

import pytest


class TestDashboardCardsRendering:
    """AC2/AC6: le dashboard contient les classes CSS pour les status cards."""

    def test_dashboard_has_status_cards_container(self, client):
        resp = client.get('/')
        html = resp.data.decode('utf-8')
        assert 'status-cards' in html, 'Dashboard should have .status-cards container'

    def test_dashboard_has_status_card_details(self, client):
        resp = client.get('/')
        html = resp.data.decode('utf-8')
        assert 'status-card-details' in html, 'Dashboard should have .status-card-details'

    def test_dashboard_has_anomalies_list(self, client):
        resp = client.get('/')
        html = resp.data.decode('utf-8')
        assert 'anomalies-list' in html, 'Dashboard should have .anomalies-list'

    def test_dashboard_links_style_css(self, client):
        resp = client.get('/')
        html = resp.data.decode('utf-8')
        assert 'style.css' in html, 'Dashboard should link style.css'


class TestAnomaliesPageRendering:
    """AC4/AC6: la page anomalies contient les classes CSS pour le scroll."""

    def test_anomalies_page_has_list_section(self, client):
        resp = client.get('/anomalies')
        html = resp.data.decode('utf-8')
        assert 'anomalies-list-section' in html, 'Anomalies page should have .anomalies-list-section'

    def test_anomalies_page_returns_200(self, client):
        resp = client.get('/anomalies')
        assert resp.status_code == 200


class TestCssFileServed:
    """AC6: le fichier CSS est servi correctement."""

    def test_css_file_accessible(self, client):
        resp = client.get('/static/css/style.css')
        assert resp.status_code == 200
        css = resp.data.decode('utf-8')
        assert '.status-card-details' in css
        assert '.anomalies-list' in css
        assert '::-webkit-scrollbar' in css

    def test_css_contains_reduced_motion(self, client):
        resp = client.get('/static/css/style.css')
        css = resp.data.decode('utf-8')
        assert 'prefers-reduced-motion' in css


class TestAllPagesNoError:
    """AC6: navigation complète sans erreur."""

    @pytest.mark.parametrize('path', [
        '/',
        '/anomalies',
        '/admin/',
        '/packets',
    ])
    def test_page_returns_success(self, client, path):
        resp = client.get(path)
        assert resp.status_code == 200, f'{path} returned {resp.status_code}'
