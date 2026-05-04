"""Integration tests for admin version display (Story 5.4).

AC Coverage:
- AC1: GET /admin/update displays admin page with system information
- AC2: System info visible (version, install date, Pi model, uptime)
- AC3: Version visible in footer on all pages
- AC4: Performance — page loads successfully (< 2s validated in E2E)
"""

import pytest
from bs4 import BeautifulSoup

from app.services.version_service import get_version_service


class TestAdminIndexVersion:
    """AC1/AC2: Admin index displays dynamic system information."""

    def test_admin_index_returns_200(self, client):
        response = client.get('/admin/')
        assert response.status_code == 200

    def test_admin_index_shows_dynamic_version(self, client):
        expected = get_version_service().get_version()
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        version_el = soup.find(class_='version-value')
        assert version_el is not None
        assert f'v{expected}' in version_el.get_text()

    def test_admin_index_shows_pi_model(self, client):
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        info_values = [el.get_text() for el in soup.find_all(class_='info-value')]
        has_model = any('Unknown' in v or 'Raspberry' in v or 'Pi' in v for v in info_values)
        assert has_model

    def test_admin_index_shows_install_date(self, client):
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        labels = soup.find_all(class_='info-label')
        date_label = [l for l in labels if 'installation' in l.get_text().lower()]
        assert len(date_label) == 1

    def test_admin_index_shows_uptime(self, client):
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        labels = soup.find_all(class_='info-label')
        uptime_label = [l for l in labels if 'uptime' in l.get_text().lower()]
        assert len(uptime_label) == 1


class TestUpdatePageVersion:
    """AC1: Update page shows dynamic version and install date."""

    def test_update_returns_200(self, client):
        response = client.get('/admin/update')
        assert response.status_code == 200

    def test_update_shows_dynamic_version(self, client):
        expected = get_version_service().get_version()
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        version_el = soup.find(class_='version-value')
        assert version_el is not None
        assert f'v{expected}' in version_el.get_text()

    def test_update_shows_install_date(self, client):
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        labels = soup.find_all(class_='version-label')
        date_label = [l for l in labels if 'installation' in l.get_text().lower()]
        assert len(date_label) == 1

    def test_update_history_table_has_dynamic_version(self, client):
        expected = get_version_service().get_version()
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        table = soup.find('table', class_='data-table')
        assert table is not None
        first_row = table.find('tbody').find('tr')
        cells = first_row.find_all('td')
        assert f'v{expected}' in cells[0].get_text()


class TestFooterVersion:
    """AC3: Version visible in footer on all pages."""

    @pytest.mark.parametrize('url', [
        '/',
        '/admin/',
        '/admin/update',
        '/admin/config',
    ])
    def test_footer_shows_dynamic_version(self, client, url):
        expected = get_version_service().get_version()
        response = client.get(url)
        assert response.status_code == 200
        soup = BeautifulSoup(response.data, 'html.parser')
        footer_version = soup.find(class_='footer-version')
        assert footer_version is not None
        assert f'v{expected}' in footer_version.get_text()

    @pytest.mark.parametrize('url', [
        '/',
        '/admin/',
    ])
    def test_footer_version_matches_service(self, client, url):
        expected = get_version_service().get_version()
        response = client.get(url)
        soup = BeautifulSoup(response.data, 'html.parser')
        footer_version = soup.find(class_='footer-version')
        assert footer_version is not None
        assert f'v{expected}' in footer_version.get_text()
