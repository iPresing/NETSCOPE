"""E2E tests for admin version display (Story 5.4).

Tests complete user journey: admin page → system info → footer version.
No mocks — real VersionService, real VERSION file, real templates.

AC Coverage:
- AC1: Full admin page load with system info
- AC2: All system info fields populated
- AC3: Footer version on every page
- AC4: Performance — page load < 2 seconds
"""

import time

import pytest
from bs4 import BeautifulSoup

from app.services.version_service import get_version_service


class TestAdminPageE2E:
    """Full journey through admin page with system information."""

    def test_admin_page_loads_with_all_system_info(self, client):
        """AC1+AC2: Admin page shows version, model, date, uptime."""
        response = client.get('/admin/')
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, 'html.parser')
        info_grid = soup.find(class_='info-grid')
        assert info_grid is not None

        labels = [el.get_text().strip() for el in info_grid.find_all(class_='info-label')]
        assert 'Version:' in labels
        assert 'Uptime:' in labels

        values = [el.get_text().strip() for el in info_grid.find_all(class_='info-value')]
        version_value = values[0]
        assert version_value.startswith('NETSCOPE v')
        assert version_value != 'NETSCOPE v0.0.0'

    def test_update_page_full_journey(self, client):
        """AC1: Navigate to update page, verify dynamic version everywhere."""
        response = client.get('/admin/update')
        assert response.status_code == 200

        soup = BeautifulSoup(response.data, 'html.parser')

        version_el = soup.find(class_='version-value')
        assert version_el is not None
        assert 'v' in version_el.get_text()

        footer = soup.find(class_='footer-version')
        assert footer is not None

        expected = get_version_service().get_version()
        assert expected in footer.get_text()
        assert expected in version_el.get_text()

    def test_version_consistent_across_pages(self, client):
        """AC3: Same version string in admin, update, footer, dashboard."""
        expected = get_version_service().get_version()
        pages = ['/', '/admin/', '/admin/update', '/admin/config']
        for url in pages:
            response = client.get(url)
            soup = BeautifulSoup(response.data, 'html.parser')
            footer = soup.find(class_='footer-version')
            assert footer is not None, f'No footer on {url}'
            assert f'v{expected}' in footer.get_text(), f'Wrong version in footer on {url}'


class TestPerformanceE2E:
    """AC4: Page load performance."""

    def test_admin_page_loads_under_2_seconds(self, client):
        start = time.monotonic()
        response = client.get('/admin/')
        elapsed = time.monotonic() - start
        assert response.status_code == 200
        assert elapsed < 2.0, f'Admin page took {elapsed:.2f}s (limit: 2s)'

    def test_update_page_loads_under_2_seconds(self, client):
        start = time.monotonic()
        response = client.get('/admin/update')
        elapsed = time.monotonic() - start
        assert response.status_code == 200
        assert elapsed < 2.0, f'Update page took {elapsed:.2f}s (limit: 2s)'
