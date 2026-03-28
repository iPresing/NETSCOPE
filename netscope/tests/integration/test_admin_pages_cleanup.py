"""Integration tests for admin pages after non-functional elements cleanup (Story 4b.3).

Tests that admin pages load correctly, return proper content,
and maintain functional sections after cleanup.

AC Coverage:
- AC1: Config page functional after cleanup
- AC2: Update page functional after cleanup
- AC3: Admin index functional after card removal
- AC5: No regressions in page loading
"""

import pytest
from bs4 import BeautifulSoup


class TestConfigPageIntegration:
    """Integration tests for config page after cleanup (AC1)."""

    def test_config_returns_200(self, client):
        """Config page loads successfully."""
        response = client.get('/admin/config')
        assert response.status_code == 200

    def test_config_has_page_header(self, client):
        """Config page retains its header."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        header = soup.find('h2')
        assert header is not None
        assert 'Configuration' in header.get_text()

    def test_config_whitelist_link_works(self, client):
        """Whitelist management link points to valid route."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        wl_link = soup.find('a', string=lambda t: t and 'Whitelist' in t)
        assert wl_link is not None
        href = wl_link.get('href')
        assert href is not None
        # Verify the linked page responds
        response_wl = client.get(href)
        assert response_wl.status_code == 200

    def test_config_return_link_works(self, client):
        """'Retour à l'administration' link points to valid route."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        back_link = soup.find('a', string=lambda t: t and 'Retour' in t)
        assert back_link is not None
        href = back_link.get('href')
        response_admin = client.get(href)
        assert response_admin.status_code == 200

    def test_config_no_disabled_buttons(self, client):
        """No disabled buttons remain on config page."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        disabled_btns = soup.find_all('button', attrs={'disabled': True})
        assert len(disabled_btns) == 0


class TestUpdatePageIntegration:
    """Integration tests for update page after cleanup (AC2)."""

    def test_update_returns_200(self, client):
        """Update page loads successfully."""
        response = client.get('/admin/update')
        assert response.status_code == 200

    def test_update_has_version_display(self, client):
        """Update page still shows version information."""
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        version = soup.find(class_='version-value')
        assert version is not None
        assert 'v0.1.0' in version.get_text()

    def test_update_has_history_table(self, client):
        """Update page still has update history table."""
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        table = soup.find('table', class_='data-table')
        assert table is not None
        rows = table.find_all('tr')
        assert len(rows) >= 2  # header + at least 1 data row

    def test_update_return_link_works(self, client):
        """'Retour à l'administration' link points to valid route."""
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        back_link = soup.find('a', string=lambda t: t and 'Retour' in t)
        assert back_link is not None
        href = back_link.get('href')
        response_admin = client.get(href)
        assert response_admin.status_code == 200

    def test_update_no_disabled_buttons(self, client):
        """No disabled buttons remain on update page."""
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        disabled_btns = soup.find_all('button', attrs={'disabled': True})
        assert len(disabled_btns) == 0


class TestAdminIndexIntegration:
    """Integration tests for admin index after card removal (AC3)."""

    def test_admin_returns_200(self, client):
        """Admin index page loads successfully."""
        response = client.get('/admin/')
        assert response.status_code == 200

    def test_admin_has_system_info(self, client):
        """Admin page still shows system information."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        info_section = soup.find(class_='admin-info')
        assert info_section is not None

    def test_admin_has_health_indicators(self, client):
        """Admin page still shows health indicators."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        health_section = soup.find(class_='admin-health')
        assert health_section is not None

    def test_admin_card_links_are_valid(self, client):
        """All remaining admin card links lead to valid pages."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        card_links = soup.find_all('a', class_='admin-card')
        assert len(card_links) >= 2
        for link in card_links:
            href = link.get('href')
            assert href is not None
            r = client.get(href)
            assert r.status_code == 200, f"Link {href} returned {r.status_code}"

    def test_admin_exactly_two_cards(self, client):
        """Admin page has exactly 2 navigation cards (update + config)."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        cards = soup.find_all(class_='admin-card')
        assert len(cards) == 2
