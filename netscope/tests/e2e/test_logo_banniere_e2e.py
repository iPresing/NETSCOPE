"""E2E tests — Story 4b.4: Logo NETSCOPE dans la bannière.

Tests end-to-end sans mocks : navigation multi-pages avec vérification
que le logo est visible partout et que l'ancien SVG est supprimé.

AC Coverage:
- AC1: Logo visible sur navigation complète
- AC2: Favicon sur toutes les pages
- AC4: Lien nav-brand fonctionnel (cliquable vers /)
"""

import pytest
from bs4 import BeautifulSoup


class TestLogoE2ENavigation:
    """E2E: navigate across pages and verify logo consistency."""

    def test_full_navigation_logo_visible(self, client):
        """Navigate dashboard → anomalies → jobs → admin: logo on every page."""
        pages = ['/', '/anomalies', '/jobs', '/packets', '/whitelist', '/admin/']
        for url in pages:
            response = client.get(url)
            assert response.status_code == 200, \
                f'Page {url} returned {response.status_code}'
            soup = BeautifulSoup(response.data, 'html.parser')
            logo = soup.find('img', class_='brand-logo')
            assert logo is not None, \
                f'Logo missing on {url}'
            assert logo.get('src') is not None, \
                f'Logo has no src on {url}'
            assert 'netscope.png' in logo['src'], \
                f'Logo src does not contain netscope.png on {url}'

    def test_full_navigation_no_old_svg(self, client):
        """Navigate all pages: old SVG brand-icon absent from DOM."""
        pages = ['/', '/anomalies', '/jobs', '/packets', '/whitelist',
                 '/admin/', '/admin/config', '/admin/update']
        for url in pages:
            response = client.get(url)
            assert response.status_code == 200
            soup = BeautifulSoup(response.data, 'html.parser')
            old_icon = soup.find(class_='brand-icon')
            assert old_icon is None, \
                f'Old brand-icon SVG still in DOM on {url}'

    def test_nav_brand_link_returns_dashboard(self, client):
        """Clicking nav-brand (href=/) returns the dashboard page."""
        response = client.get('/anomalies')
        soup = BeautifulSoup(response.data, 'html.parser')
        brand_link = soup.find('a', class_='nav-brand')
        assert brand_link is not None
        href = brand_link.get('href')
        assert href == '/'
        # Follow the link
        response_home = client.get(href)
        assert response_home.status_code == 200
        home_soup = BeautifulSoup(response_home.data, 'html.parser')
        # Dashboard should have its characteristic elements
        assert home_soup.find('img', class_='brand-logo') is not None

    def test_logo_image_not_404(self, client):
        """The logo image file is served correctly (not 404)."""
        response = client.get('/static/img/netscope.png')
        assert response.status_code == 200
        assert response.content_type.startswith('image/')

    def test_favicon_served(self, client):
        """Favicon reference resolves to a served image."""
        # Get any page to extract favicon URL
        response = client.get('/')
        soup = BeautifulSoup(response.data, 'html.parser')
        favicon = soup.find('link', rel='icon')
        assert favicon is not None
        favicon_href = favicon.get('href')
        assert favicon_href is not None
        # Fetch the favicon
        response_fav = client.get(favicon_href)
        assert response_fav.status_code == 200
