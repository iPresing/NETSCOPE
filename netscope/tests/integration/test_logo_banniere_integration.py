"""Integration tests — Story 4b.4: Logo NETSCOPE dans la bannière.

Vérifie que le logo et le favicon apparaissent sur toutes les pages
servies par Flask (héritage base.html).

AC Coverage:
- AC1: Logo visible sur dashboard, anomalies, admin
- AC2: Favicon présent dans le head de chaque page
- AC4: Accessibilité (alt text sur pages rendues)
"""

import pytest
from bs4 import BeautifulSoup


# Pages qui héritent de base.html
PAGES = [
    ('/', 'dashboard'),
    ('/anomalies', 'anomalies'),
    ('/jobs', 'jobs'),
    ('/packets', 'packets'),
    ('/whitelist', 'whitelist'),
    ('/admin/', 'admin'),
    ('/admin/config', 'config'),
    ('/admin/update', 'update'),
]


class TestLogoOnAllPages:
    """Logo PNG appears on every page that extends base.html (AC1)."""

    @pytest.mark.parametrize('url,page_name', PAGES)
    def test_brand_logo_present(self, client, url, page_name):
        """Each page has an img.brand-logo in the header."""
        response = client.get(url)
        assert response.status_code == 200
        soup = BeautifulSoup(response.data, 'html.parser')
        logo = soup.find('img', class_='brand-logo')
        assert logo is not None, f'Logo not found on {page_name} ({url})'

    @pytest.mark.parametrize('url,page_name', PAGES)
    def test_brand_logo_alt_text(self, client, url, page_name):
        """Each page's logo has alt='Logo NETSCOPE' (AC4)."""
        response = client.get(url)
        soup = BeautifulSoup(response.data, 'html.parser')
        logo = soup.find('img', class_='brand-logo')
        assert logo is not None
        assert logo.get('alt') == 'Logo NETSCOPE', \
            f'Wrong alt text on {page_name}: {logo.get("alt")}'

    @pytest.mark.parametrize('url,page_name', PAGES)
    def test_brand_logo_has_dimensions(self, client, url, page_name):
        """Each page's logo has width and height attributes (AC5)."""
        response = client.get(url)
        soup = BeautifulSoup(response.data, 'html.parser')
        logo = soup.find('img', class_='brand-logo')
        assert logo is not None
        assert logo.get('width') is not None, \
            f'Missing width on {page_name}'
        assert logo.get('height') is not None, \
            f'Missing height on {page_name}'

    @pytest.mark.parametrize('url,page_name', PAGES)
    def test_nav_brand_is_link_to_home(self, client, url, page_name):
        """nav-brand is an <a> pointing to / (AC4)."""
        response = client.get(url)
        soup = BeautifulSoup(response.data, 'html.parser')
        brand = soup.find('a', class_='nav-brand')
        assert brand is not None, \
            f'nav-brand link not found on {page_name}'
        assert brand.get('href') == '/', \
            f'nav-brand href is {brand.get("href")} on {page_name}'


class TestFaviconOnAllPages:
    """Favicon link tag in head of every page (AC2)."""

    @pytest.mark.parametrize('url,page_name', PAGES)
    def test_favicon_present(self, client, url, page_name):
        """Each page has a link rel=icon in the head."""
        response = client.get(url)
        soup = BeautifulSoup(response.data, 'html.parser')
        favicon = soup.find('link', rel='icon')
        assert favicon is not None, \
            f'Favicon not found on {page_name} ({url})'
        assert 'netscope.png' in favicon.get('href', ''), \
            f'Favicon does not reference netscope.png on {page_name}'


class TestOldSvgRemoved:
    """Old SVG brand-icon is no longer in the DOM (AC1)."""

    @pytest.mark.parametrize('url,page_name', PAGES)
    def test_no_brand_icon_svg(self, client, url, page_name):
        """No element with class brand-icon in rendered pages."""
        response = client.get(url)
        soup = BeautifulSoup(response.data, 'html.parser')
        old_icon = soup.find(class_='brand-icon')
        assert old_icon is None, \
            f'Old brand-icon still present on {page_name}'
