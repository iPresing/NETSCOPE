"""Tests unitaires — Story 4b.4: Logo NETSCOPE dans la bannière.

Vérifie que base.html contient le logo PNG, le favicon,
et que le CSS définit les règles .brand-logo correctement.

AC Coverage:
- AC1: Logo dans le header (img tag, alt, width/height)
- AC2: Favicon (link rel=icon dans head)
- AC3: Responsive (CSS media query 768px)
- AC4: Accessibilité (alt text)
- AC5: Performance (width/height explicites)
"""

import os
import re

import pytest
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEMPLATES_DIR = os.path.join(
    os.path.dirname(__file__),
    '..', '..', 'app', 'blueprints', 'dashboard', 'templates',
)

CSS_PATH = os.path.join(
    os.path.dirname(__file__),
    '..', '..', 'app', 'static', 'css', 'style.css',
)

IMG_PATH = os.path.join(
    os.path.dirname(__file__),
    '..', '..', 'app', 'static', 'img', 'netscope.png',
)


@pytest.fixture(scope='module')
def base_html():
    """Load the raw base.html template content."""
    path = os.path.join(TEMPLATES_DIR, 'base.html')
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


@pytest.fixture(scope='module')
def css_content():
    """Load the main CSS file content."""
    with open(CSS_PATH, 'r', encoding='utf-8') as f:
        return f.read()


def _find_rule_block(css, selector):
    """Extract the CSS rule block for a given selector."""
    pattern = re.escape(selector) + r'\s*\{([^}]*)\}'
    match = re.search(pattern, css)
    if match:
        return match.group(1)
    return None


def _find_media_rule_block(css, media_query, selector):
    """Extract a CSS rule block within a specific @media query."""
    media_pattern = re.escape(media_query) + r'\s*\{(.*?)\n\}'
    media_match = re.search(media_pattern, css, re.DOTALL)
    if not media_match:
        return None
    media_content = media_match.group(1)
    rule_pattern = re.escape(selector) + r'\s*\{([^}]*)\}'
    rule_match = re.search(rule_pattern, media_content)
    if rule_match:
        return rule_match.group(1)
    return None


# ===========================================================================
# AC1 — Logo dans le header
# ===========================================================================

class TestLogoInHeader:
    """Verify logo img tag replaces SVG in nav-brand (AC1, AC4, AC5)."""

    def test_brand_logo_img_exists(self, base_html):
        """base.html contains an img with class brand-logo."""
        assert 'brand-logo' in base_html
        assert '<img' in base_html

    def test_brand_logo_alt_text(self, base_html):
        """Logo img has descriptive alt attribute (AC4)."""
        assert 'alt="Logo NETSCOPE"' in base_html

    def test_brand_logo_width_height(self, base_html):
        """Logo img has explicit width/height to prevent CLS (AC5)."""
        assert 'width="38"' in base_html
        assert 'height="40"' in base_html

    def test_brand_logo_src_references_netscope_png(self, base_html):
        """Logo img src references netscope.png."""
        assert 'netscope.png' in base_html

    def test_netscope_h1_preserved(self, base_html):
        """The NETSCOPE h1 text is still present alongside the logo."""
        assert '<h1>NETSCOPE</h1>' in base_html

    def test_nav_brand_is_link(self, base_html):
        """nav-brand is an <a> tag linking to / (AC4)."""
        assert '<a href="/" class="nav-brand">' in base_html

    def test_old_svg_removed(self, base_html):
        """Old inline SVG icon no longer exists in nav-brand area."""
        assert 'brand-icon' not in base_html
        # No SVG with the old viewBox pattern
        assert 'viewBox="0 0 24 24"' not in base_html


# ===========================================================================
# AC2 — Favicon
# ===========================================================================

class TestFavicon:
    """Verify favicon link tag in head (AC2)."""

    def test_favicon_link_exists(self, base_html):
        """base.html head contains a link rel=icon."""
        assert 'rel="icon"' in base_html

    def test_favicon_type_png(self, base_html):
        """Favicon is type image/png."""
        assert 'type="image/png"' in base_html

    def test_favicon_references_netscope_png(self, base_html):
        """Favicon href references netscope.png."""
        # Find the link tag with rel=icon
        match = re.search(r'<link[^>]*rel="icon"[^>]*>', base_html)
        assert match is not None
        link_tag = match.group(0)
        assert 'netscope.png' in link_tag


# ===========================================================================
# AC1/AC3 — CSS .brand-logo
# ===========================================================================

class TestBrandLogoCSS:
    """Verify .brand-logo CSS rules (AC1, AC3)."""

    def test_brand_logo_height(self, css_content):
        """brand-logo has height: 36px."""
        block = _find_rule_block(css_content, '.brand-logo')
        assert block is not None, '.brand-logo rule not found in CSS'
        assert 'height' in block
        assert '36px' in block

    def test_brand_logo_object_fit(self, css_content):
        """brand-logo has object-fit: contain."""
        block = _find_rule_block(css_content, '.brand-logo')
        assert block is not None
        assert 'object-fit' in block
        assert 'contain' in block

    def test_brand_logo_width_auto(self, css_content):
        """brand-logo has width: auto."""
        block = _find_rule_block(css_content, '.brand-logo')
        assert block is not None
        assert 'width' in block
        assert 'auto' in block

    def test_brand_icon_removed(self, css_content):
        """Old .brand-icon CSS rule no longer exists."""
        block = _find_rule_block(css_content, '.brand-icon')
        assert block is None, '.brand-icon rule should have been removed'

    def test_brand_logo_responsive_768(self, css_content):
        """brand-logo has reduced height at 768px breakpoint (AC3)."""
        block = _find_media_rule_block(
            css_content, '@media (max-width: 768px)', '.brand-logo'
        )
        assert block is not None, '.brand-logo not found in 768px media query'
        assert 'height' in block
        assert '26px' in block


# ===========================================================================
# Logo asset exists
# ===========================================================================

class TestLogoAsset:
    """Verify the logo PNG file exists on disk."""

    def test_netscope_png_exists(self):
        """netscope.png exists in static/img/."""
        assert os.path.isfile(IMG_PATH), f'Logo file not found: {IMG_PATH}'
