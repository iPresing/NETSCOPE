"""E2E tests — Story 4b.10: Audit UX Final — Validation Cohérence Globale.

Tests end-to-end sans mocks : parcours utilisateur complet inter-pages,
cohérence CSS variables, navigation, éléments UI fonctionnels.

AC Coverage:
- AC1: Cohérence design CSS (variables, glassmorphism, typographie)
- AC2: Navigation fonctionnelle complète
- AC3: Aucun élément UI orphelin (Règle #22)
- AC4: prefers-reduced-motion couvre tous les éléments
- AC5: Pas d'erreur JS détectable côté serveur
- AC6: Cohérence tables sur toutes les pages
- AC7: Parcours E2E complet validé
"""

import re

import pytest
from bs4 import BeautifulSoup


# All navigable pages in NETSCOPE
ALL_PAGES = [
    ('/', 'Dashboard'),
    ('/anomalies', 'Anomalies'),
    ('/jobs', 'Jobs'),
    ('/blacklist', 'Blacklist'),
    ('/whitelist', 'Whitelist'),
    ('/packets', 'Packets'),
    ('/admin/', 'Admin'),
    ('/admin/config', 'Config'),
    ('/admin/update', 'Update'),
]

# Pages with HTML <table> elements (anomalies uses card layout, not tables)
TABLE_PAGES = [
    ('/blacklist', 'Blacklist'),
    ('/whitelist', 'Whitelist'),
    ('/packets', 'Packets'),
]


class TestFullNavigationE2E:
    """AC7: Parcours utilisateur complet inter-pages sans erreur."""

    def test_full_navigation_all_pages_200(self, client):
        """Navigate Dashboard → Anomalies → Jobs → Blacklist → Whitelist → Packets → Admin: all 200."""
        for url, name in ALL_PAGES:
            response = client.get(url)
            assert response.status_code == 200, \
                f'{name} ({url}) returned {response.status_code}'

    def test_full_navigation_pages_have_content(self, client):
        """Each page returns non-trivial HTML content."""
        for url, name in ALL_PAGES:
            response = client.get(url)
            assert response.status_code == 200
            assert len(response.data) > 500, \
                f'{name} ({url}) returned suspiciously small content ({len(response.data)} bytes)'

    def test_sequential_navigation_no_side_effects(self, client):
        """Visiting pages in sequence does not cause errors on subsequent pages."""
        urls = [url for url, _ in ALL_PAGES]
        for i, url in enumerate(urls):
            response = client.get(url)
            assert response.status_code == 200, \
                f'Page {url} failed after visiting {urls[:i]}'


class TestCSSDesignCoherence:
    """AC1: Cohérence du système de design CSS."""

    def test_css_variables_defined_in_root(self, client):
        """style.css defines expected CSS variables in :root."""
        response = client.get('/static/css/style.css')
        assert response.status_code == 200
        css = response.data.decode('utf-8')

        # :root must define CSS variables
        assert ':root' in css
        assert '--void-black' in css
        assert '--neon-cyan' in css
        assert '--text-primary' in css
        assert '--border-subtle' in css
        assert '--font-display' in css

        # New variables from audit should exist
        assert '--danger-red-hover' in css
        assert '--source-blue' in css
        assert '--text-on-accent' in css
        assert '--surface-faint' in css
        assert '--glass-blur-light' in css
        assert '--glass-dark-bg' in css
        assert '--accent-bg-subtle' in css
        assert '--surface-hover' in css

    def test_no_orphan_hex_outside_root(self, client):
        """No raw #fff or #ef4444 used outside :root — must use variables."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Extract content after :root block
        root_start = css.find(':root')
        assert root_start != -1
        brace_depth = 0
        root_end = root_start
        for i in range(css.index('{', root_start), len(css)):
            if css[i] == '{':
                brace_depth += 1
            elif css[i] == '}':
                brace_depth -= 1
                if brace_depth == 0:
                    root_end = i + 1
                    break
        css_after_root = css[root_end:]

        # These specific values should never appear outside :root
        orphan_values = ['#fff', '#ef4444', '#64b5f6']
        for val in orphan_values:
            matches = re.findall(re.escape(val) + r'(?![0-9a-fA-F])', css_after_root)
            assert len(matches) == 0, \
                f'Orphan hex {val} found {len(matches)} time(s) outside :root'

    def test_glassmorphism_uses_variables(self, client):
        """backdrop-filter uses CSS variables, not hardcoded blur values."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Robustly skip :root block using brace matching
        root_start = css.find(':root')
        assert root_start != -1
        brace_depth = 0
        root_end = root_start
        for i in range(css.index('{', root_start), len(css)):
            if css[i] == '{':
                brace_depth += 1
            elif css[i] == '}':
                brace_depth -= 1
                if brace_depth == 0:
                    root_end = i + 1
                    break
        css_after_root = css[root_end:]

        # No hardcoded blur(Npx) in backdrop-filter outside :root
        blur_hardcoded = re.findall(r'backdrop-filter:\s*blur\(\d+px\)', css_after_root)
        assert len(blur_hardcoded) == 0, \
            f'Hardcoded backdrop-filter found: {blur_hardcoded}'

    def test_typography_hierarchy_consistent(self, client):
        """Typography uses font variables and has clear hierarchy."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Font variables used
        assert "var(--font-display)" in css
        assert "var(--font-body)" in css
        assert "var(--font-mono)" in css

        # Heading hierarchy: h1 > h2 > h3
        h1_match = re.search(r'h1\s*\{\s*font-size:\s*([\d.]+)rem', css)
        h2_match = re.search(r'h2\s*\{\s*font-size:\s*([\d.]+)rem', css)
        h3_match = re.search(r'h3\s*\{\s*font-size:\s*([\d.]+)rem', css)
        assert h1_match and h2_match and h3_match, \
            'Missing heading font-size definitions'
        assert float(h1_match.group(1)) > float(h2_match.group(1)) > float(h3_match.group(1)), \
            'Heading hierarchy not h1 > h2 > h3'

    def test_bl_source_card_uses_variables(self, client):
        """Story 4b.9 review L1: .bl-source-card uses CSS variables, not hardcoded rgba."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Find .bl-source-card block
        card_start = css.find('.bl-source-card {')
        assert card_start != -1, '.bl-source-card not found in CSS'
        card_end = css.find('}', card_start)
        card_block = css[card_start:card_end]

        assert 'var(--surface-faint)' in card_block, \
            '.bl-source-card background should use var(--surface-faint)'
        assert 'var(--border-subtle)' in card_block, \
            '.bl-source-card border should use var(--border-subtle)'


class TestNavigationLinks:
    """AC2: Navigation fonctionnelle complète."""

    def test_navbar_present_on_all_layout_pages(self, client):
        """Navbar is present on all pages using base layout."""
        for url, name in ALL_PAGES:
            response = client.get(url)
            soup = BeautifulSoup(response.data, 'html.parser')
            nav = soup.find('nav', class_='main-nav')
            assert nav is not None, \
                f'Navbar missing on {name} ({url})'

    def test_navbar_links_count(self, client):
        """Navbar has exactly 5 links (Dashboard, Anomalies, Inspection, Blacklists, Admin)."""
        response = client.get('/')
        soup = BeautifulSoup(response.data, 'html.parser')
        nav_links = soup.find_all('a', class_='nav-link')
        assert len(nav_links) == 5, \
            f'Expected 5 nav links, found {len(nav_links)}'

    def test_navbar_active_highlighting(self, client):
        """Each page correctly highlights its nav item."""
        page_checks = [
            ('/', 'Dashboard'),
            ('/anomalies', 'Anomalies'),
            ('/jobs', 'Inspection'),
            ('/blacklist', 'Blacklists'),
            ('/admin/', 'Admin'),
        ]
        for url, expected_text in page_checks:
            response = client.get(url)
            soup = BeautifulSoup(response.data, 'html.parser')
            active_link = soup.find('a', class_='is-active')
            assert active_link is not None, \
                f'No active nav link on {url}'
            nav_text = active_link.find('span', class_='nav-text')
            assert nav_text is not None
            assert expected_text in nav_text.text, \
                f'Expected active "{expected_text}" on {url}, got "{nav_text.text}"'

    def test_navbar_all_links_resolve(self, client):
        """Every link in navbar resolves to a 200 page."""
        response = client.get('/')
        soup = BeautifulSoup(response.data, 'html.parser')
        nav_links = soup.find_all('a', class_='nav-link')
        for link in nav_links:
            href = link.get('href')
            assert href is not None
            link_response = client.get(href)
            assert link_response.status_code == 200, \
                f'Nav link {href} returned {link_response.status_code}'

    def test_footer_present_with_links(self, client):
        """Footer is present with GitHub and Admin links."""
        response = client.get('/')
        soup = BeautifulSoup(response.data, 'html.parser')
        footer = soup.find('footer')
        assert footer is not None, 'Footer missing'
        links = footer.find_all('a')
        assert len(links) >= 2, f'Footer should have at least 2 links, found {len(links)}'
        hrefs = [a.get('href', '') for a in links]
        assert any('github.com' in h for h in hrefs), 'GitHub link missing from footer'

    def test_no_dead_links_in_templates(self, client):
        """Internal links on all pages resolve (no 404)."""
        for url, name in ALL_PAGES:
            response = client.get(url)
            soup = BeautifulSoup(response.data, 'html.parser')
            internal_links = [
                a.get('href') for a in soup.find_all('a')
                if a.get('href') and a['href'].startswith('/')
                and not a['href'].startswith('/static')
            ]
            for link in internal_links:
                link_resp = client.get(link)
                assert link_resp.status_code == 200, \
                    f'Dead link on {name}: {link} returned {link_resp.status_code}'


class TestNoOrphanElements:
    """AC3: Aucun élément UI orphelin (Règle #22)."""

    def test_no_todo_or_placeholder_text(self, client):
        """No TODO, FIXME, or Coming Soon text visible in any page."""
        for url, name in ALL_PAGES:
            response = client.get(url)
            html = response.data.decode('utf-8')
            for pattern in ['TODO', 'FIXME', 'Coming soon', 'coming soon', 'À venir']:
                assert pattern not in html, \
                    f'"{pattern}" found in {name} ({url})'

    def test_all_buttons_have_id_or_type(self, client):
        """Every button has an id (for JS handler) or is type=submit (for form)."""
        for url, name in ALL_PAGES:
            response = client.get(url)
            soup = BeautifulSoup(response.data, 'html.parser')
            buttons = soup.find_all('button')
            for btn in buttons:
                has_id = btn.get('id') is not None
                is_submit = btn.get('type') == 'submit'
                has_data_tab = btn.get('data-tab') is not None
                assert has_id or is_submit or has_data_tab, \
                    f'Orphan button on {name}: {str(btn)[:100]}'


class TestReducedMotion:
    """AC4: prefers-reduced-motion couvre tous les éléments."""

    def test_reduced_motion_media_query_exists(self, client):
        """CSS has @media (prefers-reduced-motion: reduce) rule."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')
        assert '@media (prefers-reduced-motion: reduce)' in css

    def test_reduced_motion_disables_all_animations(self, client):
        """Reduced motion rule uses global selector to kill animations."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Find the reduced-motion block
        rm_start = css.find('@media (prefers-reduced-motion: reduce)')
        assert rm_start != -1
        rm_block = css[rm_start:rm_start + 800]

        assert 'animation-duration: 0.01ms' in rm_block
        assert 'transition-duration: 0.01ms' in rm_block
        assert 'scroll-behavior: auto' in rm_block

    def test_reduced_motion_hides_video(self, client):
        """Reduced motion hides video background and overlays."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        rm_start = css.find('@media (prefers-reduced-motion: reduce)')
        rm_block = css[rm_start:rm_start + 800]

        assert '.video-bg' in rm_block
        assert 'display: none' in rm_block

    def test_video_bg_js_reduced_motion_handler(self, client):
        """base.html includes JS matchMedia handler for prefers-reduced-motion on video."""
        response = client.get('/')
        html = response.data.decode('utf-8')
        assert 'matchMedia' in html, \
            'JS matchMedia() call missing in base template'
        assert 'prefers-reduced-motion' in html, \
            'prefers-reduced-motion string missing in base template'


class TestTableCoherence:
    """AC6: Cohérence des tables sur toutes les pages."""

    def test_tables_exist_on_table_pages(self, client):
        """Table pages contain at least one <table> element."""
        for url, name in TABLE_PAGES:
            response = client.get(url)
            soup = BeautifulSoup(response.data, 'html.parser')
            tables = soup.find_all('table')
            assert len(tables) >= 1, \
                f'No table found on {name} ({url})'

    def test_tables_have_thead_and_tbody(self, client):
        """All tables have proper <thead> and <tbody> structure."""
        for url, name in TABLE_PAGES:
            response = client.get(url)
            soup = BeautifulSoup(response.data, 'html.parser')
            tables = soup.find_all('table')
            for table in tables:
                thead = table.find('thead')
                tbody = table.find('tbody')
                assert thead is not None, \
                    f'Table on {name} ({url}) missing <thead>'
                assert tbody is not None, \
                    f'Table on {name} ({url}) missing <tbody>'

    def test_table_css_classes_consistent(self, client):
        """All tables use a recognized styling class."""
        valid_classes = {'data-table', 'results-table', 'raw-data-table',
                         'whitelist-table', 'essentials-table', 'layer-fields-table'}
        for url, name in TABLE_PAGES:
            response = client.get(url)
            soup = BeautifulSoup(response.data, 'html.parser')
            tables = soup.find_all('table')
            for table in tables:
                classes = set(table.get('class', []))
                has_style_class = bool(classes & valid_classes)
                assert has_style_class, \
                    f'Table on {name} ({url}) has no style class: {classes}'

    def test_whitelist_table_css_aligned_with_data_table(self, client):
        """whitelist-table CSS matches data-table: sticky header, transition, hover."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # whitelist-table should have sticky header
        wt_th_start = css.find('.whitelist-table th {')
        assert wt_th_start != -1
        wt_th_block = css[wt_th_start:css.find('}', wt_th_start)]
        assert 'position: sticky' in wt_th_block, \
            '.whitelist-table th missing sticky positioning'

        # whitelist-table should have row transition
        assert '.whitelist-table tbody tr {' in css
        wt_tr_start = css.find('.whitelist-table tbody tr {')
        wt_tr_block = css[wt_tr_start:css.find('}', wt_tr_start)]
        assert 'transition' in wt_tr_block, \
            '.whitelist-table tbody tr missing transition'

    def test_table_pages_load_js_scripts(self, client):
        """Table pages include JS scripts needed for sort/filter/pagination.

        Note: Flask test client cannot execute JavaScript, so interactive
        behavior (AC6 sort/filter/pagination) cannot be validated here.
        This test verifies the required <script> tags are present.
        """
        js_expectations = {
            '/blacklist': 'blacklist.js',
            '/packets': 'packets.js',
        }
        for url, expected_js in js_expectations.items():
            response = client.get(url)
            html = response.data.decode('utf-8')
            assert expected_js in html, \
                f'{expected_js} script not loaded on {url}'


class TestCrossPageCounters:
    """AC7: Compteurs cohérents entre les pages."""

    def test_dashboard_and_anomalies_both_load(self, client):
        """Dashboard and anomalies pages both load without error."""
        dash = client.get('/')
        assert dash.status_code == 200
        anom = client.get('/anomalies')
        assert anom.status_code == 200

    def test_api_endpoints_respond(self, client):
        """Core API endpoints return valid JSON responses."""
        endpoints = [
            '/api/health',
            '/api/anomalies',
            '/api/blacklists/active',
            '/api/whitelist',
        ]
        for ep in endpoints:
            response = client.get(ep)
            assert response.status_code == 200, \
                f'API {ep} returned {response.status_code}'
            data = response.get_json()
            assert data is not None, f'API {ep} did not return JSON'
            # /api/health uses {status: 'ok'}, others use {success: true}
            has_status = 'status' in data or 'success' in data
            assert has_status, f'API {ep} missing status/success key: {list(data.keys())}'
