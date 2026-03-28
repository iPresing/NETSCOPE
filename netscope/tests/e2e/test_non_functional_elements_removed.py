"""E2E tests for removal of non-functional elements (Story 4b.3).

Tests that disabled buttons, non-functional controls, and placeholder cards
have been removed from admin and dashboard pages.

AC Coverage:
- AC1: Boutons admin non-fonctionnels retirés ou masqués (config page)
- AC2: Page mise à jour nettoyée (update page)
- AC3: Cards admin désactivées clarifiées (admin page)
- AC4: Four Essentials cohérents (dashboard volume card)
- AC5: Parcours utilisateur complet sans casse
- AC6: Tests E2E couvrent les éléments retirés
"""

import pytest
from bs4 import BeautifulSoup


class TestConfigPageRemovedElements:
    """AC1: Boutons admin non-fonctionnels retirés de config."""

    def test_config_page_loads(self, client):
        """Config page returns 200."""
        response = client.get('/admin/config')
        assert response.status_code == 200

    def test_export_button_removed(self, client):
        """AC1: Button 'Exporter Configuration' is not present."""
        response = client.get('/admin/config')
        html = response.data.decode('utf-8')
        assert 'Exporter Configuration' not in html

    def test_import_button_removed(self, client):
        """AC1: Button 'Importer Configuration' is not present."""
        response = client.get('/admin/config')
        html = response.data.decode('utf-8')
        assert 'Importer Configuration' not in html

    def test_reset_button_removed(self, client):
        """AC1: Button 'Réinitialiser' is not present."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        danger_btns = soup.find_all('button', class_='btn-danger')
        for btn in danger_btns:
            assert 'initialiser' not in btn.get_text().lower()

    def test_interface_select_removed(self, client):
        """AC1: Disabled select #interface-select is not present."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        assert soup.find(id='interface-select') is None

    def test_default_filter_removed(self, client):
        """AC1: Disabled input #default-filter is not present."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        assert soup.find(id='default-filter') is None

    def test_default_duration_removed(self, client):
        """AC1: Disabled select #default-duration is not present."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        assert soup.find(id='default-duration') is None

    def test_max_packets_removed(self, client):
        """AC1: Disabled input #max-packets is not present."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        assert soup.find(id='max-packets') is None

    def test_detection_checkboxes_removed(self, client):
        """AC1: Disabled detection checkboxes are not present."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        disabled_checkboxes = soup.find_all('input', {'type': 'checkbox', 'disabled': True})
        assert len(disabled_checkboxes) == 0, (
            f"Found {len(disabled_checkboxes)} disabled checkboxes, expected 0"
        )

    def test_informative_message_present(self, client):
        """AC1: Informative message about future availability is shown."""
        response = client.get('/admin/config')
        html = response.data.decode('utf-8')
        assert 'version future' in html.lower()

    def test_whitelist_section_preserved(self, client):
        """AC1: Functional whitelist section is still present."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        assert soup.find(id='admin-wl-count') is not None

    def test_no_disabled_form_elements(self, client):
        """AC6: Zero elements with disabled without functional justification."""
        response = client.get('/admin/config')
        soup = BeautifulSoup(response.data, 'html.parser')
        disabled_elements = soup.find_all(attrs={'disabled': True})
        assert len(disabled_elements) == 0, (
            f"Found {len(disabled_elements)} disabled elements on config page"
        )


class TestUpdatePageRemovedElements:
    """AC2: Page mise à jour nettoyée."""

    def test_update_page_loads(self, client):
        """Update page returns 200."""
        response = client.get('/admin/update')
        assert response.status_code == 200

    def test_github_check_button_removed(self, client):
        """AC2: Button 'Vérifier sur GitHub' is not present."""
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        assert soup.find(id='check-update-btn') is None

    def test_settings_checkboxes_removed(self, client):
        """AC2: Disabled parameter checkboxes are not present."""
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        disabled_checkboxes = soup.find_all('input', {'type': 'checkbox', 'disabled': True})
        assert len(disabled_checkboxes) == 0, (
            f"Found {len(disabled_checkboxes)} disabled checkboxes, expected 0"
        )

    def test_version_info_preserved(self, client):
        """AC2: Version information section is still present."""
        response = client.get('/admin/update')
        html = response.data.decode('utf-8')
        assert 'v0.1.0' in html

    def test_update_history_preserved(self, client):
        """AC2: Update history table is still present."""
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        table = soup.find('table', class_='data-table')
        assert table is not None

    def test_informative_messages_present(self, client):
        """AC2: Informative messages about future availability are shown."""
        response = client.get('/admin/update')
        html = response.data.decode('utf-8').lower()
        assert 'version future' in html

    def test_no_disabled_form_elements(self, client):
        """AC6: Zero elements with disabled without functional justification."""
        response = client.get('/admin/update')
        soup = BeautifulSoup(response.data, 'html.parser')
        disabled_elements = soup.find_all(attrs={'disabled': True})
        assert len(disabled_elements) == 0, (
            f"Found {len(disabled_elements)} disabled elements on update page"
        )


class TestAdminPageRemovedCards:
    """AC3: Cards admin désactivées clarifiées."""

    def test_admin_page_loads(self, client):
        """Admin index page returns 200."""
        response = client.get('/admin/')
        assert response.status_code == 200

    def test_logs_card_removed(self, client):
        """AC3: Card 'Logs' is not present."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        cards = soup.find_all(class_='admin-card')
        card_titles = [c.find('h4').get_text() for c in cards if c.find('h4')]
        assert 'Logs' not in card_titles

    def test_sauvegarde_card_removed(self, client):
        """AC3: Card 'Sauvegarde' is not present."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        cards = soup.find_all(class_='admin-card')
        card_titles = [c.find('h4').get_text() for c in cards if c.find('h4')]
        assert 'Sauvegarde' not in card_titles

    def test_no_disabled_admin_cards(self, client):
        """AC3: No admin cards have the 'disabled' class."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        disabled_cards = soup.find_all('div', class_=['admin-card', 'disabled'])
        # Filter to only those with BOTH classes
        truly_disabled = [c for c in disabled_cards if 'disabled' in c.get('class', [])]
        assert len(truly_disabled) == 0

    def test_functional_cards_remain(self, client):
        """AC3: Functional cards (Mise à Jour, Configuration) are still present."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        cards = soup.find_all(class_='admin-card')
        card_titles = [c.find('h4').get_text() for c in cards if c.find('h4')]
        assert 'Mise à Jour' in card_titles
        assert 'Configuration' in card_titles

    def test_functional_cards_are_links(self, client):
        """AC3: Remaining cards are clickable links (not div)."""
        response = client.get('/admin/')
        soup = BeautifulSoup(response.data, 'html.parser')
        card_links = soup.find_all('a', class_='admin-card')
        assert len(card_links) == 2


class TestDashboardFourEssentials:
    """AC4: Four Essentials cohérents — no generic 'Voir' links."""

    def _get_dashboard_soup(self, client):
        from unittest.mock import patch
        with patch('app.blueprints.dashboard.routes.get_tcpdump_manager') as mock_mgr:
            mock_mgr.return_value.get_latest_result.return_value = None
            response = client.get('/')
            assert response.status_code == 200
            return BeautifulSoup(response.data, 'html.parser')

    def test_no_generic_links_on_status_cards(self, client):
        """AC4: Status cards do NOT have generic 'Voir →' links to anomalies."""
        soup = self._get_dashboard_soup(client)
        card_ids = ['card-ips', 'card-protocols', 'card-ports', 'card-volume']
        for card_id in card_ids:
            card = soup.find(id=card_id)
            assert card is not None, f"Card {card_id} should exist"
            link = card.find('a', class_='status-card-link')
            assert link is None, f"Card {card_id} should NOT have a generic 'Voir' link"

    def test_all_four_cards_exist(self, client):
        """AC4: All 4 status cards are present on dashboard."""
        soup = self._get_dashboard_soup(client)
        for card_id in ['card-ips', 'card-protocols', 'card-ports', 'card-volume']:
            assert soup.find(id=card_id) is not None, f"Card {card_id} missing"

    def test_volume_card_structure_matches_others(self, client):
        """AC4: Volume card has same visual structure as IPs card (header, value, details)."""
        soup = self._get_dashboard_soup(client)
        ips_card = soup.find(id='card-ips')
        volume_card = soup.find(id='card-volume')

        for card, name in [(ips_card, 'ips'), (volume_card, 'volume')]:
            assert card.find(class_='status-card-header') is not None, f"{name} missing header"
            assert card.find(class_='status-card-value') is not None, f"{name} missing value"
            assert card.find(class_='status-card-details') is not None, f"{name} missing details"

    def test_anomalies_section_has_view_all_link(self, client):
        """AC4: Anomalies section has 'Voir tout →' link for contextual navigation."""
        soup = self._get_dashboard_soup(client)
        anomalies_section = soup.find(id='anomalies-section')
        assert anomalies_section is not None
        link = anomalies_section.find('a', class_='anomalies-view-all')
        assert link is not None, "Anomalies section should have 'Voir tout' link"
        assert '/anomalies' in link.get('href', '')


class TestUserJourneyNoCrash:
    """AC5: Parcours utilisateur complet sans casse."""

    JOURNEY_PAGES = [
        ('/', 'dashboard'),
        ('/anomalies', 'anomalies'),
        ('/admin/', 'admin'),
        ('/admin/config', 'admin-config'),
        ('/admin/update', 'admin-update'),
        ('/packets', 'packets'),
        ('/jobs', 'jobs'),
    ]

    @pytest.mark.parametrize("route,name", JOURNEY_PAGES)
    def test_page_returns_200(self, client, route, name):
        """AC5: Page {name} loads without error."""
        response = client.get(route)
        assert response.status_code == 200, f"{name} returned {response.status_code}"

    @pytest.mark.parametrize("route,name", JOURNEY_PAGES)
    def test_page_has_glassmorphism(self, client, route, name):
        """AC5: Page {name} has glassmorphism card elements."""
        response = client.get(route)
        html = response.data.decode('utf-8')
        assert 'card' in html, f"No card class found on {name}"
