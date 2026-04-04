"""E2E tests for Story 4b.7 — Inspection form → Packet viewer flow.

Tests HTML structure, navigation, and full form→redirect→filter flow.
Uses BeautifulSoup for HTML parsing (project E2E convention).
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from bs4 import BeautifulSoup

from app.models.capture import PacketInfo


class TestJobsPageRefonte:
    """E2E: Jobs page has been refactored to Inspection (AC4, AC5)."""

    def test_page_title_is_inspection(self, client):
        """Page title should be 'Inspection de Paquets'."""
        response = client.get('/jobs')
        assert response.status_code == 200
        soup = BeautifulSoup(response.data, 'html.parser')
        h2 = soup.find('h2')
        assert h2 is not None
        assert 'Inspection de Paquets' in h2.text

    def test_no_duration_field(self, client):
        """Duration field should be removed from form."""
        response = client.get('/jobs')
        soup = BeautifulSoup(response.data, 'html.parser')
        duration_input = soup.find('input', {'id': 'job-duration'})
        assert duration_input is None

    def test_inspect_button_present(self, client):
        """'Voir les Paquets' button should replace 'Lancer Inspection'."""
        response = client.get('/jobs')
        soup = BeautifulSoup(response.data, 'html.parser')
        btn = soup.find('button', {'id': 'btn-inspect-packets'})
        assert btn is not None
        assert 'Voir les Paquets' in btn.text

    def test_no_create_job_button(self, client):
        """Old 'btn-create-job' button should not exist."""
        response = client.get('/jobs')
        soup = BeautifulSoup(response.data, 'html.parser')
        btn = soup.find('button', {'id': 'btn-create-job'})
        assert btn is None

    def test_history_section_present(self, client):
        """Job history section should still be present (read-only)."""
        response = client.get('/jobs')
        soup = BeautifulSoup(response.data, 'html.parser')
        history = soup.find('div', {'id': 'jobs-history-list'})
        assert history is not None

    def test_no_active_jobs_section(self, client):
        """Active jobs section should be removed."""
        response = client.get('/jobs')
        soup = BeautifulSoup(response.data, 'html.parser')
        active = soup.find('div', {'id': 'jobs-active-list'})
        assert active is None

    def test_no_queue_section(self, client):
        """Queue section should be removed."""
        response = client.get('/jobs')
        soup = BeautifulSoup(response.data, 'html.parser')
        queue = soup.find('div', {'id': 'jobs-queue-list'})
        assert queue is None

    def test_form_fields_present(self, client):
        """IP, port, direction, protocol fields should still be present."""
        response = client.get('/jobs')
        soup = BeautifulSoup(response.data, 'html.parser')
        assert soup.find('input', {'id': 'job-target-ip'}) is not None
        assert soup.find('input', {'id': 'job-target-port'}) is not None
        assert soup.find('select', {'id': 'job-port-direction'}) is not None
        assert soup.find('select', {'id': 'job-protocol'}) is not None


class TestNavigationUpdate:
    """E2E: Navigation label updated from 'Jobs' to 'Inspection' (AC5)."""

    def test_nav_shows_inspection_label(self, client):
        """Navigation should show 'Inspection' instead of 'Jobs'."""
        response = client.get('/')
        soup = BeautifulSoup(response.data, 'html.parser')
        nav_links = soup.find_all('span', class_='nav-text')
        nav_texts = [link.text.strip() for link in nav_links]
        assert 'Inspection' in nav_texts
        assert 'Jobs' not in nav_texts


class TestPacketsPageBanners:
    """E2E: Packets page has manual filter banner (AC2)."""

    def test_manual_filter_banner_exists(self, client):
        """Manual filter banner element should exist (hidden by default)."""
        response = client.get('/packets')
        soup = BeautifulSoup(response.data, 'html.parser')
        banner = soup.find('section', {'id': 'manual-filter-banner'})
        assert banner is not None
        assert banner.get('style') == 'display: none;'

    def test_anomaly_banner_still_exists(self, client):
        """Anomaly context banner should still be present."""
        response = client.get('/packets')
        soup = BeautifulSoup(response.data, 'html.parser')
        banner = soup.find('section', {'id': 'anomaly-context-banner'})
        assert banner is not None

    def test_clear_filters_button_exists(self, client):
        """Clear filters button should exist in manual banner."""
        response = client.get('/packets')
        soup = BeautifulSoup(response.data, 'html.parser')
        btn = soup.find('button', {'id': 'clear-manual-filters'})
        assert btn is not None
        assert 'Effacer filtres' in btn.text


class TestAnomalyFlowRegression:
    """E2E regression: anomaly → packets flow unchanged (AC6)."""

    @patch('app.blueprints.api.packets.find_pcap_by_capture_id')
    @patch('app.blueprints.api.packets._get_parsed_packets')
    @patch('app.blueprints.api.packets.get_anomaly_store')
    def test_anomaly_flow_still_works(self, mock_store, mock_parse, mock_find, client):
        """Navigating from anomaly should still resolve and filter correctly."""
        mock_anomaly = MagicMock()
        mock_anomaly.id = "ano_001"
        mock_anomaly.capture_id = "cap_test"
        mock_anomaly.match.matched_value = "10.0.0.1"
        mock_anomaly.match.match_type.value = "ip"
        mock_anomaly.criticality_level.value = "critical"
        mock_anomaly.score = 85
        mock_anomaly.packet_info = {}
        mock_store.return_value.get_anomaly.return_value = mock_anomaly
        mock_find.return_value = '/fake/path.pcap'
        mock_parse.return_value = ([
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 0),
                ip_src="10.0.0.1", ip_dst="192.168.1.1",
                port_src=12345, port_dst=443,
                protocol="TCP", length=100,
            )
        ], None)

        response = client.get('/api/packets?anomaly_id=ano_001')
        data = response.get_json()
        assert data['success'] is True
        assert data['result']['anomaly_context'] is not None
        assert data['result']['anomaly_context']['anomaly_id'] == 'ano_001'
        assert data['result']['anomaly_context']['matched_value'] == '10.0.0.1'


class TestJobsApiRegression:
    """E2E regression: POST /api/jobs still functional (AC7)."""

    def test_jobs_api_endpoint_exists(self, client):
        """POST /api/jobs endpoint should still exist."""
        response = client.post('/api/jobs', json={
            'target_ip': '10.0.0.1',
        })
        # Should not return 404 (endpoint exists)
        # May return 4xx/5xx due to missing dependencies, but not 404
        assert response.status_code != 404

    def test_jobs_api_get_works(self, client):
        """GET /api/jobs should still return job list."""
        response = client.get('/api/jobs')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
