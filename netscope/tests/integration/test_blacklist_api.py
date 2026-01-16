"""Integration tests for Blacklist API endpoints.

Tests the blacklist REST API endpoints with a test Flask client.
"""

import pytest


class TestBlacklistApiStats:
    """Test GET /api/blacklists/stats endpoint."""

    def test_get_stats_returns_200(self, client):
        """Test that stats endpoint returns 200 OK."""
        response = client.get('/api/blacklists/stats')
        assert response.status_code == 200

    def test_get_stats_returns_json(self, client):
        """Test that stats endpoint returns valid JSON."""
        response = client.get('/api/blacklists/stats')
        data = response.get_json()
        assert data is not None
        assert 'success' in data

    def test_get_stats_success_true(self, client):
        """Test that stats endpoint returns success: true."""
        response = client.get('/api/blacklists/stats')
        data = response.get_json()
        assert data['success'] is True

    def test_get_stats_has_result(self, client):
        """Test that stats endpoint returns result object."""
        response = client.get('/api/blacklists/stats')
        data = response.get_json()
        assert 'result' in data
        assert data['result'] is not None

    def test_get_stats_has_counts(self, client):
        """Test that stats result contains count fields."""
        response = client.get('/api/blacklists/stats')
        data = response.get_json()
        result = data['result']

        assert 'ips_count' in result
        assert 'domains_count' in result
        assert 'terms_count' in result
        assert 'total_entries' in result
        assert 'files_loaded' in result

    def test_get_stats_counts_are_integers(self, client):
        """Test that stats counts are integers."""
        response = client.get('/api/blacklists/stats')
        data = response.get_json()
        result = data['result']

        assert isinstance(result['ips_count'], int)
        assert isinstance(result['domains_count'], int)
        assert isinstance(result['terms_count'], int)
        assert isinstance(result['total_entries'], int)

    def test_get_stats_files_loaded_is_list(self, client):
        """Test that files_loaded is a list."""
        response = client.get('/api/blacklists/stats')
        data = response.get_json()
        result = data['result']

        assert isinstance(result['files_loaded'], list)

    def test_get_stats_total_equals_sum(self, client):
        """Test that total_entries equals sum of individual counts."""
        response = client.get('/api/blacklists/stats')
        data = response.get_json()
        result = data['result']

        expected_total = result['ips_count'] + result['domains_count'] + result['terms_count']
        assert result['total_entries'] == expected_total

    def test_get_stats_starter_pack_loaded(self, client):
        """Test that starter pack is loaded at app startup."""
        response = client.get('/api/blacklists/stats')
        data = response.get_json()
        result = data['result']

        # At minimum, starter pack should have some entries
        assert result['ips_count'] > 0
        assert result['domains_count'] > 0
        assert result['terms_count'] > 0


class TestBlacklistApiActive:
    """Test GET /api/blacklists/active endpoint."""

    def test_get_active_returns_200(self, client):
        """Test that active endpoint returns 200 OK."""
        response = client.get('/api/blacklists/active')
        assert response.status_code == 200

    def test_get_active_returns_json(self, client):
        """Test that active endpoint returns valid JSON."""
        response = client.get('/api/blacklists/active')
        data = response.get_json()
        assert data is not None
        assert 'success' in data

    def test_get_active_success_true(self, client):
        """Test that active endpoint returns success: true."""
        response = client.get('/api/blacklists/active')
        data = response.get_json()
        assert data['success'] is True

    def test_get_active_has_result(self, client):
        """Test that active endpoint returns result object."""
        response = client.get('/api/blacklists/active')
        data = response.get_json()
        assert 'result' in data
        assert data['result'] is not None

    def test_get_active_has_lists(self, client):
        """Test that active result contains list fields."""
        response = client.get('/api/blacklists/active')
        data = response.get_json()
        result = data['result']

        assert 'ips' in result
        assert 'domains' in result
        assert 'terms' in result

    def test_get_active_lists_are_lists(self, client):
        """Test that active lists are arrays."""
        response = client.get('/api/blacklists/active')
        data = response.get_json()
        result = data['result']

        assert isinstance(result['ips'], list)
        assert isinstance(result['domains'], list)
        assert isinstance(result['terms'], list)

    def test_get_active_lists_are_sorted(self, client):
        """Test that active lists are sorted alphabetically."""
        response = client.get('/api/blacklists/active')
        data = response.get_json()
        result = data['result']

        if len(result['ips']) > 1:
            assert result['ips'] == sorted(result['ips'])
        if len(result['domains']) > 1:
            assert result['domains'] == sorted(result['domains'])
        if len(result['terms']) > 1:
            assert result['terms'] == sorted(result['terms'])

    def test_get_active_ips_has_entries(self, client):
        """Test that active IPs contains entries from starter pack."""
        response = client.get('/api/blacklists/active')
        data = response.get_json()
        result = data['result']

        assert len(result['ips']) > 0

    def test_get_active_domains_lowercase(self, client):
        """Test that active domains are lowercase."""
        response = client.get('/api/blacklists/active')
        data = response.get_json()
        result = data['result']

        for domain in result['domains']:
            assert domain == domain.lower()


class TestBlacklistApiReload:
    """Test POST /api/blacklists/reload endpoint."""

    def test_reload_returns_200(self, client):
        """Test that reload endpoint returns 200 OK."""
        response = client.post('/api/blacklists/reload')
        assert response.status_code == 200

    def test_reload_returns_json(self, client):
        """Test that reload endpoint returns valid JSON."""
        response = client.post('/api/blacklists/reload')
        data = response.get_json()
        assert data is not None
        assert 'success' in data

    def test_reload_success_true(self, client):
        """Test that reload endpoint returns success: true."""
        response = client.post('/api/blacklists/reload')
        data = response.get_json()
        assert data['success'] is True

    def test_reload_has_result(self, client):
        """Test that reload endpoint returns result with stats."""
        response = client.post('/api/blacklists/reload')
        data = response.get_json()
        assert 'result' in data
        assert 'ips_count' in data['result']

    def test_reload_has_message(self, client):
        """Test that reload endpoint returns success message."""
        response = client.post('/api/blacklists/reload')
        data = response.get_json()
        assert 'message' in data

    def test_reload_preserves_stats(self, client):
        """Test that reload preserves blacklist counts."""
        # Get stats before reload
        before = client.get('/api/blacklists/stats').get_json()['result']

        # Reload
        client.post('/api/blacklists/reload')

        # Get stats after reload
        after = client.get('/api/blacklists/stats').get_json()['result']

        # Counts should remain the same (same files)
        assert after['ips_count'] == before['ips_count']
        assert after['domains_count'] == before['domains_count']
        assert after['terms_count'] == before['terms_count']


class TestBlacklistApiIntegration:
    """Integration tests combining multiple endpoints."""

    def test_stats_and_active_count_match(self, client):
        """Test that stats counts match active list lengths."""
        stats_response = client.get('/api/blacklists/stats')
        stats = stats_response.get_json()['result']

        active_response = client.get('/api/blacklists/active')
        active = active_response.get_json()['result']

        assert len(active['ips']) == stats['ips_count']
        assert len(active['domains']) == stats['domains_count']
        assert len(active['terms']) == stats['terms_count']

    def test_reload_updates_stats(self, client):
        """Test that reload endpoint updates stats correctly."""
        # Reload
        reload_response = client.post('/api/blacklists/reload')
        reload_stats = reload_response.get_json()['result']

        # Get fresh stats
        stats_response = client.get('/api/blacklists/stats')
        stats = stats_response.get_json()['result']

        # Should match
        assert reload_stats['ips_count'] == stats['ips_count']
        assert reload_stats['domains_count'] == stats['domains_count']
        assert reload_stats['terms_count'] == stats['terms_count']

    def test_api_response_format_consistent(self, client):
        """Test that all endpoints use consistent response format."""
        endpoints = [
            ('GET', '/api/blacklists/stats'),
            ('GET', '/api/blacklists/active'),
            ('POST', '/api/blacklists/reload'),
        ]

        for method, url in endpoints:
            if method == 'GET':
                response = client.get(url)
            else:
                response = client.post(url)

            data = response.get_json()

            # All endpoints should have 'success' field
            assert 'success' in data, f"Missing 'success' in {method} {url}"

            # All successful responses should have 'result' (or be success:true)
            if data['success']:
                assert 'result' in data or 'message' in data, \
                    f"Missing 'result' or 'message' in {method} {url}"


class TestBlacklistApiErrorHandling:
    """Test error handling for blacklist API."""

    def test_stats_get_only(self, client):
        """Test that stats endpoint only accepts GET."""
        response = client.post('/api/blacklists/stats')
        assert response.status_code == 405

    def test_active_get_only(self, client):
        """Test that active endpoint only accepts GET."""
        response = client.post('/api/blacklists/active')
        assert response.status_code == 405

    def test_reload_post_only(self, client):
        """Test that reload endpoint only accepts POST."""
        response = client.get('/api/blacklists/reload')
        assert response.status_code == 405
