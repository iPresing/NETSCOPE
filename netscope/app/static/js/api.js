/**
 * NETSCOPE API Client
 * Version: 0.1.0
 *
 * Client-side API wrapper for NETSCOPE backend endpoints.
 * Uses Vanilla ES6+ fetch API.
 */

(function() {
    'use strict';

    /**
     * API client configuration.
     */
    var config = {
        baseUrl: '/api',
        timeout: 30000
    };

    /**
     * Make an API request.
     * @param {string} endpoint - API endpoint path
     * @param {Object} options - Fetch options
     * @returns {Promise<Object>} Response data
     */
    function request(endpoint, options) {
        options = options || {};
        var url = config.baseUrl + endpoint;

        var fetchOptions = {
            method: options.method || 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        };

        if (options.body) {
            fetchOptions.body = JSON.stringify(options.body);
        }

        return fetch(url, fetchOptions)
            .then(function(response) {
                return response.json().then(function(data) {
                    if (!response.ok) {
                        throw {
                            status: response.status,
                            data: data
                        };
                    }
                    return data;
                });
            })
            .catch(function(error) {
                console.error('[NETSCOPE API] Request failed:', endpoint, error);
                throw error;
            });
    }

    /**
     * GET request helper.
     * @param {string} endpoint - API endpoint
     * @returns {Promise<Object>} Response data
     */
    function get(endpoint) {
        return request(endpoint, { method: 'GET' });
    }

    /**
     * POST request helper.
     * @param {string} endpoint - API endpoint
     * @param {Object} data - Request body
     * @returns {Promise<Object>} Response data
     */
    function post(endpoint, data) {
        return request(endpoint, { method: 'POST', body: data });
    }

    /**
     * Get system health status.
     * @returns {Promise<Object>} Health status
     */
    function getHealth() {
        return get('/health');
    }

    /**
     * Get network status.
     * @returns {Promise<Object>} Network status
     */
    function getNetworkStatus() {
        return get('/network/status');
    }

    /**
     * Get available network interfaces.
     * @returns {Promise<Object>} Interfaces list
     */
    function getInterfaces() {
        return get('/network/interfaces');
    }

    // Export API client
    window.NetScope = window.NetScope || {};
    window.NetScope.api = {
        get: get,
        post: post,
        getHealth: getHealth,
        getNetworkStatus: getNetworkStatus,
        getInterfaces: getInterfaces
    };

})();
