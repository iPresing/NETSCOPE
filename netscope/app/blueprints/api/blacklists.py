"""Blacklist API endpoints for NETSCOPE.

Provides REST API for blacklist statistics and management.
"""

import logging
from flask import jsonify, current_app

from . import api_bp
from app.core.detection import get_blacklist_manager

logger = logging.getLogger(__name__)


@api_bp.route('/blacklists/stats', methods=['GET'])
def get_blacklist_stats():
    """Get blacklist statistics.

    Returns:
        JSON response with blacklist counts and loaded files

    Example Response:
        {
            "success": true,
            "result": {
                "ips_count": 35,
                "domains_count": 25,
                "terms_count": 15,
                "files_loaded": ["ips_malware.txt", ...],
                "total_entries": 75
            }
        }
    """
    logger.debug("GET /api/blacklists/stats called")

    try:
        manager = get_blacklist_manager()
        stats = manager.get_stats()

        return jsonify({
            "success": True,
            "result": stats.to_dict(),
        }), 200

    except Exception as e:
        logger.error(f"Error getting blacklist stats (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "BLACKLIST_STATS_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/blacklists/active', methods=['GET'])
def get_active_blacklists():
    """Get active blacklist entries by type.

    Returns:
        JSON response with lists of active entries

    Example Response:
        {
            "success": true,
            "result": {
                "ips": ["192.168.1.1", "10.0.0.1"],
                "domains": ["malware.com", "phishing.com"],
                "terms": ["/bin/bash -i", "nc -e"]
            }
        }
    """
    logger.debug("GET /api/blacklists/active called")

    try:
        manager = get_blacklist_manager()
        active_lists = manager.get_active_lists()

        return jsonify({
            "success": True,
            "result": active_lists,
        }), 200

    except Exception as e:
        logger.error(f"Error getting active blacklists (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "BLACKLIST_ACTIVE_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/blacklists/reload', methods=['POST'])
def reload_blacklists():
    """Reload blacklists from files.

    Forces a reload of all blacklist files.

    Returns:
        JSON response with new statistics
    """
    logger.info("POST /api/blacklists/reload called")

    try:
        import yaml
        from pathlib import Path

        # Get base path
        base_path = Path(current_app.root_path).parent

        # Load config from YAML
        config_path = base_path / 'data' / 'config' / 'netscope.yaml'

        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)

            blacklist_config = config_data.get('blacklists', {})
        else:
            blacklist_config = {}

        # Reload blacklists
        manager = get_blacklist_manager()
        manager.load_blacklists(blacklist_config, base_path=base_path)

        # Update app config
        stats = manager.get_stats()
        current_app.config['NETSCOPE_BLACKLIST_STATS'] = stats

        logger.info(
            f"Blacklists reloaded (ips={stats.ips_count}, "
            f"domains={stats.domains_count}, terms={stats.terms_count})"
        )

        return jsonify({
            "success": True,
            "message": "Blacklists rechargées avec succès",
            "result": stats.to_dict(),
        }), 200

    except Exception as e:
        logger.error(f"Error reloading blacklists (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "BLACKLIST_RELOAD_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500
