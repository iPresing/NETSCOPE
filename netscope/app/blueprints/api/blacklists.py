"""Blacklist API endpoints for NETSCOPE.

Provides REST API for blacklist statistics, management and user CRUD.

Story 4b.6: CRUD Blacklists — Interface Web
- POST /api/blacklists → ajouter entrée user
- GET /api/blacklists/user → lister entrées user
- DELETE /api/blacklists/<entry_id> → supprimer entrée user
"""

import logging
from flask import jsonify, request, current_app

from . import api_bp
from app.core.detection import get_blacklist_manager
from app.models.blacklist import (
    BlacklistType,
    BLACKLIST_DUPLICATE,
    BLACKLIST_INVALID_TYPE,
    BLACKLIST_INVALID_VALUE,
    BLACKLIST_NOT_FOUND,
    BLACKLIST_LIMIT_REACHED,
    BLACKLIST_DEFAULT_READONLY,
)
from app.services.blacklist_user_manager import get_blacklist_user_manager

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

    Story 4b.9 : la réponse inclut désormais `by_file` qui mappe chaque
    fichier default (ex: `ips_malware.txt`) à sa liste d'entrées, permettant
    au front d'attribuer la source à chaque entrée dans le tableau.

    Returns:
        JSON response with lists of active entries

    Example Response:
        {
            "success": true,
            "result": {
                "ips": ["192.168.1.1", "10.0.0.1"],
                "domains": ["malware.com", "phishing.com"],
                "terms": ["/bin/bash -i", "nc -e"],
                "by_file": {
                    "ips_malware.txt": ["185.220.100.240", ...],
                    "ips_c2.txt": [...]
                }
            }
        }
    """
    logger.debug("GET /api/blacklists/active called")

    try:
        manager = get_blacklist_manager()
        active_lists = manager.get_active_lists()
        # TODO(perf): by_file duplique toutes les entrées (déjà dans ips/domains/terms).
        # À 652 entrées c'est acceptable (~13 KB), mais si le dataset dépasse 1500+,
        # envisager un endpoint dédié ou un index inversé {value: filename}.
        active_lists["by_file"] = manager.get_entries_by_file()

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


@api_bp.route('/blacklists/sources', methods=['GET'])
def get_blacklist_sources():
    """Get metadata for default blacklist files (Story 4b.9).

    Returns:
        JSON response with sources metadata parsed from .meta.yaml files

    Example Response:
        {
            "success": true,
            "result": {
                "sources": [
                    {
                        "name": "ips_malware",
                        "category": "ip",
                        "file": "ips_malware.txt",
                        "description": "IPs malware...",
                        "entries_count": 112,
                        "last_updated": "2026-04-08T00:00:00+00:00",
                        "sources": [
                            {"name": "IPsum", "url": "...", "license": "Unlicense"}
                        ]
                    }
                ],
                "count": 5
            }
        }
    """
    logger.debug("GET /api/blacklists/sources called")

    try:
        manager = get_blacklist_manager()
        metadata = manager.get_defaults_metadata()

        return jsonify({
            "success": True,
            "result": {
                "sources": metadata,
                "count": len(metadata),
            },
        }), 200

    except Exception as e:
        logger.error(f"Error getting blacklist sources (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "BLACKLIST_SOURCES_ERROR",
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


# =========================================================================
# User Blacklist CRUD Endpoints (Story 4b.6)
# =========================================================================

@api_bp.route('/blacklists/user', methods=['GET'])
def list_user_blacklists():
    """List all user blacklist entries.

    Returns:
        JSON response with list of user entries and count
    """
    logger.debug("GET /api/blacklists/user called")

    try:
        manager = get_blacklist_user_manager()
        entries = manager.get_all()

        return jsonify({
            "success": True,
            "result": {
                "entries": [e.to_dict() for e in entries],
                "count": len(entries),
            },
        }), 200

    except (OSError, IOError, ValueError, KeyError) as e:
        logger.error(f"Error listing user blacklists (error={str(e)})")
        return jsonify({
            "success": False,
            "error": {
                "code": "BLACKLIST_LIST_ERROR",
                "message": f"Erreur: {str(e)}",
                "details": {},
            },
        }), 500


@api_bp.route('/blacklists', methods=['POST'])
def add_user_blacklist():
    """Add an entry to the user blacklist.

    Request body:
        {
            "value": "192.168.1.100",
            "type": "ip",        // optional, auto-detected if omitted
            "reason": "Suspect"  // optional
        }

    Returns:
        201: Entry created successfully
        400: Validation error (invalid value, duplicate, limit reached)
    """
    logger.debug("POST /api/blacklists called")

    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "success": False,
            "error": {
                "code": BLACKLIST_INVALID_VALUE,
                "message": "Corps de requête JSON invalide",
                "details": {},
            },
        }), 400

    value = data.get("value", "").strip()
    if not value:
        return jsonify({
            "success": False,
            "error": {
                "code": BLACKLIST_INVALID_VALUE,
                "message": "La valeur est requise",
                "details": {},
            },
        }), 400

    # Parse entry type (optional)
    entry_type = None
    type_str = data.get("type")
    if type_str:
        try:
            entry_type = BlacklistType(type_str)
        except ValueError:
            return jsonify({
                "success": False,
                "error": {
                    "code": BLACKLIST_INVALID_TYPE,
                    "message": f"Type invalide: '{type_str}'. Valeurs acceptées: ip, domain, term",
                    "details": {},
                },
            }), 400

    reason = data.get("reason", "").strip()

    try:
        manager = get_blacklist_user_manager()
        entry = manager.add(value, entry_type=entry_type, reason=reason)

        logger.info(f"User blacklist entry added (id={entry.id}, type={entry.entry_type.value})")

        return jsonify({
            "success": True,
            "result": entry.to_dict(),
        }), 201

    except ValueError as e:
        error_msg = str(e)
        if "Doublon" in error_msg:
            code = BLACKLIST_DUPLICATE
        elif "Limite" in error_msg:
            code = BLACKLIST_LIMIT_REACHED
        elif "invalide" in error_msg.lower():
            code = BLACKLIST_INVALID_VALUE
        else:
            code = BLACKLIST_INVALID_VALUE

        return jsonify({
            "success": False,
            "error": {
                "code": code,
                "message": error_msg,
                "details": {},
            },
        }), 400


@api_bp.route('/blacklists/<entry_id>', methods=['DELETE'])
def delete_user_blacklist(entry_id):
    """Delete a user blacklist entry by ID.

    Args:
        entry_id: ID of the entry to delete (must start with bl_)

    Returns:
        200: Entry deleted successfully
        400: Attempt to delete a default entry
        404: Entry not found
    """
    logger.debug(f"DELETE /api/blacklists/{entry_id} called")

    # Reject deletion of default entries
    if not entry_id.startswith("bl_"):
        return jsonify({
            "success": False,
            "error": {
                "code": BLACKLIST_DEFAULT_READONLY,
                "message": "Les entrées par défaut ne peuvent pas être supprimées",
                "details": {},
            },
        }), 400

    try:
        manager = get_blacklist_user_manager()
        removed = manager.remove(entry_id)

        logger.info(f"User blacklist entry deleted (id={entry_id}, value={removed.value})")

        return jsonify({
            "success": True,
            "result": removed.to_dict(),
        }), 200

    except KeyError:
        return jsonify({
            "success": False,
            "error": {
                "code": BLACKLIST_NOT_FOUND,
                "message": f"Entrée '{entry_id}' non trouvée",
                "details": {},
            },
        }), 404
