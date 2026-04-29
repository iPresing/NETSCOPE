"""Endpoints API pour l'export des données NETSCOPE.

Story 5.1: Export CSV des anomalies (FR45, FR47, NFR8, NFR46).
Story 5.2: Export JSON des anomalies (FR46, FR47, NFR8, NFR47).

CSV : flux `text/csv` (charset UTF-8, BOM) en streaming.
JSON : document complet `application/json` (charset UTF-8, sans BOM).

Patterns (Règles #4, #9, #13) :
- Imports module-level, logger module-level
- Logs structurés clé=valeur (capture_id, anomaly_count, duration_ms)
- Réponse JSON 404 gracieuse pour capture_id inexistant
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone

from flask import Response, jsonify, request, stream_with_context

from . import api_bp
from app.core.detection.anomaly_store import get_anomaly_store
from app.services.export_service import get_csv_exporter, get_json_exporter

logger = logging.getLogger(__name__)

CSV_MIMETYPE = "text/csv; charset=utf-8"
JSON_MIMETYPE = "application/json; charset=utf-8"


def _sanitize_for_header(value: str) -> str:
    """Retire les caractères dangereux pour un header HTTP (Content-Disposition)."""
    return re.sub(r'[\r\n\";]', "", value)


def _filename_for(capture_id: str, ext: str = "csv") -> str:
    """Produit le nom de fichier `netscope-anomalies-{capture_id}-{timestamp}.{ext}`."""
    safe_id = _sanitize_for_header(capture_id)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"netscope-anomalies-{safe_id}-{stamp}.{ext}"


@api_bp.route("/exports/csv", methods=["GET"])
def export_anomalies_csv():
    """Exporte les anomalies d'une capture au format CSV (streaming).

    Query Parameters:
        capture_id: str - ID de capture ciblé (optionnel, défaut = dernière).

    Returns:
        200 : `text/csv; charset=utf-8` avec BOM, header + lignes anomalies.
              `Content-Disposition: attachment` avec nom de fichier normalisé.
        404 : JSON d'erreur si `capture_id` fourni mais introuvable ou si
              aucune capture n'a jamais été effectuée.
    """
    start_time = time.perf_counter()
    capture_id_arg = request.args.get("capture_id")

    logger.info(f"GET /api/exports/csv called (capture_id={capture_id_arg or 'latest'})")

    store = get_anomaly_store()

    if capture_id_arg:
        collection = store.get_by_capture(capture_id_arg)
        if collection is None:
            logger.warning(
                f"CSV export rejected (capture_id={capture_id_arg}, reason=not_found)"
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "code": "CAPTURE_NOT_FOUND",
                            "message": f"Capture {capture_id_arg} non trouvée",
                            "details": {},
                        },
                    }
                ),
                404,
            )
    else:
        collection = store.get_latest()
        if collection is None:
            logger.info("CSV export with empty store — returning header-only CSV")

    # Capture_id effectif pour le nom de fichier.
    resolved_capture_id = (
        collection.capture_id if collection and collection.capture_id else "none"
    )
    anomaly_count = collection.total if collection else 0

    exporter = get_csv_exporter()
    stream = exporter.generate_anomalies_csv(collection)

    def _log_and_stream():
        try:
            for chunk in stream:
                yield chunk
        finally:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            logger.info(
                f"CSV export completed "
                f"(capture_id={resolved_capture_id}, "
                f"anomaly_count={anomaly_count}, "
                f"duration_ms={duration_ms})"
            )

    response = Response(
        stream_with_context(_log_and_stream()),
        mimetype=CSV_MIMETYPE,
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{_filename_for(resolved_capture_id)}"'
    )
    response.headers["X-Anomaly-Count"] = str(anomaly_count)
    return response


@api_bp.route("/exports/json", methods=["GET"])
def export_anomalies_json():
    """Exporte les anomalies d'une capture au format JSON (document complet).

    Query Parameters:
        capture_id: str - ID de capture ciblé (optionnel, défaut = dernière).

    Returns:
        200 : `application/json; charset=utf-8` avec Content-Disposition attachment.
        404 : JSON d'erreur si `capture_id` fourni mais introuvable.
    """
    start_time = time.perf_counter()
    capture_id_arg = request.args.get("capture_id")

    logger.info(f"GET /api/exports/json called (capture_id={capture_id_arg or 'latest'})")

    store = get_anomaly_store()

    if capture_id_arg:
        collection = store.get_by_capture(capture_id_arg)
        if collection is None:
            logger.warning(
                f"JSON export rejected (capture_id={capture_id_arg}, reason=not_found)"
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "code": "CAPTURE_NOT_FOUND",
                            "message": f"Capture {capture_id_arg} non trouvée",
                            "details": {},
                        },
                    }
                ),
                404,
            )
    else:
        collection = store.get_latest()
        if collection is None:
            logger.info("JSON export with empty store — returning empty anomalies")

    resolved_capture_id = (
        collection.capture_id if collection and collection.capture_id else "none"
    )
    anomaly_count = collection.total if collection else 0

    exporter = get_json_exporter()
    json_content = exporter.generate_anomalies_json(collection)

    duration_ms = int((time.perf_counter() - start_time) * 1000)
    logger.info(
        f"JSON export completed "
        f"(capture_id={resolved_capture_id}, "
        f"anomaly_count={anomaly_count}, "
        f"duration_ms={duration_ms})"
    )

    response = Response(json_content, mimetype=JSON_MIMETYPE)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{_filename_for(resolved_capture_id, "json")}"'
    )
    response.headers["X-Anomaly-Count"] = str(anomaly_count)
    return response
