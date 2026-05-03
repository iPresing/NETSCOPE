"""Endpoints API pour l'export des données NETSCOPE.

Story 5.1: Export CSV des anomalies (FR45, FR47, NFR8, NFR46).
Story 5.2: Export JSON des anomalies (FR46, FR47, NFR8, NFR47).
Story 5.3: Filtre export anomalies — paramètre anomalies_only (FR48).

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
from app.core.capture.packet_parser import find_pcap_by_capture_id
from app.core.detection.anomaly_store import get_anomaly_store
from app.services.export_service import get_csv_exporter, get_json_exporter

logger = logging.getLogger(__name__)

CSV_MIMETYPE = "text/csv; charset=utf-8"
JSON_MIMETYPE = "application/json; charset=utf-8"


def _sanitize_for_header(value: str) -> str:
    """Retire les caractères dangereux pour un header HTTP (Content-Disposition)."""
    return re.sub(r'[\r\n\";]', "", value)


def _filename_for(capture_id: str, ext: str = "csv", all_data: bool = False) -> str:
    """Produit le nom de fichier d'export.

    Mode anomalies : `netscope-anomalies-{capture_id}-{timestamp}.{ext}`
    Mode all-data  : `netscope-all-data-{capture_id}-{timestamp}.{ext}`
    """
    safe_id = _sanitize_for_header(capture_id)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    label = "all-data" if all_data else "anomalies"
    return f"netscope-{label}-{safe_id}-{stamp}.{ext}"


@api_bp.route("/exports/csv", methods=["GET"])
def export_anomalies_csv():
    """Exporte les anomalies d'une capture au format CSV (streaming).

    Query Parameters:
        capture_id: str - ID de capture ciblé (optionnel, défaut = dernière).
        anomalies_only: str - "true" (défaut) exporte anomalies seules,
            "false" exporte tous les paquets enrichis.

    Returns:
        200 : `text/csv; charset=utf-8` avec BOM, header + lignes.
              `Content-Disposition: attachment` avec nom de fichier normalisé.
        404 : JSON d'erreur si capture introuvable.
    """
    start_time = time.perf_counter()
    capture_id_arg = request.args.get("capture_id")
    anomalies_only = request.args.get("anomalies_only", "true").lower() != "false"

    export_mode = "anomalies_only" if anomalies_only else "all"
    logger.info(
        f"GET /api/exports/csv called "
        f"(capture_id={capture_id_arg or 'latest'}, export_mode={export_mode})"
    )

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

    resolved_capture_id = (
        collection.capture_id if collection and collection.capture_id else "none"
    )
    anomaly_count = collection.total if collection else 0

    exporter = get_csv_exporter()

    if anomalies_only:
        stream = exporter.generate_anomalies_csv(collection)
    else:
        pcap_path = find_pcap_by_capture_id(resolved_capture_id)
        if pcap_path is None:
            logger.warning(
                f"CSV all-data export rejected "
                f"(capture_id={resolved_capture_id}, reason=pcap_not_found)"
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "code": "PCAP_NOT_FOUND",
                            "message": f"Fichier pcap introuvable pour {resolved_capture_id}",
                            "details": {},
                        },
                    }
                ),
                404,
            )
        stream = exporter.generate_all_data_csv(pcap_path, collection)

    def _log_and_stream():
        try:
            for chunk in stream:
                yield chunk
        finally:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            logger.info(
                f"CSV export completed "
                f"(export_mode={export_mode}, "
                f"capture_id={resolved_capture_id}, "
                f"anomaly_count={anomaly_count}, "
                f"duration_ms={duration_ms})"
            )

    response = Response(
        stream_with_context(_log_and_stream()),
        mimetype=CSV_MIMETYPE,
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{_filename_for(resolved_capture_id, all_data=not anomalies_only)}"'
    )
    # X-Anomaly-Count = anomalies in collection (store). In all-data JSON,
    # metadata.anomaly_count = packets matched — may differ at the margins.
    response.headers["X-Anomaly-Count"] = str(anomaly_count)
    return response


@api_bp.route("/exports/json", methods=["GET"])
def export_anomalies_json():
    """Exporte les anomalies d'une capture au format JSON (document complet).

    Query Parameters:
        capture_id: str - ID de capture ciblé (optionnel, défaut = dernière).
        anomalies_only: str - "true" (défaut) exporte anomalies seules,
            "false" exporte tous les paquets enrichis.

    Returns:
        200 : `application/json; charset=utf-8` avec Content-Disposition attachment.
        404 : JSON d'erreur si capture introuvable.
    """
    start_time = time.perf_counter()
    capture_id_arg = request.args.get("capture_id")
    anomalies_only = request.args.get("anomalies_only", "true").lower() != "false"

    export_mode = "anomalies_only" if anomalies_only else "all"
    logger.info(
        f"GET /api/exports/json called "
        f"(capture_id={capture_id_arg or 'latest'}, export_mode={export_mode})"
    )

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

    if anomalies_only:
        json_content = exporter.generate_anomalies_json(collection)
    else:
        pcap_path = find_pcap_by_capture_id(resolved_capture_id)
        if pcap_path is None:
            logger.warning(
                f"JSON all-data export rejected "
                f"(capture_id={resolved_capture_id}, reason=pcap_not_found)"
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "code": "PCAP_NOT_FOUND",
                            "message": f"Fichier pcap introuvable pour {resolved_capture_id}",
                            "details": {},
                        },
                    }
                ),
                404,
            )
        json_content = exporter.generate_all_data_json(pcap_path, collection)

    duration_ms = int((time.perf_counter() - start_time) * 1000)
    logger.info(
        f"JSON export completed "
        f"(export_mode={export_mode}, "
        f"capture_id={resolved_capture_id}, "
        f"anomaly_count={anomaly_count}, "
        f"duration_ms={duration_ms})"
    )

    response = Response(json_content, mimetype=JSON_MIMETYPE)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{_filename_for(resolved_capture_id, "json", all_data=not anomalies_only)}"'
    )
    response.headers["X-Anomaly-Count"] = str(anomaly_count)
    return response
