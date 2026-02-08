"""Jobs API endpoints for NETSCOPE.

Provides REST API for Scapy inspection job management.

Story 4.1: Lancement Inspection Scapy (FR22)
- POST /api/jobs: Creer un job d'inspection
- GET /api/jobs: Lister tous les jobs
- GET /api/jobs/<job_id>: Details d'un job specifique

Lessons Learned Epic 1/2/3:
- Use module-level logger, NOT current_app.logger
- Standard response format: {"success": bool, "result": {...}, "error": {...}}
"""

import logging

from flask import jsonify, request

from . import api_bp
from app.core.inspection.job_models import create_job
from app.core.inspection.job_queue import get_job_queue
from app.services.thread_manager import get_thread_manager

logger = logging.getLogger(__name__)


@api_bp.route('/jobs', methods=['POST'])
def create_inspection_job():
    """Creer un job d'inspection Scapy.

    Request Body:
        {"target_ip": "192.168.1.1", "target_port": 443, "protocol": "TCP", "duration": 30}

    Returns:
        201: Job cree avec succes
        400: Parametres invalides
        503: Queue saturee
    """
    logger.debug("POST /api/jobs called")

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_INVALID_PARAMS",
                "message": "Corps de requete JSON invalide ou manquant",
                "details": {},
            },
        }), 400

    if "target_ip" not in data:
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_INVALID_PARAMS",
                "message": "Champ 'target_ip' requis",
                "details": {"field": "target_ip"},
            },
        }), 400

    try:
        job = create_job(
            target_ip=data["target_ip"],
            target_port=data.get("target_port"),
            protocol=data.get("protocol"),
            duration=data.get("duration", 30),
        )
    except ValueError as exc:
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_INVALID_PARAMS",
                "message": str(exc),
                "details": {},
            },
        }), 400

    queue = get_job_queue()
    if queue.is_full():
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_QUEUE_FULL",
                "message": "File d'attente saturee, reessayez plus tard",
                "details": {},
            },
        }), 503

    submitted = queue.submit(job)

    logger.info(
        f"Job created (job_id={submitted.spec.id}, "
        f"target={submitted.spec.target_ip})"
    )

    return jsonify({
        "success": True,
        "result": submitted.to_dict(),
    }), 201


@api_bp.route('/jobs', methods=['GET'])
def list_jobs():
    """Lister tous les jobs d'inspection.

    Returns:
        JSON response with list of jobs, count, and available slots
    """
    logger.debug("GET /api/jobs called")

    queue = get_job_queue()
    jobs = queue.get_all_jobs()
    tm = get_thread_manager()

    return jsonify({
        "success": True,
        "result": {
            "jobs": [j.to_dict() for j in jobs],
            "count": len(jobs),
            "available_slots": tm.get_available_job_slots(),
        },
    }), 200


@api_bp.route('/jobs/<job_id>', methods=['GET'])
def get_job(job_id):
    """Details d'un job specifique.

    Args:
        job_id: ID du job a consulter

    Returns:
        200: Details du job
        404: Job non trouve
    """
    logger.debug(f"GET /api/jobs/{job_id} called")

    queue = get_job_queue()
    job = queue.get_job(job_id)

    if job is None:
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_NOT_FOUND",
                "message": f"Job '{job_id}' non trouve",
                "details": {},
            },
        }), 404

    return jsonify({
        "success": True,
        "result": job.to_dict(),
    }), 200
