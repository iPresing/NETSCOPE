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
from app.core.inspection.job_models import create_job, JobStatus
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
            target_port_direction=data.get("target_port_direction"),
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
        stats = queue.get_queue_stats()
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_QUEUE_FULL",
                "message": f"File d'attente saturee ({stats['pending_count']}/{stats['max_queue_size']} jobs en attente)",
                "details": {
                    "max_queue_size": stats["max_queue_size"],
                    "pending_count": stats["pending_count"],
                    "running_count": stats["running_count"],
                },
            },
        }), 503

    submitted = queue.submit(job)

    logger.info(
        f"Job created (job_id={submitted.spec.id}, "
        f"target={submitted.spec.target_ip})"
    )

    result = submitted.to_dict()
    response = {
        "success": True,
        "result": result,
    }

    if submitted.status == JobStatus.PENDING:
        position = queue.get_queue_position(submitted.spec.id)
        if position is not None:
            result["queue_position"] = position
            jobs_ahead = position - 1
            if jobs_ahead == 0:
                response["message"] = "Job en attente - premier dans la file"
            elif jobs_ahead == 1:
                response["message"] = "Job en attente - 1 job devant"
            else:
                response["message"] = f"Job en attente - {jobs_ahead} jobs devant"
        else:
            response["message"] = "Job en attente"
    else:
        response["message"] = "Job cree - inspection en cours"

    return jsonify(response), 201


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

    job_dicts = []
    for j in jobs:
        d = j.to_dict()
        if j.status == JobStatus.PENDING:
            position = queue.get_queue_position(j.spec.id)
            if position is not None:
                d["queue_position"] = position
        job_dicts.append(d)

    return jsonify({
        "success": True,
        "result": {
            "jobs": job_dicts,
            "count": len(jobs),
            "available_slots": tm.get_available_job_slots(),
            "queue_stats": queue.get_queue_stats(),
        },
    }), 200


@api_bp.route('/jobs/<job_id>/cancel', methods=['POST'])
def cancel_job(job_id):
    """Annuler ou arreter un job d'inspection.

    Args:
        job_id: ID du job a annuler

    Returns:
        200: Job annule/arrete
        404: Job non trouve
        409: Job deja termine
    """
    logger.debug(f"POST /api/jobs/{job_id}/cancel called")

    if not job_id or not job_id.strip():
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_NOT_FOUND",
                "message": "Job inexistant",
                "details": {"job_id": job_id},
            },
        }), 404

    queue = get_job_queue()
    job = queue.get_job(job_id)

    if job is None:
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_NOT_FOUND",
                "message": "Job inexistant",
                "details": {"job_id": job_id},
            },
        }), 404

    previous_status = job.status.value

    if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
        return jsonify({
            "success": False,
            "error": {
                "code": "JOB_ALREADY_COMPLETED",
                "message": "Le job est déjà terminé",
                "details": {"job_id": job_id, "status": previous_status},
            },
        }), 409

    success = queue.cancel_job(job_id)

    if success:
        message = "Job arrêté" if previous_status == "running" else "Job annulé"
        return jsonify({
            "success": True,
            "result": {
                "job_id": job_id,
                "previous_status": previous_status,
                "status": "cancelled",
            },
            "message": message,
        }), 200

    return jsonify({
        "success": False,
        "error": {
            "code": "JOB_ALREADY_COMPLETED",
            "message": "Le job est déjà terminé",
            "details": {"job_id": job_id, "status": job.status.value},
        },
    }), 409


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

    result = job.to_dict()
    if job.status == JobStatus.PENDING:
        position = queue.get_queue_position(job_id)
        if position is not None:
            result["queue_position"] = position
            result["jobs_ahead"] = position - 1

    return jsonify({
        "success": True,
        "result": result,
    }), 200
