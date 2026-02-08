"""ScapyInspector pour l'inspection approfondie de paquets.

Story 4.1: Lancement Inspection Scapy (FR22)
- Construction filtre BPF depuis JobSpec
- Appel scapy.sniff() avec filtre et timeout
- Gestion erreurs: Scapy non disponible, permissions insuffisantes
- Support callback progres

Lessons Learned Epic 1/2/3:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Callable

from app.core.inspection.job_models import JobResult, JobSpec, JobStatus

logger = logging.getLogger(__name__)

# Import conditionnel de Scapy (regle: fallback avec message clair)
try:
    from scapy.all import sniff, conf as scapy_conf  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def build_bpf_filter(spec: JobSpec) -> str:
    """Construit un filtre BPF depuis les specifications du job.

    Exemples:
        IP seule         -> "host 45.33.32.156"
        IP + port        -> "host 45.33.32.156 and port 4444"
        IP + port + TCP  -> "host 45.33.32.156 and tcp port 4444"
        IP + protocole   -> "host 45.33.32.156 and tcp"

    Args:
        spec: Specification du job

    Returns:
        Filtre BPF sous forme de string
    """
    parts = [f"host {spec.target_ip}"]

    if spec.protocol and spec.target_port:
        parts.append(f"{spec.protocol.lower()} port {spec.target_port}")
    elif spec.target_port:
        parts.append(f"port {spec.target_port}")
    elif spec.protocol:
        parts.append(spec.protocol.lower())

    return " and ".join(parts)


class ScapyInspector:
    """Inspecteur de paquets utilisant Scapy.

    Execute des captures ciblees basees sur les specifications du job.
    """

    def run(
        self,
        spec: JobSpec,
        progress_callback: Callable[[int], None] | None = None,
    ) -> JobResult:
        """Execute une inspection Scapy selon les specifications.

        Args:
            spec: Specification du job (IP, port, protocole, duree)
            progress_callback: Callback pour mise a jour progression (0-100)

        Returns:
            JobResult avec les resultats de la capture

        Raises:
            RuntimeError: Si Scapy n'est pas disponible ou permissions insuffisantes
        """
        if not SCAPY_AVAILABLE:
            logger.error(
                f"Job failed "
                f"(job_id={spec.id}): Scapy non disponible"
            )
            return JobResult(
                job_id=spec.id,
                status=JobStatus.FAILED,
                error_message="Scapy n'est pas installe sur ce systeme",
            )

        bpf_filter = build_bpf_filter(spec)
        start_time = datetime.now(timezone.utc)

        logger.info(
            f"Job started "
            f"(job_id={spec.id}, filter='{bpf_filter}', duration={spec.duration}s)"
        )

        stop_event = None
        try:
            # Lancer un thread de progression base sur le temps
            if progress_callback:
                stop_event = threading.Event()
                self._start_progress_tracker(
                    spec.duration, progress_callback, stop_event
                )

            packets = sniff(
                filter=bpf_filter,
                timeout=spec.duration,
            )

            end_time = datetime.now(timezone.utc)
            packets_count = len(packets)

            logger.info(
                f"Job completed "
                f"(job_id={spec.id}, packets={packets_count})"
            )

            return JobResult(
                job_id=spec.id,
                status=JobStatus.COMPLETED,
                packets_captured=packets_count,
                start_time=start_time,
                end_time=end_time,
            )

        except PermissionError:
            logger.error(
                f"Job failed "
                f"(job_id={spec.id}): permissions root requises"
            )
            return JobResult(
                job_id=spec.id,
                status=JobStatus.FAILED,
                error_message="Permissions root requises pour la capture Scapy",
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
            )

        except Exception as exc:
            logger.error(
                f"Job failed "
                f"(job_id={spec.id}, error={exc})"
            )
            return JobResult(
                job_id=spec.id,
                status=JobStatus.FAILED,
                error_message=str(exc),
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
            )

        finally:
            if stop_event:
                stop_event.set()

    def _start_progress_tracker(
        self,
        duration: int,
        callback: Callable[[int], None],
        stop_event: threading.Event,
    ) -> None:
        """Lance un tracker de progression en arriere-plan.

        Calcule le pourcentage base sur le temps ecoule vs duree totale.
        S'arrete quand stop_event est set ou quand la duree est atteinte.

        Args:
            duration: Duree totale de la capture en secondes
            callback: Callback appele avec le pourcentage (0-100)
            stop_event: Event pour signaler l'arret du tracker
        """
        def track() -> None:
            start = time.monotonic()
            while not stop_event.is_set():
                elapsed = time.monotonic() - start
                percent = min(99, int((elapsed / duration) * 100))
                callback(percent)
                if elapsed >= duration:
                    break
                stop_event.wait(1)

        thread = threading.Thread(target=track, daemon=True)
        thread.start()
