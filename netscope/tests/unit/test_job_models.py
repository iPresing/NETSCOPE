"""Tests unitaires pour les modeles de donnees Job.

Story 4.1 - Task 1 & Task 7 (7.1-7.7)
"""

import pytest

from app.core.inspection.job_models import (
    Job,
    JobResult,
    JobSpec,
    JobStatus,
    create_job,
    DURATION_DEFAULT,
    DURATION_MAX,
    DURATION_MIN,
    PORT_MAX,
    PORT_MIN,
    VALID_PROTOCOLS,
)


class TestCreateJob:
    """Tests pour la factory create_job()."""

    def test_create_job_with_valid_ip(self):
        """7.2: create_job() avec IP valide retourne Job avec status PENDING."""
        job = create_job(target_ip="192.168.1.1")

        assert isinstance(job, Job)
        assert job.status == JobStatus.PENDING
        assert job.spec.target_ip == "192.168.1.1"
        assert job.spec.target_port is None
        assert job.spec.protocol is None
        assert job.spec.duration == DURATION_DEFAULT
        assert job.spec.id.startswith("job_")
        assert job.progress_percent == 0
        assert job.result is None

    def test_create_job_with_all_params(self):
        """create_job() avec tous les parametres."""
        job = create_job(
            target_ip="10.0.0.1",
            target_port=443,
            protocol="TCP",
            duration=60,
        )

        assert job.spec.target_ip == "10.0.0.1"
        assert job.spec.target_port == 443
        assert job.spec.protocol == "TCP"
        assert job.spec.duration == 60

    def test_create_job_rejects_invalid_ip(self):
        """7.3: create_job() rejette IP invalide (ValueError)."""
        with pytest.raises(ValueError, match="IP cible invalide"):
            create_job(target_ip="abc")

    def test_create_job_rejects_empty_ip(self):
        """create_job() rejette IP vide."""
        with pytest.raises(ValueError, match="IP cible invalide"):
            create_job(target_ip="")

    def test_create_job_rejects_ip_out_of_range(self):
        """create_job() rejette IP avec octet > 255."""
        with pytest.raises(ValueError, match="IP cible invalide"):
            create_job(target_ip="256.1.1.1")

    def test_create_job_rejects_ipv6(self):
        """create_job() rejette IPv6."""
        with pytest.raises(ValueError, match="IP cible invalide"):
            create_job(target_ip="::1")

    def test_create_job_rejects_duration_too_low(self):
        """7.4: create_job() rejette duree hors limites (trop basse)."""
        with pytest.raises(ValueError, match="Duree invalide"):
            create_job(target_ip="192.168.1.1", duration=DURATION_MIN - 1)

    def test_create_job_rejects_duration_too_high(self):
        """7.4: create_job() rejette duree hors limites (trop haute)."""
        with pytest.raises(ValueError, match="Duree invalide"):
            create_job(target_ip="192.168.1.1", duration=DURATION_MAX + 1)

    def test_create_job_accepts_min_duration(self):
        """create_job() accepte duree minimum."""
        job = create_job(target_ip="192.168.1.1", duration=DURATION_MIN)
        assert job.spec.duration == DURATION_MIN

    def test_create_job_accepts_max_duration(self):
        """create_job() accepte duree maximum."""
        job = create_job(target_ip="192.168.1.1", duration=DURATION_MAX)
        assert job.spec.duration == DURATION_MAX

    def test_create_job_rejects_port_too_low(self):
        """7.5: create_job() rejette port hors limites (trop bas)."""
        with pytest.raises(ValueError, match="Port invalide"):
            create_job(target_ip="192.168.1.1", target_port=PORT_MIN - 1)

    def test_create_job_rejects_port_too_high(self):
        """7.5: create_job() rejette port hors limites (trop haut)."""
        with pytest.raises(ValueError, match="Port invalide"):
            create_job(target_ip="192.168.1.1", target_port=PORT_MAX + 1)

    def test_create_job_accepts_min_port(self):
        """create_job() accepte port minimum."""
        job = create_job(target_ip="192.168.1.1", target_port=PORT_MIN)
        assert job.spec.target_port == PORT_MIN

    def test_create_job_accepts_max_port(self):
        """create_job() accepte port maximum."""
        job = create_job(target_ip="192.168.1.1", target_port=PORT_MAX)
        assert job.spec.target_port == PORT_MAX

    def test_create_job_rejects_invalid_protocol(self):
        """create_job() rejette protocole invalide."""
        with pytest.raises(ValueError, match="Protocole invalide"):
            create_job(target_ip="192.168.1.1", protocol="HTTP")

    def test_create_job_normalizes_protocol_case(self):
        """create_job() normalise le protocole en majuscules."""
        job = create_job(target_ip="192.168.1.1", protocol="tcp")
        assert job.spec.protocol == "TCP"

    def test_create_job_unique_ids(self):
        """create_job() genere des IDs uniques."""
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.1")
        assert job1.spec.id != job2.spec.id


class TestJobSpecSerialization:
    """Tests pour JobSpec.to_dict()/from_dict()."""

    def test_jobspec_roundtrip(self):
        """7.6: JobSpec.to_dict()/from_dict() roundtrip."""
        job = create_job(
            target_ip="10.0.0.1",
            target_port=8080,
            protocol="UDP",
            duration=60,
        )
        spec_dict = job.spec.to_dict()
        restored = JobSpec.from_dict(spec_dict)

        assert restored.id == job.spec.id
        assert restored.target_ip == job.spec.target_ip
        assert restored.target_port == job.spec.target_port
        assert restored.protocol == job.spec.protocol
        assert restored.duration == job.spec.duration

    def test_job_roundtrip(self):
        """Job.to_dict()/from_dict() roundtrip."""
        job = create_job(target_ip="192.168.1.100", target_port=443)
        job_dict = job.to_dict()
        restored = Job.from_dict(job_dict)

        assert restored.spec.id == job.spec.id
        assert restored.status == job.status
        assert restored.progress_percent == job.progress_percent

    def test_job_result_roundtrip(self):
        """JobResult.to_dict()/from_dict() roundtrip."""
        from datetime import datetime, timezone

        result = JobResult(
            job_id="job_abc12345",
            status=JobStatus.COMPLETED,
            packets_captured=42,
            start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            end_time=datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        )
        result_dict = result.to_dict()
        restored = JobResult.from_dict(result_dict)

        assert restored.job_id == result.job_id
        assert restored.status == result.status
        assert restored.packets_captured == result.packets_captured


class TestJobStatusEnum:
    """Tests pour JobStatus enum."""

    def test_job_status_covers_all_states(self):
        """7.7: JobStatus enum couvre tous les etats."""
        expected = {"pending", "running", "completed", "failed", "cancelled"}
        actual = {s.value for s in JobStatus}
        assert actual == expected

    def test_job_status_values(self):
        """JobStatus enum a les bonnes valeurs."""
        assert JobStatus.PENDING.value == "pending"
        assert JobStatus.RUNNING.value == "running"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"
        assert JobStatus.CANCELLED.value == "cancelled"


class TestValidProtocols:
    """Tests pour les protocoles valides."""

    @pytest.mark.parametrize("protocol", VALID_PROTOCOLS)
    def test_valid_protocols_accepted(self, protocol):
        """Tous les protocoles valides sont acceptes."""
        job = create_job(target_ip="192.168.1.1", protocol=protocol)
        assert job.spec.protocol == protocol
