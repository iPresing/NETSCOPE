"""Tests unitaires pour le ScapyInspector.

Story 4.1 - Task 3 & Task 7 (7.13-7.17)
"""

from unittest.mock import patch, MagicMock

from app.core.inspection.job_models import JobSpec, JobStatus
from app.core.inspection.scapy_inspector import ScapyInspector, build_bpf_filter


class TestBuildBpfFilter:
    """Tests pour build_bpf_filter()."""

    def _make_spec(self, ip="192.168.1.1", port=None, protocol=None):
        """Helper pour creer un JobSpec minimal."""
        return JobSpec(
            id="job_test1234",
            target_ip=ip,
            target_port=port,
            protocol=protocol,
        )

    def test_ip_only(self):
        """7.14: build_bpf_filter() avec IP seule."""
        spec = self._make_spec(ip="45.33.32.156")
        assert build_bpf_filter(spec) == "host 45.33.32.156"

    def test_ip_and_port(self):
        """7.15: build_bpf_filter() avec IP + port."""
        spec = self._make_spec(ip="45.33.32.156", port=4444)
        assert build_bpf_filter(spec) == "host 45.33.32.156 and port 4444"

    def test_ip_port_and_protocol(self):
        """7.16: build_bpf_filter() avec IP + port + protocole."""
        spec = self._make_spec(ip="45.33.32.156", port=4444, protocol="TCP")
        assert build_bpf_filter(spec) == "host 45.33.32.156 and tcp port 4444"

    def test_ip_and_protocol_only(self):
        """build_bpf_filter() avec IP + protocole sans port."""
        spec = self._make_spec(ip="10.0.0.1", protocol="UDP")
        assert build_bpf_filter(spec) == "host 10.0.0.1 and udp"

    def test_icmp_protocol(self):
        """build_bpf_filter() avec protocole ICMP."""
        spec = self._make_spec(ip="10.0.0.1", protocol="ICMP")
        assert build_bpf_filter(spec) == "host 10.0.0.1 and icmp"


class TestScapyInspectorRun:
    """Tests pour ScapyInspector.run()."""

    @patch("app.core.inspection.scapy_inspector.SCAPY_AVAILABLE", False)
    def test_run_scapy_unavailable(self):
        """run() retourne FAILED quand Scapy non disponible."""
        spec = JobSpec(id="job_test1234", target_ip="192.168.1.1")
        inspector = ScapyInspector()

        result = inspector.run(spec)

        assert result.status == JobStatus.FAILED
        assert "installe" in result.error_message

    @patch("app.core.inspection.scapy_inspector.SCAPY_AVAILABLE", True)
    @patch("app.core.inspection.scapy_inspector.sniff")
    def test_run_with_mocked_scapy(self, mock_sniff):
        """7.17: run() avec Scapy mocke retourne resultat."""
        # Simuler 5 paquets captures
        mock_packets = MagicMock()
        mock_packets.__len__ = MagicMock(return_value=5)
        mock_sniff.return_value = mock_packets

        spec = JobSpec(id="job_test1234", target_ip="192.168.1.1", duration=10)
        inspector = ScapyInspector()

        result = inspector.run(spec)

        assert result.status == JobStatus.COMPLETED
        assert result.packets_captured == 5
        assert result.start_time is not None
        assert result.end_time is not None
        mock_sniff.assert_called_once()

    @patch("app.core.inspection.scapy_inspector.SCAPY_AVAILABLE", True)
    @patch("app.core.inspection.scapy_inspector.sniff")
    def test_run_with_permission_error(self, mock_sniff):
        """run() retourne FAILED sur PermissionError."""
        mock_sniff.side_effect = PermissionError("Operation not permitted")

        spec = JobSpec(id="job_test1234", target_ip="192.168.1.1")
        inspector = ScapyInspector()

        result = inspector.run(spec)

        assert result.status == JobStatus.FAILED
        assert "root" in result.error_message.lower() or "permission" in result.error_message.lower()

    @patch("app.core.inspection.scapy_inspector.SCAPY_AVAILABLE", True)
    @patch("app.core.inspection.scapy_inspector.sniff")
    def test_run_with_bpf_filter(self, mock_sniff):
        """run() utilise le bon filtre BPF."""
        mock_packets = MagicMock()
        mock_packets.__len__ = MagicMock(return_value=0)
        mock_sniff.return_value = mock_packets

        spec = JobSpec(
            id="job_test1234",
            target_ip="10.0.0.1",
            target_port=443,
            protocol="TCP",
            duration=15,
        )
        inspector = ScapyInspector()
        inspector.run(spec)

        mock_sniff.assert_called_once_with(
            filter="host 10.0.0.1 and tcp port 443",
            timeout=15,
        )
