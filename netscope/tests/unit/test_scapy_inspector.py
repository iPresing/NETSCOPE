"""Tests unitaires pour le ScapyInspector.

Story 4.1 - Task 3 & Task 7 (7.13-7.17)
"""

from unittest.mock import patch, MagicMock

from app.core.inspection.job_models import JobSpec, JobStatus
from app.core.inspection.scapy_inspector import ScapyInspector, build_bpf_filter


class TestBuildBpfFilter:
    """Tests pour build_bpf_filter()."""

    def _make_spec(self, ip="192.168.1.1", port=None, protocol=None, direction=None):
        """Helper pour creer un JobSpec minimal."""
        return JobSpec(
            id="job_test1234",
            target_ip=ip,
            target_port=port,
            target_port_direction=direction,
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


class TestBpfFilterWithDirection:
    """Tests pour build_bpf_filter() avec direction du port (Story 4.2 - Task 7.2)."""

    def _make_spec(self, ip="192.168.1.1", port=None, protocol=None, direction=None):
        """Helper pour creer un JobSpec minimal."""
        return JobSpec(
            id="job_test1234",
            target_ip=ip,
            target_port=port,
            target_port_direction=direction,
            protocol=protocol,
        )

    def test_ip_port_direction_dst(self):
        """IP + port + direction 'dst' → 'host X and dst port Y'."""
        spec = self._make_spec(ip="10.0.0.1", port=4444, direction="dst")
        assert build_bpf_filter(spec) == "host 10.0.0.1 and dst port 4444"

    def test_ip_port_direction_src(self):
        """IP + port + direction 'src' → 'host X and src port Y'."""
        spec = self._make_spec(ip="10.0.0.1", port=4444, direction="src")
        assert build_bpf_filter(spec) == "host 10.0.0.1 and src port 4444"

    def test_ip_port_direction_both(self):
        """IP + port + direction 'both' → 'host X and port Y'."""
        spec = self._make_spec(ip="10.0.0.1", port=4444, direction="both")
        assert build_bpf_filter(spec) == "host 10.0.0.1 and port 4444"

    def test_ip_port_proto_direction_dst(self):
        """IP + port + proto + direction 'dst' → 'host X and tcp dst port Y'."""
        spec = self._make_spec(ip="10.0.0.1", port=4444, protocol="TCP", direction="dst")
        assert build_bpf_filter(spec) == "host 10.0.0.1 and tcp dst port 4444"

    def test_ip_port_proto_direction_src(self):
        """IP + port + proto + direction 'src' → 'host X and udp src port Y'."""
        spec = self._make_spec(ip="10.0.0.1", port=4444, protocol="UDP", direction="src")
        assert build_bpf_filter(spec) == "host 10.0.0.1 and udp src port 4444"

    def test_ip_port_no_direction_backward_compat(self):
        """IP + port sans direction → 'host X and port Y' (backward compat)."""
        spec = self._make_spec(ip="10.0.0.1", port=4444)
        assert build_bpf_filter(spec) == "host 10.0.0.1 and port 4444"


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
        # Retourner 1 paquet par iteration (duration=5 → 5 appels → 5 paquets)
        mock_sniff.return_value = [MagicMock()]

        spec = JobSpec(id="job_test1234", target_ip="192.168.1.1", duration=5)
        inspector = ScapyInspector()

        result = inspector.run(spec)

        assert result.status == JobStatus.COMPLETED
        assert result.packets_captured == 5
        assert result.start_time is not None
        assert result.end_time is not None
        assert mock_sniff.call_count == 5

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
        mock_sniff.return_value = []

        spec = JobSpec(
            id="job_test1234",
            target_ip="10.0.0.1",
            target_port=443,
            protocol="TCP",
            duration=5,
        )
        inspector = ScapyInspector()
        inspector.run(spec)

        # Verifier que tous les appels utilisent le bon filtre BPF
        assert mock_sniff.call_count == 5
        mock_sniff.assert_called_with(
            filter="host 10.0.0.1 and tcp port 443",
            timeout=1.0,
        )


class TestScapyInspectorStopEvent:
    """Tests pour stop_event dans ScapyInspector.run() (Story 4.6 - Task 6.2)."""

    @patch("app.core.inspection.scapy_inspector.SCAPY_AVAILABLE", True)
    @patch("app.core.inspection.scapy_inspector.sniff")
    def test_run_with_stop_event_stops_early(self, mock_sniff):
        """run() avec stop_event set s'arrete et retourne CANCELLED."""
        import threading

        stop_event = threading.Event()
        call_count = [0]

        def sniff_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] >= 2:
                stop_event.set()
            return []

        mock_sniff.side_effect = sniff_side_effect

        spec = JobSpec(id="job_test1234", target_ip="192.168.1.1", duration=30)
        inspector = ScapyInspector()

        result = inspector.run(spec, stop_event=stop_event)

        assert result.status == JobStatus.CANCELLED
        assert result.error_message == "Arrêté manuellement"
        assert mock_sniff.call_count < 30

    @patch("app.core.inspection.scapy_inspector.SCAPY_AVAILABLE", True)
    @patch("app.core.inspection.scapy_inspector.sniff")
    def test_run_with_stop_event_preserves_partial_packets(self, mock_sniff):
        """run() avec stop_event conserve les paquets captes avant l'arret."""
        import threading

        stop_event = threading.Event()
        call_count = [0]

        def sniff_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] >= 3:
                stop_event.set()
            return [MagicMock()]

        mock_sniff.side_effect = sniff_side_effect

        spec = JobSpec(id="job_test1234", target_ip="192.168.1.1", duration=30)
        inspector = ScapyInspector()

        result = inspector.run(spec, stop_event=stop_event)

        assert result.status == JobStatus.CANCELLED
        assert result.packets_captured > 0

    @patch("app.core.inspection.scapy_inspector.SCAPY_AVAILABLE", True)
    @patch("app.core.inspection.scapy_inspector.sniff")
    def test_run_without_stop_event_works_normally(self, mock_sniff):
        """run() sans stop_event fonctionne normalement (backward compat)."""
        mock_sniff.return_value = [MagicMock()]

        spec = JobSpec(id="job_test1234", target_ip="192.168.1.1", duration=5)
        inspector = ScapyInspector()

        result = inspector.run(spec)

        assert result.status == JobStatus.COMPLETED
        assert result.packets_captured == 5
