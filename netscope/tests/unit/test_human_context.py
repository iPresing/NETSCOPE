"""Unit tests for HumanContextProvider.

Tests human-readable context generation for anomalies.
Story 2.5: Contexte Humain Anomalies (FR14, NFR27)
"""

import pytest

from app.core.detection.human_context import (
    HumanContext,
    HumanContextProvider,
    RiskLevel,
    RISK_INDICATOR_MAP,
    PORT_CONTEXTS,
    BLACKLIST_CATEGORY_CONTEXTS,
    PROTOCOL_CONTEXTS,
    VOLUME_CONTEXTS,
    get_human_context_provider,
    reset_human_context_provider,
)
from app.core.analysis.scoring import ScoringEngine


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset HumanContextProvider singleton before and after each test."""
    reset_human_context_provider()
    yield
    reset_human_context_provider()


@pytest.fixture
def provider():
    """Get a fresh HumanContextProvider instance."""
    return HumanContextProvider()


class TestHumanContextInit:
    """Test HumanContextProvider initialization."""

    def test_provider_init(self, provider):
        """Test HumanContextProvider initializes correctly."""
        assert provider is not None
        assert provider._suspicious_ports == ScoringEngine.SUSPICIOUS_PORTS

    def test_get_human_context_provider_singleton(self):
        """Test get_human_context_provider returns singleton."""
        provider1 = get_human_context_provider()
        provider2 = get_human_context_provider()
        assert provider1 is provider2

    def test_reset_human_context_provider(self):
        """Test reset_human_context_provider creates new instance."""
        provider1 = get_human_context_provider()
        reset_human_context_provider()
        provider2 = get_human_context_provider()
        assert provider1 is not provider2


class TestHumanContextDataclass:
    """Test HumanContext dataclass."""

    def test_human_context_creation(self):
        """Test HumanContext can be created with all fields."""
        ctx = HumanContext(
            short_message="Test message",
            explanation="Test explanation",
            risk_level=RiskLevel.HIGH,
            indicator="🔴",
            action_hint="Test action",
            technical_details={"key": "value"},
        )

        assert ctx.short_message == "Test message"
        assert ctx.explanation == "Test explanation"
        assert ctx.risk_level == RiskLevel.HIGH
        assert ctx.indicator == "🔴"
        assert ctx.action_hint == "Test action"
        assert ctx.technical_details == {"key": "value"}

    def test_human_context_to_dict(self):
        """Test HumanContext serializes to dict correctly."""
        ctx = HumanContext(
            short_message="Test message",
            explanation="Test explanation",
            risk_level=RiskLevel.MEDIUM,
            indicator="🟡",
            action_hint="Test action",
            technical_details={"port": 4444},
        )

        result = ctx.to_dict()

        assert result["short_message"] == "Test message"
        assert result["explanation"] == "Test explanation"
        assert result["risk_level"] == "medium"
        assert result["indicator"] == "🟡"
        assert result["action_hint"] == "Test action"
        assert result["technical_details"] == {"port": 4444}

    def test_human_context_defaults(self):
        """Test HumanContext default values."""
        ctx = HumanContext(
            short_message="Test",
            explanation="Explanation",
        )

        assert ctx.risk_level == RiskLevel.INFO
        assert ctx.indicator == "ℹ️"
        assert ctx.action_hint is None
        assert ctx.technical_details == {}


class TestRiskLevelEnum:
    """Test RiskLevel enum."""

    def test_risk_levels(self):
        """Test all risk levels exist."""
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.INFO.value == "info"

    def test_risk_indicator_map(self):
        """Test risk level to indicator mapping."""
        assert RISK_INDICATOR_MAP[RiskLevel.HIGH] == "🔴"
        assert RISK_INDICATOR_MAP[RiskLevel.MEDIUM] == "🟡"
        assert RISK_INDICATOR_MAP[RiskLevel.LOW] == "🟢"
        assert RISK_INDICATOR_MAP[RiskLevel.INFO] == "ℹ️"


class TestPortContext:
    """Test port context generation (AC1: Contexte Ports Suspects)."""

    def test_port_4444_metasploit(self, provider):
        """Test port 4444 gives Metasploit context (AC1)."""
        ctx = provider.get_port_context(4444)

        assert ctx.short_message == "Port Metasploit/Meterpreter"
        assert "Metasploit" in ctx.explanation
        assert "piratage" in ctx.explanation
        assert ctx.risk_level == RiskLevel.HIGH
        assert ctx.indicator == "🔴"
        assert ctx.technical_details["port"] == 4444
        assert ctx.technical_details["is_suspicious"] is True

    def test_port_8080_proxy(self, provider):
        """Test port 8080 gives proxy context (AC1)."""
        ctx = provider.get_port_context(8080)

        assert ctx.short_message == "Proxy HTTP alternatif"
        assert "proxy" in ctx.explanation.lower()
        assert ctx.risk_level == RiskLevel.MEDIUM
        assert ctx.indicator == "🟡"

    def test_port_1337_elite(self, provider):
        """Test port 1337 gives Elite/backdoor context (AC1)."""
        ctx = provider.get_port_context(1337)

        assert "Elite" in ctx.short_message or "Backdoor" in ctx.short_message
        assert "leet" in ctx.explanation.lower() or "1337" in ctx.explanation
        assert ctx.risk_level == RiskLevel.HIGH

    def test_port_6666_irc(self, provider):
        """Test port 6666 gives IRC/botnet context (AC1)."""
        ctx = provider.get_port_context(6666)

        assert "IRC" in ctx.short_message or "Botnet" in ctx.short_message
        assert "botnet" in ctx.explanation.lower() or "irc" in ctx.explanation.lower()
        assert ctx.risk_level == RiskLevel.HIGH

    def test_port_6667_irc(self, provider):
        """Test port 6667 gives IRC context (AC1)."""
        ctx = provider.get_port_context(6667)

        assert "IRC" in ctx.short_message
        assert ctx.risk_level == RiskLevel.MEDIUM

    def test_port_31337_elite_backdoor(self, provider):
        """Test port 31337 gives Elite Backdoor context (AC1)."""
        ctx = provider.get_port_context(31337)

        assert "Elite" in ctx.short_message or "Backdoor" in ctx.short_message
        assert ctx.risk_level == RiskLevel.HIGH

    def test_port_3389_rdp(self, provider):
        """Test port 3389 gives RDP context (AC1)."""
        ctx = provider.get_port_context(3389)

        assert "RDP" in ctx.short_message
        assert "distance" in ctx.explanation.lower() or "rdp" in ctx.explanation.lower()
        assert ctx.risk_level == RiskLevel.HIGH
        assert "VPN" in ctx.action_hint or "Internet" in ctx.action_hint

    def test_port_5900_vnc(self, provider):
        """Test port 5900 gives VNC context (AC1)."""
        ctx = provider.get_port_context(5900)

        assert "VNC" in ctx.short_message
        assert ctx.risk_level == RiskLevel.HIGH

    def test_port_5901_vnc(self, provider):
        """Test port 5901 gives VNC context (AC1)."""
        ctx = provider.get_port_context(5901)

        assert "VNC" in ctx.short_message
        assert ctx.risk_level == RiskLevel.HIGH

    def test_unknown_suspicious_port(self, provider):
        """Test unknown but suspicious port gives generic suspicious context."""
        # Port 5555 is in SUSPICIOUS_PORTS but may not have detailed context
        ctx = provider.get_port_context(5555)

        assert ctx.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM]
        assert ctx.technical_details["is_suspicious"] is True

    def test_standard_port_80(self, provider):
        """Test standard port 80 gives HTTP context."""
        ctx = provider.get_port_context(80)

        assert "HTTP" in ctx.short_message
        assert "standard" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.INFO

    def test_standard_port_443(self, provider):
        """Test standard port 443 gives HTTPS context."""
        ctx = provider.get_port_context(443)

        assert "HTTPS" in ctx.short_message
        assert ctx.risk_level == RiskLevel.INFO

    def test_unknown_port(self, provider):
        """Test unknown port gives generic context."""
        ctx = provider.get_port_context(54321)

        assert "54321" in ctx.short_message
        assert ctx.risk_level == RiskLevel.INFO

    def test_all_suspicious_ports_covered(self, provider):
        """Test all ScoringEngine.SUSPICIOUS_PORTS have context."""
        for port in ScoringEngine.SUSPICIOUS_PORTS:
            ctx = provider.get_port_context(port)
            assert ctx is not None
            # All suspicious ports should have at least LOW risk or higher
            # Port 8443 (Tomcat HTTPS) is LOW as it's generally legitimate
            assert ctx.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
            # Should always be marked as suspicious in technical details
            assert ctx.technical_details.get("is_suspicious") is True


class TestIPContext:
    """Test IP context generation (AC2: Contexte IPs Blacklistees)."""

    def test_ip_malware_context(self, provider):
        """Test IP from malware list gives malware context (AC2)."""
        ctx = provider.get_ip_context(
            ip="45.33.32.156",
            source_file="ips_malware.txt",
        )

        assert "malware" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.HIGH
        assert ctx.technical_details["ip"] == "45.33.32.156"
        assert ctx.technical_details["category"] == "malware"

    def test_ip_c2_context(self, provider):
        """Test IP from C2 list gives C2 context (AC2)."""
        ctx = provider.get_ip_context(
            ip="10.0.0.1",
            source_file="ips_c2.txt",
        )

        assert "C2" in ctx.short_message or "controle" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.HIGH
        assert ctx.technical_details["category"] == "c2"

    def test_ip_tor_context(self, provider):
        """Test IP from Tor list gives Tor context (AC2)."""
        ctx = provider.get_ip_context(
            ip="1.2.3.4",
            source_file="ips_tor_exit.txt",
        )

        assert "Tor" in ctx.short_message
        assert ctx.risk_level == RiskLevel.MEDIUM
        assert ctx.technical_details["category"] == "tor"

    def test_ip_scanner_context(self, provider):
        """Test IP from scanner list gives scanner context (AC2)."""
        ctx = provider.get_ip_context(
            ip="5.6.7.8",
            source_file="ips_scanner.txt",
        )

        assert "Scanner" in ctx.short_message or "Bruteforce" in ctx.short_message
        assert ctx.risk_level == RiskLevel.MEDIUM
        assert ctx.technical_details["category"] == "scanner"

    def test_ip_botnet_context(self, provider):
        """Test IP from botnet list gives botnet context (AC2)."""
        ctx = provider.get_ip_context(
            ip="9.10.11.12",
            source_file="ips_botnet.txt",
        )

        assert "botnet" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.HIGH
        assert ctx.technical_details["category"] == "botnet"

    def test_ip_phishing_context(self, provider):
        """Test IP from phishing list gives phishing context (AC2)."""
        ctx = provider.get_ip_context(
            ip="13.14.15.16",
            source_file="ips_phishing.txt",
        )

        assert "phishing" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.HIGH

    def test_ip_default_context(self, provider):
        """Test IP with unknown source gives default context (AC2)."""
        ctx = provider.get_ip_context(
            ip="1.1.1.1",
            source_file="unknown_list.txt",
        )

        assert "blacklist" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.HIGH
        assert ctx.technical_details["category"] == "default"

    def test_ip_explicit_category(self, provider):
        """Test explicit category overrides source inference."""
        ctx = provider.get_ip_context(
            ip="1.2.3.4",
            source_file="random.txt",
            category="c2",
        )

        assert "C2" in ctx.short_message or "controle" in ctx.short_message.lower()
        assert ctx.technical_details["category"] == "c2"

    def test_ip_context_includes_source_file(self, provider):
        """Test IP context includes source file in technical details."""
        ctx = provider.get_ip_context(
            ip="1.2.3.4",
            source_file="ips_malware.txt",
        )

        assert ctx.technical_details["source_file"] == "ips_malware.txt"


class TestProtocolContext:
    """Test protocol context generation (AC3: Contexte Distribution Protocoles)."""

    def test_icmp_high_warning(self, provider):
        """Test ICMP > 50% gives warning context (AC3)."""
        ctx = provider.get_protocol_context("ICMP", 55.0)

        assert "ICMP" in ctx.short_message
        assert ctx.risk_level == RiskLevel.MEDIUM
        assert ctx.technical_details["protocol"] == "ICMP"
        assert ctx.technical_details["percentage"] == 55.0

    def test_icmp_critical(self, provider):
        """Test ICMP > 90% gives critical context (AC3)."""
        ctx = provider.get_protocol_context("ICMP", 95.0)

        assert "ICMP" in ctx.short_message or "flood" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.HIGH

    def test_icmp_normal(self, provider):
        """Test ICMP < 50% gives normal context."""
        ctx = provider.get_protocol_context("ICMP", 10.0)

        assert "Normal" in ctx.short_message
        assert ctx.risk_level == RiskLevel.INFO

    def test_udp_high(self, provider):
        """Test UDP > 80% gives warning context (AC3)."""
        ctx = provider.get_protocol_context("UDP", 85.0)

        assert "UDP" in ctx.short_message
        assert ctx.risk_level == RiskLevel.MEDIUM

    def test_udp_normal(self, provider):
        """Test UDP < 80% gives normal context."""
        ctx = provider.get_protocol_context("UDP", 30.0)

        assert ctx.risk_level == RiskLevel.INFO

    def test_tcp_low(self, provider):
        """Test TCP < 10% gives warning context (AC3)."""
        ctx = provider.get_protocol_context("TCP", 5.0)

        assert "TCP" in ctx.short_message
        assert ctx.risk_level == RiskLevel.LOW

    def test_tcp_normal(self, provider):
        """Test TCP normal percentage gives normal context."""
        ctx = provider.get_protocol_context("TCP", 70.0)

        assert ctx.risk_level == RiskLevel.INFO

    def test_protocol_case_insensitive(self, provider):
        """Test protocol name is case insensitive."""
        ctx1 = provider.get_protocol_context("icmp", 55.0)
        ctx2 = provider.get_protocol_context("ICMP", 55.0)
        ctx3 = provider.get_protocol_context("Icmp", 55.0)

        assert ctx1.risk_level == ctx2.risk_level == ctx3.risk_level


class TestVolumeContext:
    """Test volume context generation (AC4: Contexte Volume Anormal)."""

    def test_exfiltration_ratio(self, provider):
        """Test ratio > 10:1 gives exfiltration warning (AC4)."""
        ctx = provider.get_volume_context(ratio=15.0, total_packets=1000)

        assert "exfiltration" in ctx.short_message.lower() or "sortant" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.HIGH
        assert ctx.technical_details["ratio"] == 15.0

    def test_high_volume(self, provider):
        """Test high packet count gives volume warning (AC4)."""
        ctx = provider.get_volume_context(ratio=1.0, total_packets=15000)

        assert "intense" in ctx.short_message.lower() or "eleve" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.MEDIUM
        assert ctx.technical_details["total_packets"] == 15000

    def test_external_ip_high_volume(self, provider):
        """Test external IP with high traffic gives warning (AC4)."""
        external_ips = [
            ("8.8.8.8", 100),
            ("1.1.1.1", 200),
        ]
        ctx = provider.get_volume_context(
            ratio=1.0,
            total_packets=500,
            external_ip_volumes=external_ips,
        )

        assert "IP externe" in ctx.short_message
        assert ctx.risk_level == RiskLevel.MEDIUM
        assert "external_ips" in ctx.technical_details

    def test_volume_normal(self, provider):
        """Test normal volume gives info context."""
        ctx = provider.get_volume_context(ratio=1.5, total_packets=500)

        assert "normal" in ctx.short_message.lower()
        assert ctx.risk_level == RiskLevel.INFO

    def test_volume_with_low_external_ips(self, provider):
        """Test external IPs below threshold don't trigger warning."""
        external_ips = [
            ("8.8.8.8", 10),
            ("1.1.1.1", 20),
        ]
        ctx = provider.get_volume_context(
            ratio=1.0,
            total_packets=500,
            external_ip_volumes=external_ips,
        )

        # Should be normal since all below threshold
        assert ctx.risk_level == RiskLevel.INFO


class TestAccessibleTerminology:
    """Test terminology is accessible (AC5: NFR27 Terminologie Accessible)."""

    def test_port_context_no_jargon(self, provider):
        """Test port context uses accessible language (AC5)."""
        ctx = provider.get_port_context(4444)

        # Should use analogies, not pure technical jargon
        assert "cambrioleur" in ctx.explanation or "colis" in ctx.explanation
        # Should have action hint
        assert ctx.action_hint is not None

    def test_ip_context_no_jargon(self, provider):
        """Test IP context uses accessible language (AC5)."""
        ctx = provider.get_ip_context("1.2.3.4", "ips_malware.txt")

        # Should use analogies like "douane" metaphor
        assert "colis" in ctx.explanation or "expediteur" in ctx.explanation
        # Should have action hint
        assert ctx.action_hint is not None

    def test_protocol_context_explains_risk(self, provider):
        """Test protocol context explains risk simply (AC5)."""
        ctx = provider.get_protocol_context("ICMP", 95.0)

        # Should explain what the risk means
        assert "scan" in ctx.explanation.lower() or "flood" in ctx.explanation.lower()

    def test_volume_context_explains_risk(self, provider):
        """Test volume context explains risk simply (AC5)."""
        ctx = provider.get_volume_context(ratio=15.0, total_packets=1000)

        # Should use simple analogy
        assert "documents" in ctx.explanation.lower() or "cachette" in ctx.explanation.lower()

    def test_all_contexts_have_action_hint(self, provider):
        """Test all warning/critical contexts have action hints."""
        # Port
        ctx = provider.get_port_context(4444)
        assert ctx.action_hint is not None

        # IP
        ctx = provider.get_ip_context("1.2.3.4", "ips_malware.txt")
        assert ctx.action_hint is not None

        # Protocol (warning level)
        ctx = provider.get_protocol_context("ICMP", 55.0)
        assert ctx.action_hint is not None

        # Volume (exfiltration)
        ctx = provider.get_volume_context(ratio=15.0, total_packets=1000)
        assert ctx.action_hint is not None


class TestCategoryInference:
    """Test category inference from source file."""

    def test_infer_malware(self, provider):
        """Test malware category inference."""
        assert provider._infer_category_from_source("ips_malware.txt") == "malware"
        assert provider._infer_category_from_source("MALWARE_IPS.txt") == "malware"

    def test_infer_c2(self, provider):
        """Test C2 category inference."""
        assert provider._infer_category_from_source("ips_c2.txt") == "c2"
        assert provider._infer_category_from_source("command_control.txt") == "c2"

    def test_infer_tor(self, provider):
        """Test Tor category inference."""
        assert provider._infer_category_from_source("ips_tor.txt") == "tor"
        assert provider._infer_category_from_source("tor_exit_nodes.txt") == "tor"

    def test_infer_scanner(self, provider):
        """Test scanner category inference."""
        assert provider._infer_category_from_source("ips_scanner.txt") == "scanner"
        assert provider._infer_category_from_source("bruteforce_ips.txt") == "scanner"

    def test_infer_botnet(self, provider):
        """Test botnet category inference."""
        assert provider._infer_category_from_source("ips_botnet.txt") == "botnet"

    def test_infer_phishing(self, provider):
        """Test phishing category inference."""
        assert provider._infer_category_from_source("phishing_urls.txt") == "phishing"

    def test_infer_default(self, provider):
        """Test default category for unknown sources."""
        assert provider._infer_category_from_source("random.txt") == "default"
        assert provider._infer_category_from_source("blacklist.txt") == "default"


class TestThresholdConstants:
    """Test threshold constants are correctly defined."""

    def test_icmp_thresholds(self, provider):
        """Test ICMP thresholds match FourEssentialsAnalyzer."""
        assert provider.ICMP_WARNING_THRESHOLD == 50
        assert provider.ICMP_CRITICAL_THRESHOLD == 90

    def test_udp_threshold(self, provider):
        """Test UDP threshold."""
        assert provider.UDP_HIGH_THRESHOLD == 80

    def test_tcp_threshold(self, provider):
        """Test TCP threshold."""
        assert provider.TCP_LOW_THRESHOLD == 10

    def test_exfiltration_ratio(self, provider):
        """Test exfiltration ratio threshold."""
        assert provider.EXFILTRATION_RATIO == 10

    def test_high_volume_threshold(self, provider):
        """Test high volume threshold."""
        assert provider.HIGH_VOLUME_THRESHOLD == 10000

    def test_external_ip_threshold(self, provider):
        """Test external IP volume threshold."""
        assert provider.EXTERNAL_IP_VOLUME_THRESHOLD == 50


class TestDictionaryCompleteness:
    """Test context dictionaries are complete."""

    def test_port_contexts_complete(self):
        """Test PORT_CONTEXTS has all required ports from AC1."""
        required_ports = [4444, 8080, 1337, 6666, 6667, 31337, 3389, 5900, 5901]
        for port in required_ports:
            assert port in PORT_CONTEXTS, f"Port {port} missing from PORT_CONTEXTS"

    def test_blacklist_categories_complete(self):
        """Test BLACKLIST_CATEGORY_CONTEXTS has all categories."""
        required_categories = ["malware", "c2", "tor", "scanner", "botnet", "phishing", "default"]
        for cat in required_categories:
            assert cat in BLACKLIST_CATEGORY_CONTEXTS, f"Category {cat} missing"

    def test_protocol_contexts_complete(self):
        """Test PROTOCOL_CONTEXTS has all required protocols."""
        required_keys = ["icmp_high", "icmp_critical", "udp_high", "tcp_low"]
        for key in required_keys:
            assert key in PROTOCOL_CONTEXTS, f"Protocol context {key} missing"

    def test_volume_contexts_complete(self):
        """Test VOLUME_CONTEXTS has all required contexts."""
        required_keys = ["exfiltration", "high_volume", "external_ip_high"]
        for key in required_keys:
            assert key in VOLUME_CONTEXTS, f"Volume context {key} missing"
