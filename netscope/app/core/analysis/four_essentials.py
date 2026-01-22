"""Module d'analyse des 4 essentielles pour dashboard NETSCOPE.

Implemente les 4 analyses requises par FR15:
1. Top IPs - IPs les plus actives avec distinction interne/externe
2. Protocoles - Distribution TCP/UDP/ICMP avec alertes disproportion
3. Ports - Ports actifs avec marquage suspects
4. Volume - Statistiques trafic avec detection anomalies

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Reuse ScoringEngine constants for consistency
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.models.capture import CaptureResult, CaptureSummary, PacketInfo
from app.models.anomaly import Anomaly
from app.core.analysis.scoring import ScoringEngine

logger = logging.getLogger(__name__)


class AnalysisStatus(Enum):
    """Status d'une analyse essentielle."""

    CRITICAL = "critical"  # Probleme grave detecte
    WARNING = "warning"    # Attention requise
    NORMAL = "normal"      # Tout va bien


INDICATOR_MAP = {
    AnalysisStatus.CRITICAL: "🔴",
    AnalysisStatus.WARNING: "🟡",
    AnalysisStatus.NORMAL: "🟢",
}


@dataclass
class EssentialAnalysis:
    """Resultat d'une analyse essentielle individuelle."""

    name: str                          # "top_ips", "protocols", "ports", "volume"
    title: str                         # "Top IPs", "Distribution Protocoles", etc.
    status: AnalysisStatus = AnalysisStatus.NORMAL
    indicator: str = "🟢"
    data: dict[str, Any] = field(default_factory=dict)
    message: str = ""                  # Message resume pour la carte
    details: list[str] = field(default_factory=list)  # Details pour expansion

    def to_dict(self) -> dict[str, Any]:
        """Serialisation JSON."""
        return {
            "name": self.name,
            "title": self.title,
            "status": self.status.value,
            "indicator": self.indicator,
            "data": self.data,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class FourEssentialsResult:
    """Resultat complet des 4 analyses essentielles."""

    capture_id: str
    top_ips: EssentialAnalysis = field(default_factory=lambda: EssentialAnalysis(
        name="top_ips", title="Top IPs"
    ))
    protocols: EssentialAnalysis = field(default_factory=lambda: EssentialAnalysis(
        name="protocols", title="Distribution Protocoles"
    ))
    ports: EssentialAnalysis = field(default_factory=lambda: EssentialAnalysis(
        name="ports", title="Ports Utilises"
    ))
    volume: EssentialAnalysis = field(default_factory=lambda: EssentialAnalysis(
        name="volume", title="Volume Donnees"
    ))
    overall_status: AnalysisStatus = AnalysisStatus.NORMAL
    overall_indicator: str = "🟢"

    def to_dict(self) -> dict[str, Any]:
        """Serialisation JSON."""
        return {
            "capture_id": self.capture_id,
            "top_ips": self.top_ips.to_dict(),
            "protocols": self.protocols.to_dict(),
            "ports": self.ports.to_dict(),
            "volume": self.volume.to_dict(),
            "overall_status": self.overall_status.value,
            "overall_indicator": self.overall_indicator,
        }

    def _calculate_overall(self) -> None:
        """Calcule le statut global base sur les 4 analyses."""
        statuses = [
            self.top_ips.status,
            self.protocols.status,
            self.ports.status,
            self.volume.status,
        ]
        if AnalysisStatus.CRITICAL in statuses:
            self.overall_status = AnalysisStatus.CRITICAL
        elif AnalysisStatus.WARNING in statuses:
            self.overall_status = AnalysisStatus.WARNING
        else:
            self.overall_status = AnalysisStatus.NORMAL
        self.overall_indicator = INDICATOR_MAP[self.overall_status]


class FourEssentialsAnalyzer:
    """Analyseur des 4 essentielles pour dashboard.

    Usage:
        analyzer = FourEssentialsAnalyzer()
        result = analyzer.analyze(capture_result, anomalies)
    """

    # Constantes ports connus pour contexte
    PORT_DESCRIPTIONS: dict[int, str] = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        5432: "PostgreSQL",
        # Ports suspects (aligned with ScoringEngine.SUSPICIOUS_PORTS)
        1337: "⚠️ Elite/Backdoor",
        3389: "⚠️ RDP (suspect si externe)",
        4443: "⚠️ HTTPS Alt",
        4444: "⚠️ Metasploit/Meterpreter",
        5555: "⚠️ Android ADB",
        5900: "⚠️ VNC",
        5901: "⚠️ VNC",
        6666: "⚠️ IRC/Backdoor",
        6667: "⚠️ IRC",
        8080: "⚠️ HTTP Alt/Proxy",
        8443: "⚠️ HTTPS Alt",
        12345: "⚠️ NetBus Trojan",
        27374: "⚠️ SubSeven Trojan",
        31337: "⚠️ Elite Backdoor",
    }

    # Seuils pour alertes
    ICMP_WARNING_THRESHOLD = 50    # % ICMP > 50% = suspect
    ICMP_CRITICAL_THRESHOLD = 90   # % ICMP > 90% = tres suspect
    EXFILTRATION_RATIO = 10        # ratio out/in > 10 = possible exfiltration
    HIGH_VOLUME_THRESHOLD = 10000  # paquets
    EXTERNAL_IP_VOLUME_THRESHOLD = 50  # paquets externes > 50 = warning

    def __init__(self) -> None:
        """Initialise l'analyseur."""
        # Reutiliser les constantes de ScoringEngine
        self._suspicious_ports = ScoringEngine.SUSPICIOUS_PORTS
        self._private_prefixes = ScoringEngine.PRIVATE_IP_PREFIXES
        logger.debug("FourEssentialsAnalyzer initialized")

    def analyze(
        self,
        capture_result: CaptureResult,
        anomalies: list[Anomaly] | None = None,
    ) -> FourEssentialsResult:
        """Analyse complete des 4 essentielles.

        Args:
            capture_result: Resultat de capture avec packets et summary
            anomalies: Liste d'anomalies detectees (optionnel)

        Returns:
            FourEssentialsResult avec les 4 analyses
        """
        anomalies = anomalies or []
        result = FourEssentialsResult(capture_id=capture_result.session.id)

        # Analyse 1: Top IPs
        result.top_ips = self._analyze_top_ips(
            capture_result.packets,
            capture_result.summary,
            anomalies,
        )

        # Analyse 2: Distribution Protocoles
        result.protocols = self._analyze_protocols(
            capture_result.packets,
            capture_result.summary,
        )

        # Analyse 3: Ports Utilises
        result.ports = self._analyze_ports(
            capture_result.packets,
            capture_result.summary,
            anomalies,
        )

        # Analyse 4: Volume Donnees
        result.volume = self._analyze_volume(
            capture_result.packets,
            capture_result.summary,
        )

        # Calculer statut global
        result._calculate_overall()

        logger.info(
            f"Four essentials analysis complete "
            f"(capture={capture_result.session.id}, overall={result.overall_status.value})"
        )

        return result

    def _analyze_top_ips(
        self,
        packets: list[PacketInfo],
        summary: CaptureSummary,
        anomalies: list[Anomaly],
    ) -> EssentialAnalysis:
        """Analyse Top IPs."""
        analysis = EssentialAnalysis(name="top_ips", title="Top IPs")

        # Extraire IPs blacklistees des anomalies
        blacklisted_ips: set[str] = set()
        for a in anomalies:
            if a.match.match_type.value == "ip":
                blacklisted_ips.add(a.match.matched_value)

        # Enrichir top_ips
        enriched_ips = []
        has_critical = False
        has_warning = False

        for ip, count in summary.top_ips[:10]:  # Top 10
            is_external = self._is_external_ip(ip)
            is_blacklisted = ip in blacklisted_ips

            if is_blacklisted:
                has_critical = True
            elif is_external and count > self.EXTERNAL_IP_VOLUME_THRESHOLD:
                has_warning = True

            enriched_ips.append({
                "ip": ip,
                "count": count,
                "is_external": is_external,
                "is_blacklisted": is_blacklisted,
                "type": "externe" if is_external else "interne",
            })

        # Calculer status
        if has_critical:
            analysis.status = AnalysisStatus.CRITICAL
            analysis.message = f"{len(blacklisted_ips)} IP(s) blacklistee(s) detectee(s)"
        elif has_warning:
            analysis.status = AnalysisStatus.WARNING
            external_count = sum(1 for ip in enriched_ips if ip["is_external"])
            analysis.message = f"{external_count} IP(s) externe(s) actives"
        else:
            analysis.status = AnalysisStatus.NORMAL
            analysis.message = f"{len(enriched_ips)} IPs actives, aucune suspecte"

        analysis.indicator = INDICATOR_MAP[analysis.status]
        analysis.data = {
            "ips": enriched_ips,
            "total_unique": summary.unique_ips,
            "blacklisted_count": len(blacklisted_ips),
        }

        return analysis

    def _analyze_protocols(
        self,
        packets: list[PacketInfo],
        summary: CaptureSummary,
    ) -> EssentialAnalysis:
        """Analyse Distribution Protocoles."""
        analysis = EssentialAnalysis(name="protocols", title="Distribution Protocoles")

        total = sum(summary.protocols.values()) or 1
        distribution = {}

        for proto, count in summary.protocols.items():
            pct = round((count / total) * 100, 1)
            distribution[proto] = {
                "count": count,
                "percentage": pct,
            }

        # Verifier disproportion
        icmp_pct = distribution.get("ICMP", {}).get("percentage", 0)

        if icmp_pct >= self.ICMP_CRITICAL_THRESHOLD:
            analysis.status = AnalysisStatus.CRITICAL
            analysis.message = f"ICMP anormal: {icmp_pct}% - Possible flood/scan"
        elif icmp_pct >= self.ICMP_WARNING_THRESHOLD:
            analysis.status = AnalysisStatus.WARNING
            analysis.message = f"ICMP eleve: {icmp_pct}% - A surveiller"
        else:
            analysis.status = AnalysisStatus.NORMAL
            tcp_pct = distribution.get("TCP", {}).get("percentage", 0)
            analysis.message = f"TCP {tcp_pct}% - Distribution normale"

        analysis.indicator = INDICATOR_MAP[analysis.status]
        analysis.data = {
            "distribution": distribution,
            "total_packets": total,
            "bytes_per_protocol": summary.bytes_per_protocol,
        }

        return analysis

    def _analyze_ports(
        self,
        packets: list[PacketInfo],
        summary: CaptureSummary,
        anomalies: list[Anomaly],
    ) -> EssentialAnalysis:
        """Analyse Ports Utilises."""
        analysis = EssentialAnalysis(name="ports", title="Ports Utilises")

        # Enrichir top_ports
        enriched_ports = []
        suspicious_found = []

        for port, count in summary.top_ports[:15]:  # Top 15
            is_suspicious = port in self._suspicious_ports
            description = self.PORT_DESCRIPTIONS.get(port, "Inconnu")

            if is_suspicious:
                suspicious_found.append(port)

            enriched_ports.append({
                "port": port,
                "count": count,
                "is_suspicious": is_suspicious,
                "description": description,
            })

        # Calculer status
        if suspicious_found:
            analysis.status = AnalysisStatus.CRITICAL
            analysis.message = f"Ports suspects actifs: {', '.join(map(str, suspicious_found[:3]))}"
            analysis.details = [
                f"Port {p}: {self.PORT_DESCRIPTIONS.get(p, 'Suspect')}"
                for p in suspicious_found
            ]
        else:
            analysis.status = AnalysisStatus.NORMAL
            top_port = summary.top_ports[0][0] if summary.top_ports else 0
            analysis.message = f"Top port: {top_port} - Aucun suspect"

        analysis.indicator = INDICATOR_MAP[analysis.status]
        analysis.data = {
            "ports": enriched_ports,
            "total_unique": summary.unique_ports,
            "suspicious_count": len(suspicious_found),
            "suspicious_ports": suspicious_found,
        }

        return analysis

    def _analyze_volume(
        self,
        packets: list[PacketInfo],
        summary: CaptureSummary,
    ) -> EssentialAnalysis:
        """Analyse Volume Donnees."""
        analysis = EssentialAnalysis(name="volume", title="Volume Donnees")

        # Estimer entrant/sortant (heuristique: IP RFC1918 = interne)
        bytes_in = 0
        bytes_out = 0

        for packet in packets:
            is_src_internal = self._is_internal_ip(packet.ip_src)
            is_dst_internal = self._is_internal_ip(packet.ip_dst)

            if is_src_internal and not is_dst_internal:
                # Sortant: interne -> externe
                bytes_out += packet.length
            elif not is_src_internal and is_dst_internal:
                # Entrant: externe -> interne
                bytes_in += packet.length
            else:
                # Local ou indetermine
                bytes_in += packet.length // 2
                bytes_out += packet.length // 2

        # Calculer ratio
        ratio_str = "N/A"
        ratio = 0.0
        if bytes_in > 0:
            ratio = bytes_out / bytes_in
            ratio_str = f"{ratio:.1f}:1"

        # Verifier anomalies
        if ratio > self.EXFILTRATION_RATIO:
            analysis.status = AnalysisStatus.WARNING
            analysis.message = f"Ratio sortant eleve ({ratio_str}) - Possible exfiltration"
        elif summary.total_packets > self.HIGH_VOLUME_THRESHOLD:
            analysis.status = AnalysisStatus.WARNING
            analysis.message = f"Volume eleve: {summary.total_packets:,} paquets"
        else:
            analysis.status = AnalysisStatus.NORMAL
            analysis.message = f"{summary.total_packets:,} paquets captures"

        analysis.indicator = INDICATOR_MAP[analysis.status]
        analysis.data = {
            "total_packets": summary.total_packets,
            "total_bytes": summary.total_bytes,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "ratio": ratio_str,
            "duration_seconds": summary.duration_actual,
            "packets_per_second": round(
                summary.total_packets / summary.duration_actual, 1
            ) if summary.duration_actual > 0 else 0,
        }

        return analysis

    def _is_external_ip(self, ip: str) -> bool:
        """Verifie si une IP est externe (hors RFC1918)."""
        if not ip:
            return False
        return not any(ip.startswith(prefix) for prefix in self._private_prefixes)

    def _is_internal_ip(self, ip: str) -> bool:
        """Verifie si une IP est interne (RFC1918)."""
        return not self._is_external_ip(ip)


# Singleton instance
_analyzer: FourEssentialsAnalyzer | None = None


def get_four_essentials_analyzer() -> FourEssentialsAnalyzer:
    """Retourne l'instance singleton de l'analyseur.

    Returns:
        Instance FourEssentialsAnalyzer
    """
    global _analyzer
    if _analyzer is None:
        _analyzer = FourEssentialsAnalyzer()
    return _analyzer


def reset_four_essentials_analyzer() -> None:
    """Reset le singleton (pour tests)."""
    global _analyzer
    _analyzer = None
