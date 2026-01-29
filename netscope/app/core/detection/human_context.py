"""Module de generation de contexte humain pour anomalies NETSCOPE.

Fournit des explications accessibles pour les utilisateurs non-experts
en securite reseau, utilisant l'analogie "douane" definie dans le PRD.

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Reuse constants from ScoringEngine and FourEssentialsAnalyzer
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.core.analysis.scoring import ScoringEngine
from app.core.analysis.four_essentials import FourEssentialsAnalyzer

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Niveau de risque pour contexte humain."""

    HIGH = "high"       # Risque eleve - Action recommandee
    MEDIUM = "medium"   # Risque modere - A surveiller
    LOW = "low"         # Risque faible - Informatif
    INFO = "info"       # Information contextuelle


RISK_INDICATOR_MAP: dict[RiskLevel, str] = {
    RiskLevel.HIGH: "🔴",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.LOW: "🟢",
    RiskLevel.INFO: "ℹ️",
}


@dataclass
class HumanContext:
    """Contexte humain pour une anomalie.

    Attributes:
        short_message: Message court (1-2 phrases) pour affichage direct
        explanation: Explication detaillee du risque
        risk_level: Niveau de risque (high/medium/low/info)
        indicator: Emoji indicateur
        action_hint: Suggestion d'action (optionnel)
        technical_details: Details techniques pour utilisateurs avances
    """

    short_message: str
    explanation: str
    risk_level: RiskLevel = RiskLevel.INFO
    indicator: str = "ℹ️"
    action_hint: str | None = None
    technical_details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialisation JSON."""
        return {
            "short_message": self.short_message,
            "explanation": self.explanation,
            "risk_level": self.risk_level.value,
            "indicator": self.indicator,
            "action_hint": self.action_hint,
            "technical_details": self.technical_details,
        }


# =============================================================================
# PORT CONTEXTS - Descriptions accessibles pour ports suspects
# =============================================================================

PORT_CONTEXTS: dict[int, dict[str, Any]] = {
    # Ports suspects critiques (Metasploit, Backdoors)
    4444: {
        "short": "Port Metasploit/Meterpreter",
        "explanation": (
            "Ce port est tres souvent utilise par l'outil de piratage Metasploit. "
            "C'est comme trouver un passe-partout de cambrioleur dans un colis - "
            "la presence de trafic sur ce port est tres suspecte."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Investiguer immediatement la source et bloquer si non legitime",
    },
    1337: {
        "short": "Port 'Elite' / Backdoor",
        "explanation": (
            "Port historiquement associe aux hackers ('leet' = 1337). "
            "Souvent utilise par des programmes malveillants qui veulent "
            "etablir une porte derobee sur votre reseau."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Verifier quel programme utilise ce port et bloquer si suspect",
    },
    31337: {
        "short": "Elite Backdoor historique",
        "explanation": (
            "Ce port est le 'grand frere' du 1337, utilise par des backdoors "
            "tres anciennes comme Back Orifice. Sa presence est anormale "
            "sur un reseau moderne."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Bloquer ce port et scanner les machines concernees",
    },
    6666: {
        "short": "IRC / Botnet potentiel",
        "explanation": (
            "Port souvent utilise par IRC (chat) mais aussi par des botnets "
            "pour communiquer avec leur centre de controle. C'est comme "
            "un talkie-walkie de malfaiteur."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Verifier si IRC est legitime, sinon bloquer",
    },
    6667: {
        "short": "IRC standard",
        "explanation": (
            "Port IRC classique. Peut etre legitime (chat) mais aussi "
            "utilise par des botnets. A surveiller si vous n'utilisez "
            "pas de service IRC."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Autoriser uniquement si IRC est utilise legitimement",
    },
    12345: {
        "short": "NetBus Trojan",
        "explanation": (
            "Port historique du trojan NetBus des annees 90-2000. "
            "Sa presence aujourd'hui est tres suspecte - c'est un "
            "indicateur classique de compromission."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Scanner la machine concernee pour malware",
    },
    27374: {
        "short": "SubSeven Trojan",
        "explanation": (
            "Port du celebre trojan SubSeven. Comme NetBus, c'est un "
            "indicateur historique de compromission. Aucun logiciel "
            "legitime n'utilise ce port."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Scanner la machine et analyser les connexions",
    },

    # Ports suspects moderes (Services detournables)
    8080: {
        "short": "Proxy HTTP alternatif",
        "explanation": (
            "Port alternatif pour HTTP, souvent utilise par des proxys. "
            "Legitime pour des serveurs web alternatifs, mais peut aussi "
            "etre utilise pour contourner des filtres reseau."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Verifier que le service est autorise sur votre reseau",
    },
    4443: {
        "short": "HTTPS alternatif",
        "explanation": (
            "Port alternatif pour HTTPS. Peut etre legitime pour certains "
            "services, mais aussi utilise pour eviter la detection. "
            "Verifier la legitimite du service."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Confirmer que le service HTTPS sur ce port est autorise",
    },
    8443: {
        "short": "HTTPS alternatif (Tomcat)",
        "explanation": (
            "Port HTTPS alternatif, souvent utilise par Tomcat ou des "
            "applications Java. Generalement legitime mais a verifier."
        ),
        "risk": RiskLevel.LOW,
        "action": "Verifier le service associe",
    },
    3389: {
        "short": "RDP - Bureau a distance Windows",
        "explanation": (
            "Port du Bureau a distance Windows (RDP). Tres risque si "
            "accessible depuis Internet - c'est une cible privilegiee "
            "des attaquants pour prendre le controle de machines."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Ne JAMAIS exposer RDP sur Internet sans VPN",
    },
    5900: {
        "short": "VNC - Bureau a distance",
        "explanation": (
            "Port VNC pour l'acces bureau a distance. Comme RDP, "
            "tres risque si expose sur Internet. Souvent cible "
            "par des scanners automatiques."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Restreindre l'acces VNC au reseau local uniquement",
    },
    5901: {
        "short": "VNC - Ecran 1",
        "explanation": (
            "Port VNC secondaire (ecran 1). Memes risques que le "
            "port 5900 - acces bureau a distance a proteger."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Restreindre l'acces au reseau local",
    },
    5555: {
        "short": "Android ADB",
        "explanation": (
            "Port Android Debug Bridge. Permet de controler un "
            "appareil Android a distance. Dangereux si expose - "
            "permet l'installation d'applications."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Desactiver ADB reseau si non necessaire",
    },
}


# =============================================================================
# BLACKLIST CATEGORY CONTEXTS
# =============================================================================

BLACKLIST_CATEGORY_CONTEXTS: dict[str, dict[str, Any]] = {
    "malware": {
        "short": "IP connue pour distribution de malware",
        "explanation": (
            "Cette adresse IP est repertoriee comme distribuant des "
            "logiciels malveillants. C'est comme recevoir un colis "
            "d'un expediteur connu pour envoyer des produits dangereux."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Bloquer immediatement et analyser les machines ayant communique",
    },
    "c2": {
        "short": "Serveur de controle (C2)",
        "explanation": (
            "Cette IP est un serveur de 'Command & Control' - un centre "
            "de controle pour logiciels malveillants. Si votre machine "
            "communique avec cette IP, elle pourrait etre compromise."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Isoler les machines concernees et lancer un scan antimalware",
    },
    "tor": {
        "short": "Noeud de sortie Tor",
        "explanation": (
            "Cette IP est un noeud de sortie du reseau Tor. Le trafic "
            "peut etre legitime (anonymisation) ou malveillant "
            "(attaques anonymisees)."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Surveiller le type de trafic et bloquer si suspect",
    },
    "scanner": {
        "short": "Scanner/Bruteforce connu",
        "explanation": (
            "Cette IP est connue pour scanner les reseaux ou tenter "
            "des attaques par force brute. C'est un 'rodeur' qui "
            "cherche des portes ouvertes."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Bloquer et verifier qu'aucun acces n'a reussi",
    },
    "botnet": {
        "short": "IP de botnet",
        "explanation": (
            "Cette IP fait partie d'un reseau de machines zombies "
            "(botnet). La communication avec cette IP indique une "
            "possible infection."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Scanner la machine source pour malware",
    },
    "phishing": {
        "short": "IP associee au phishing",
        "explanation": (
            "Cette IP heberge ou a heberge des sites de phishing - "
            "des faux sites qui volent vos identifiants."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Verifier si des identifiants ont ete saisis",
    },
    "default": {
        "short": "IP blacklistee",
        "explanation": (
            "Cette IP figure sur une liste noire de securite. "
            "Elle a ete signalee pour activite suspecte ou malveillante."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Investiguer la nature de la communication",
    },
}


# =============================================================================
# PROTOCOL DISTRIBUTION CONTEXTS
# =============================================================================

PROTOCOL_CONTEXTS: dict[str, dict[str, Any]] = {
    "icmp_high": {
        "short": "Trafic ICMP anormalement eleve",
        "explanation": (
            "Le protocole ICMP (ping) represente une part inhabituelle "
            "du trafic. Cela peut indiquer un scan reseau (quelqu'un "
            "qui 'frappe a toutes les portes') ou une attaque par flood."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Identifier la source du trafic ICMP et bloquer si anormal",
    },
    "icmp_critical": {
        "short": "Possible flood/scan ICMP",
        "explanation": (
            "Le trafic ICMP represente plus de 90% du total - c'est "
            "tres anormal. Probable scan reseau massif ou attaque "
            "de type 'ping flood'."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Bloquer le trafic ICMP excessif immediatement",
    },
    "udp_high": {
        "short": "Proportion UDP elevee",
        "explanation": (
            "Le trafic UDP est anormalement eleve. Peut etre legitime "
            "(DNS, streaming, jeux) mais aussi signe d'attaque DDoS "
            "ou de tunneling."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Verifier les services UDP actifs et leur legitimite",
    },
    "tcp_low": {
        "short": "Tres peu de trafic TCP",
        "explanation": (
            "Le trafic TCP est anormalement bas. La plupart des services "
            "web utilisent TCP - une absence peut indiquer des problemes "
            "de connectivite ou un trafic detourne."
        ),
        "risk": RiskLevel.LOW,
        "action": "Verifier la connectivite Internet et les services actifs",
    },
}


# =============================================================================
# VOLUME CONTEXTS
# =============================================================================

VOLUME_CONTEXTS: dict[str, dict[str, Any]] = {
    "exfiltration": {
        "short": "Volume sortant eleve - Possible exfiltration",
        "explanation": (
            "Le volume de donnees sortantes est tres superieur aux donnees "
            "entrantes (ratio >10:1). Cela peut indiquer une exfiltration "
            "de donnees - comme si quelqu'un faisait sortir des documents "
            "en cachette."
        ),
        "risk": RiskLevel.HIGH,
        "action": "Identifier les machines qui envoient et verifier les destinations",
    },
    "high_volume": {
        "short": "Activite reseau intense",
        "explanation": (
            "Le volume de paquets captures est tres eleve. Peut etre normal "
            "(telechargement, streaming) ou anormal (attaque, malware actif)."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Identifier les sources principales du trafic",
    },
    "external_ip_high": {
        "short": "IP externe avec trafic important",
        "explanation": (
            "Une IP externe genere un volume de trafic significatif. "
            "A surveiller si cette IP n'est pas un service connu "
            "(Google, Microsoft, etc.)."
        ),
        "risk": RiskLevel.MEDIUM,
        "action": "Verifier si cette IP correspond a un service legitime",
    },
}


# =============================================================================
# STANDARD PORTS (for context on non-suspicious ports)
# =============================================================================

STANDARD_PORT_DESCRIPTIONS: dict[int, str] = {
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
}


class HumanContextProvider:
    """Generateur de contexte humain pour anomalies.

    Fournit des explications accessibles aux utilisateurs non-experts
    pour les differents types d'anomalies detectees.

    Usage:
        provider = HumanContextProvider()
        context = provider.get_port_context(4444)
    """

    # Seuils importes de FourEssentialsAnalyzer pour coherence (Code Review M2 fix)
    ICMP_WARNING_THRESHOLD = FourEssentialsAnalyzer.ICMP_WARNING_THRESHOLD
    ICMP_CRITICAL_THRESHOLD = FourEssentialsAnalyzer.ICMP_CRITICAL_THRESHOLD
    UDP_HIGH_THRESHOLD = 80  # Not in FourEssentialsAnalyzer, local definition
    TCP_LOW_THRESHOLD = 10   # Not in FourEssentialsAnalyzer, local definition
    EXFILTRATION_RATIO = FourEssentialsAnalyzer.EXFILTRATION_RATIO
    HIGH_VOLUME_THRESHOLD = FourEssentialsAnalyzer.HIGH_VOLUME_THRESHOLD
    EXTERNAL_IP_VOLUME_THRESHOLD = FourEssentialsAnalyzer.EXTERNAL_IP_VOLUME_THRESHOLD

    def __init__(self) -> None:
        """Initialise le provider."""
        # Reutiliser les ports suspects de ScoringEngine
        self._suspicious_ports = ScoringEngine.SUSPICIOUS_PORTS
        logger.debug("HumanContextProvider initialized")

    def get_port_context(self, port: int) -> HumanContext:
        """Genere le contexte humain pour un port.

        Args:
            port: Numero de port

        Returns:
            HumanContext avec explication accessible
        """
        logger.debug(f"Port context requested (port={port})")

        if port in PORT_CONTEXTS:
            ctx = PORT_CONTEXTS[port]
            return HumanContext(
                short_message=ctx["short"],
                explanation=ctx["explanation"],
                risk_level=ctx["risk"],
                indicator=RISK_INDICATOR_MAP[ctx["risk"]],
                action_hint=ctx.get("action"),
                technical_details={"port": port, "is_suspicious": port in self._suspicious_ports},
            )

        # Port inconnu mais suspect
        if port in self._suspicious_ports:
            return HumanContext(
                short_message=f"Port {port} suspect",
                explanation=(
                    f"Le port {port} est marque comme suspect dans notre base "
                    "de donnees. Verifiez quel service l'utilise."
                ),
                risk_level=RiskLevel.MEDIUM,
                indicator=RISK_INDICATOR_MAP[RiskLevel.MEDIUM],
                action_hint="Identifier le service utilisant ce port",
                technical_details={"port": port, "is_suspicious": True},
            )

        # Port standard connu
        if port in STANDARD_PORT_DESCRIPTIONS:
            return HumanContext(
                short_message=f"{STANDARD_PORT_DESCRIPTIONS[port]} (port standard)",
                explanation=f"Port {port} utilise par {STANDARD_PORT_DESCRIPTIONS[port]} - service courant.",
                risk_level=RiskLevel.INFO,
                indicator=RISK_INDICATOR_MAP[RiskLevel.INFO],
                technical_details={"port": port, "service": STANDARD_PORT_DESCRIPTIONS[port]},
            )

        # Port inconnu
        return HumanContext(
            short_message=f"Port {port}",
            explanation=f"Port {port} - service non identifie.",
            risk_level=RiskLevel.INFO,
            indicator=RISK_INDICATOR_MAP[RiskLevel.INFO],
            technical_details={"port": port},
        )

    def get_ip_context(
        self,
        ip: str,
        source_file: str,
        category: str | None = None,
    ) -> HumanContext:
        """Genere le contexte humain pour une IP blacklistee.

        Args:
            ip: Adresse IP
            source_file: Fichier source de la blacklist
            category: Categorie optionnelle (malware, c2, tor, etc.)

        Returns:
            HumanContext avec explication accessible
        """
        logger.debug(f"IP context requested (ip={ip}, source_file={source_file}, category={category})")

        # Deduire categorie du nom de fichier si non fournie
        if not category:
            category = self._infer_category_from_source(source_file)

        ctx = BLACKLIST_CATEGORY_CONTEXTS.get(
            category,
            BLACKLIST_CATEGORY_CONTEXTS["default"],
        )

        return HumanContext(
            short_message=ctx["short"],
            explanation=ctx["explanation"],
            risk_level=ctx["risk"],
            indicator=RISK_INDICATOR_MAP[ctx["risk"]],
            action_hint=ctx.get("action"),
            technical_details={
                "ip": ip,
                "source_file": source_file,
                "category": category,
            },
        )

    def get_domain_context(
        self,
        domain: str,
        source_file: str,
        category: str | None = None,
    ) -> HumanContext:
        """Genere le contexte humain pour un domaine blackliste.

        Story 2.2 AC2: Domain blacklist detection with human context.

        Args:
            domain: Nom de domaine
            source_file: Fichier source de la blacklist
            category: Categorie optionnelle (phishing, malware, c2, etc.)

        Returns:
            HumanContext avec explication accessible
        """
        logger.debug(f"Domain context requested (domain={domain}, source_file={source_file})")

        # Deduire categorie du nom de fichier si non fournie
        if not category:
            category = self._infer_category_from_source(source_file)

        ctx = BLACKLIST_CATEGORY_CONTEXTS.get(
            category,
            BLACKLIST_CATEGORY_CONTEXTS["default"],
        )

        # Adapter le message pour les domaines
        short_msg = ctx["short"].replace("Adresse IP", "Domaine").replace("IP", "Domaine")
        explanation = ctx["explanation"].replace("adresse IP", "domaine").replace("IP", "domaine")

        return HumanContext(
            short_message=short_msg,
            explanation=explanation,
            risk_level=ctx["risk"],
            indicator=RISK_INDICATOR_MAP[ctx["risk"]],
            action_hint=ctx.get("action"),
            technical_details={
                "domain": domain,
                "source_file": source_file,
                "category": category,
            },
        )

    def get_term_context(
        self,
        term: str,
        context_snippet: str | None = None,
    ) -> HumanContext:
        """Genere le contexte humain pour un terme suspect detecte.

        Story 2.2 AC3: Term detection with human context.

        Args:
            term: Terme suspect detecte
            context_snippet: Extrait du payload contenant le terme

        Returns:
            HumanContext avec explication accessible
        """
        logger.debug(f"Term context requested (term={term})")

        return HumanContext(
            short_message="Terme suspect detecte",
            explanation=(
                f"Le terme '{term}' a ete detecte dans le trafic reseau. "
                "Ce terme peut indiquer une activite suspecte comme un reverse shell, "
                "une tentative d'intrusion, ou l'execution de commandes malveillantes."
            ),
            risk_level=RiskLevel.MEDIUM,
            indicator=RISK_INDICATOR_MAP[RiskLevel.MEDIUM],
            action_hint="Analysez le contexte complet du paquet pour determiner si l'activite est legitime.",
            technical_details={
                "term": term,
                "context_snippet": context_snippet[:100] if context_snippet else None,
            },
        )

    def get_protocol_context(
        self,
        protocol: str,
        percentage: float,
    ) -> HumanContext:
        """Genere le contexte humain pour une distribution protocole anormale.

        Args:
            protocol: Nom du protocole (TCP, UDP, ICMP)
            percentage: Pourcentage du protocole dans le trafic

        Returns:
            HumanContext avec explication si anormal
        """
        logger.debug(f"Protocol context requested (protocol={protocol}, percentage={percentage})")

        protocol = protocol.upper()

        if protocol == "ICMP":
            if percentage >= self.ICMP_CRITICAL_THRESHOLD:
                ctx = PROTOCOL_CONTEXTS["icmp_critical"]
            elif percentage >= self.ICMP_WARNING_THRESHOLD:
                ctx = PROTOCOL_CONTEXTS["icmp_high"]
            else:
                return HumanContext(
                    short_message=f"ICMP {percentage:.1f}% - Normal",
                    explanation="Proportion ICMP dans les limites normales.",
                    risk_level=RiskLevel.INFO,
                    indicator=RISK_INDICATOR_MAP[RiskLevel.INFO],
                    technical_details={"protocol": protocol, "percentage": percentage},
                )
        elif protocol == "UDP" and percentage >= self.UDP_HIGH_THRESHOLD:
            ctx = PROTOCOL_CONTEXTS["udp_high"]
        elif protocol == "TCP" and percentage < self.TCP_LOW_THRESHOLD:
            ctx = PROTOCOL_CONTEXTS["tcp_low"]
        else:
            return HumanContext(
                short_message=f"{protocol} {percentage:.1f}%",
                explanation=f"Proportion {protocol} normale.",
                risk_level=RiskLevel.INFO,
                indicator=RISK_INDICATOR_MAP[RiskLevel.INFO],
                technical_details={"protocol": protocol, "percentage": percentage},
            )

        return HumanContext(
            short_message=ctx["short"],
            explanation=ctx["explanation"],
            risk_level=ctx["risk"],
            indicator=RISK_INDICATOR_MAP[ctx["risk"]],
            action_hint=ctx.get("action"),
            technical_details={"protocol": protocol, "percentage": percentage},
        )

    def get_volume_context(
        self,
        ratio: float,
        total_packets: int,
        external_ip_volumes: list[tuple[str, int]] | None = None,
    ) -> HumanContext:
        """Genere le contexte humain pour un volume de trafic anormal.

        Args:
            ratio: Ratio sortant/entrant
            total_packets: Total de paquets captures
            external_ip_volumes: Liste de tuples (ip, count) pour IPs externes

        Returns:
            HumanContext avec explication si anormal
        """
        logger.debug(f"Volume context requested (ratio={ratio}, total_packets={total_packets})")

        # Verifier ratio exfiltration
        if ratio > self.EXFILTRATION_RATIO:
            ctx = VOLUME_CONTEXTS["exfiltration"]
            return HumanContext(
                short_message=ctx["short"],
                explanation=ctx["explanation"],
                risk_level=ctx["risk"],
                indicator=RISK_INDICATOR_MAP[ctx["risk"]],
                action_hint=ctx.get("action"),
                technical_details={
                    "ratio": ratio,
                    "total_packets": total_packets,
                },
            )

        # Verifier volume eleve
        if total_packets > self.HIGH_VOLUME_THRESHOLD:
            ctx = VOLUME_CONTEXTS["high_volume"]
            return HumanContext(
                short_message=ctx["short"],
                explanation=ctx["explanation"],
                risk_level=ctx["risk"],
                indicator=RISK_INDICATOR_MAP[ctx["risk"]],
                action_hint=ctx.get("action"),
                technical_details={
                    "total_packets": total_packets,
                    "threshold": self.HIGH_VOLUME_THRESHOLD,
                },
            )

        # Verifier IPs externes volumineuses
        if external_ip_volumes:
            high_volume_externals = [
                (ip, count) for ip, count in external_ip_volumes
                if count > self.EXTERNAL_IP_VOLUME_THRESHOLD
            ]
            if high_volume_externals:
                ctx = VOLUME_CONTEXTS["external_ip_high"]
                return HumanContext(
                    short_message=ctx["short"],
                    explanation=ctx["explanation"],
                    risk_level=ctx["risk"],
                    indicator=RISK_INDICATOR_MAP[ctx["risk"]],
                    action_hint=ctx.get("action"),
                    technical_details={
                        "external_ips": high_volume_externals,
                    },
                )

        # Volume normal
        return HumanContext(
            short_message=f"{total_packets:,} paquets - Volume normal",
            explanation="Le volume de trafic est dans les limites normales.",
            risk_level=RiskLevel.INFO,
            indicator=RISK_INDICATOR_MAP[RiskLevel.INFO],
            technical_details={"total_packets": total_packets, "ratio": ratio},
        )

    def _infer_category_from_source(self, source_file: str) -> str:
        """Deduit la categorie de menace du nom de fichier.

        Args:
            source_file: Nom du fichier blacklist

        Returns:
            Categorie deduite
        """
        source_lower = source_file.lower()

        if "malware" in source_lower:
            return "malware"
        elif "c2" in source_lower or "command" in source_lower:
            return "c2"
        elif "tor" in source_lower:
            return "tor"
        elif "scanner" in source_lower or "bruteforce" in source_lower:
            return "scanner"
        elif "botnet" in source_lower:
            return "botnet"
        elif "phishing" in source_lower:
            return "phishing"

        return "default"


# Singleton instance
_provider: HumanContextProvider | None = None


def get_human_context_provider() -> HumanContextProvider:
    """Retourne l'instance singleton du provider.

    Returns:
        Instance HumanContextProvider
    """
    global _provider
    if _provider is None:
        _provider = HumanContextProvider()
    return _provider


def reset_human_context_provider() -> None:
    """Reset le singleton (pour tests)."""
    global _provider
    _provider = None
