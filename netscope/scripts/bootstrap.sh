#!/usr/bin/env bash
# ============================================================================
# NETSCOPE Bootstrap — Déploiement complet sur Raspberry Pi
# ============================================================================
# Usage (sur un Pi fraîchement flashé avec Pi OS Bookworm) :
#
#   curl -sSL https://raw.githubusercontent.com/<owner>/NETSCOPE/main/netscope/scripts/bootstrap.sh | sudo bash
#
# Ou localement :
#   sudo bash bootstrap.sh
#
# Ce script :
#   1. Installe les paquets système (hostapd, dnsmasq, tcpdump, python3…)
#   2. Clone le dépôt NETSCOPE (ou utilise un clone existant)
#   3. Crée un venv Python + installe les dépendances
#   4. Configure l'environnement de production (.env)
#   5. Lance deploy_netscope_probe.sh (réseau, AP, iptables, captive)
#   6. Crée le service systemd netscope-web (Gunicorn)
#   7. Active tout + reboot
# ============================================================================

set -euo pipefail

# ── Couleurs ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }
step() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# ── Vérifications préliminaires ─────────────────────────────────────────────
[[ $EUID -eq 0 ]] || { err "Ce script doit être lancé en root (sudo)."; exit 1; }

if ! grep -qi 'raspberry\|BCM' /proc/cpuinfo 2>/dev/null; then
    warn "Ce système ne semble pas être un Raspberry Pi."
    read -rp "Continuer quand même ? [y/N] " ans
    [[ "$ans" =~ ^[yY]$ ]] || exit 0
fi

# ── Configuration ───────────────────────────────────────────────────────────
NETSCOPE_REPO="${NETSCOPE_REPO:-https://github.com/iPresing/NETSCOPE.git}"
NETSCOPE_BRANCH="${NETSCOPE_BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/netscope}"
VENV_DIR="${INSTALL_DIR}/venv"
APP_DIR="${INSTALL_DIR}/netscope"
NETSCOPE_USER="${NETSCOPE_USER:-netscope}"

# ── Étape 1 : Paquets système ──────────────────────────────────────────────
step "1/7 — Installation des paquets système"

apt-get update -qq

PACKAGES=(
    # Réseau & AP
    hostapd dnsmasq iw iproute2 iptables iptables-persistent
    wireless-regdb net-tools tcpdump
    # Python
    python3 python3-pip python3-venv python3-dev
    # Build essentials (pour scapy/psutil)
    build-essential libffi-dev libssl-dev
    # Outils
    git curl
)

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PACKAGES[@]}"
log "Paquets installés"

# Désactiver hostapd/dnsmasq au démarrage (deploy_netscope_probe.sh gère)
systemctl unmask hostapd 2>/dev/null || true
systemctl disable hostapd 2>/dev/null || true
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true

# ── Étape 2 : Clonage du dépôt ─────────────────────────────────────────────
step "2/7 — Récupération du code NETSCOPE"

if [[ -d "${APP_DIR}/.git" ]]; then
    log "Dépôt existant détecté dans ${INSTALL_DIR}, mise à jour…"
    cd "$INSTALL_DIR"
    git fetch origin
    git checkout "$NETSCOPE_BRANCH"
    git pull origin "$NETSCOPE_BRANCH"
elif [[ -f "$(dirname "$0")/deploy_netscope_probe.sh" ]]; then
    # Script lancé depuis le repo cloné localement
    REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
    log "Clone local détecté : ${REPO_ROOT}"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    if [[ "$REPO_ROOT" != "$INSTALL_DIR" ]]; then
        cp -a "$REPO_ROOT" "$INSTALL_DIR"
        log "Copié vers ${INSTALL_DIR}"
    fi
else
    log "Clonage depuis ${NETSCOPE_REPO} (branche: ${NETSCOPE_BRANCH})…"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --branch "$NETSCOPE_BRANCH" --depth 1 "$NETSCOPE_REPO" "$INSTALL_DIR"
fi

log "Code disponible dans ${INSTALL_DIR}"

# ── Étape 3 : Environnement Python ─────────────────────────────────────────
step "3/7 — Création du venv Python et installation des dépendances"

python3 -m venv "$VENV_DIR"
source "${VENV_DIR}/bin/activate"

pip install --upgrade pip setuptools wheel -q
pip install -r "${APP_DIR}/requirements.txt" -q

log "Python venv prêt : ${VENV_DIR}"
log "Paquets installés : $(pip list --format=freeze | wc -l) packages"

# ── Étape 4 : Configuration production ──────────────────────────────────────
step "4/7 — Configuration de l'environnement de production"

ENV_FILE="${APP_DIR}/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > "$ENV_FILE" <<EOF
# NETSCOPE Production — généré par bootstrap.sh le $(date -Iseconds)
NETSCOPE_CONFIG=production
FLASK_DEBUG=0
SECRET_KEY=${SECRET_KEY}
NETSCOPE_CONFIG_PATH=data/config/netscope.yaml
EOF
    chmod 600 "$ENV_FILE"
    log "Fichier .env créé avec SECRET_KEY aléatoire"
else
    warn ".env existant conservé"
fi

# ── Étape 5 : Déploiement réseau (AP, iptables, dnsmasq, captive) ──────────
step "5/7 — Déploiement réseau (hostapd, dnsmasq, iptables, captive portal)"

DEPLOY_SCRIPT="${APP_DIR}/scripts/deploy_netscope_probe.sh"
if [[ -x "$DEPLOY_SCRIPT" ]] || chmod +x "$DEPLOY_SCRIPT"; then
    bash "$DEPLOY_SCRIPT"
    log "Déploiement réseau terminé"
else
    err "Script de déploiement introuvable : ${DEPLOY_SCRIPT}"
    exit 1
fi

# ── Étape 6 : Service systemd Gunicorn ──────────────────────────────────────
step "6/7 — Création du service systemd netscope-web"

# Créer l'utilisateur système si nécessaire
if ! id "$NETSCOPE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$NETSCOPE_USER"
    log "Utilisateur système '${NETSCOPE_USER}' créé"
fi

# Permissions — l'app doit lire les configs et écrire les captures
chown -R "${NETSCOPE_USER}:${NETSCOPE_USER}" "$INSTALL_DIR"
# tcpdump a besoin de CAP_NET_RAW (géré via AmbientCapabilities)

cat > /etc/systemd/system/netscope-web.service <<EOF
[Unit]
Description=NETSCOPE Web Application (Gunicorn)
After=network-online.target dnsmasq.service
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=notify
User=root
Group=root
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${VENV_DIR}/bin/gunicorn \
    --config gunicorn.conf.py \
    "app:create_app('production')"
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=10

# Sécurité
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR} /tmp /run
PrivateTmp=true
NoNewPrivileges=false

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netscope-web

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/netscope-beacon.service <<BEACON_EOF
[Unit]
Description=NETSCOPE Beacon — Broadcast UDP pour identification de la sonde
After=network-online.target netscope-web.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${VENV_DIR}/bin/python3 ${APP_DIR}/scripts/netscope_beacon.py
Restart=on-failure
RestartSec=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netscope-beacon

[Install]
WantedBy=multi-user.target
BEACON_EOF

systemctl daemon-reload
systemctl enable netscope-web.service
systemctl enable netscope-beacon.service
log "Services netscope-web et netscope-beacon créés et activés"

# ── Étape 7 : Activation et résumé ─────────────────────────────────────────
step "7/7 — Activation finale"

# Tester que l'app démarre correctement
log "Test de démarrage de l'application…"
cd "$APP_DIR"
if "${VENV_DIR}/bin/python" -c "from app import create_app; app = create_app('production'); print('OK')" 2>/dev/null; then
    log "Application Flask : OK"
else
    warn "L'application ne démarre pas correctement (vérifier les logs après reboot)"
fi

# Démarrer les services
systemctl start netscope-web.service || warn "Démarrage immédiat échoué (normal avant reboot)"
systemctl start netscope-beacon.service || warn "Démarrage beacon échoué (normal avant reboot)"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  NETSCOPE — Bootstrap terminé !${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Installation : ${CYAN}${INSTALL_DIR}${NC}"
echo -e "  Venv Python  : ${CYAN}${VENV_DIR}${NC}"
echo -e "  Service web  : ${CYAN}netscope-web.service${NC}"
echo -e "  Beacon       : ${CYAN}netscope-beacon.service (UDP ${BEACON_PORT:-5742})${NC}"
echo -e "  Port         : ${CYAN}80 (HTTP)${NC}"
echo ""
echo -e "  ${YELLOW}SSID Wi-Fi   : NETSCOPE_PROBE${NC}"
echo -e "  ${YELLOW}Mot de passe : netscope123${NC}"
echo -e "  ${YELLOW}IP probe     : 192.168.88.1${NC}"
echo ""
echo -e "  Commandes utiles :"
echo -e "    sudo systemctl status netscope-web"
echo -e "    sudo systemctl status netscope-beacon"
echo -e "    sudo journalctl -u netscope-web -f"
echo -e "    sudo journalctl -u netscope-beacon -f"
echo -e "    sudo netscope-captive-toggle.sh status"
echo ""
echo -e "  ${YELLOW}Retrouver la sonde sur le réseau :${NC}"
echo -e "    python3 scripts/discover_probe.py"
echo ""

read -rp "Redémarrer maintenant ? [Y/n] " reboot_ans
if [[ ! "$reboot_ans" =~ ^[nN]$ ]]; then
    log "Redémarrage dans 3 secondes…"
    sleep 3
    reboot
else
    warn "Pense à redémarrer pour activer le AP Wi-Fi."
fi
