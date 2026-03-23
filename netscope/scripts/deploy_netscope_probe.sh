#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[ERREUR] ligne $LINENO : $BASH_COMMAND" >&2' ERR

# ==========================================================
# NETSCOPE - Raspberry Pi deployment script (safe SSH)
# - Wi-Fi uplink on wlan0 (managed by your current system / NM)
# - AP on ap0 (virtual interface on wlan0)
# - USB gadget on usb0
# - Ethernet plugged => sniff-only (AP off, no NAT)
# - Ethernet unplugged => AP on + NAT via wlan0
#
# This script:
# - does NOT disable NetworkManager live
# - does NOT restart your live uplink stack
# - prepares everything for next boot
# ==========================================================

# ---------- CONFIG ----------
WIFI_UPLINK_IF="${WIFI_UPLINK_IF:-wlan0}"
COUNTRY_CODE="${COUNTRY_CODE:-FR}"

AP_IF="${AP_IF:-ap0}"
AP_SSID="${AP_SSID:-NETSCOPE_PROBE}"
AP_PSK="${AP_PSK:-netscope123}"
AP_CHANNEL_FALLBACK="${AP_CHANNEL_FALLBACK:-6}"
AP_IP="${AP_IP:-192.168.88.1/24}"
AP_NET="${AP_NET:-192.168.88.0/24}"
AP_DHCP_START="${AP_DHCP_START:-192.168.88.50}"
AP_DHCP_END="${AP_DHCP_END:-192.168.88.200}"
AP_DHCP_LEASE="${AP_DHCP_LEASE:-12h}"

USB_IF="${USB_IF:-usb0}"
USB_IP="${USB_IP:-192.168.50.1/24}"
USB_NET="${USB_NET:-192.168.50.0/24}"
USB_DHCP_START="${USB_DHCP_START:-192.168.50.50}"
USB_DHCP_END="${USB_DHCP_END:-192.168.50.200}"
USB_DHCP_LEASE="${USB_DHCP_LEASE:-12h}"

DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-8.8.8.8}"

# ---------- PATHS ----------
MODULES_FILE="/etc/modules"
HOSTAPD_CONF="/etc/hostapd/hostapd.conf"
HOSTAPD_DEFAULT="/etc/default/hostapd"
DNSMASQ_MAIN="/etc/dnsmasq.conf"
DNSMASQ_AP="/etc/dnsmasq.d/netscope-ap.conf"
DNSMASQ_USB="/etc/dnsmasq.d/netscope-usb.conf"
SYSCTL_FILE="/etc/sysctl.d/90-netscope.conf"
NM_UNMANAGED_CONF="/etc/NetworkManager/conf.d/99-netscope-unmanaged.conf"

AP0_HELPER="/usr/local/sbin/netscope-create-ap0.sh"
AP0_SERVICE="/etc/systemd/system/netscope-ap0.service"

MODE_SCRIPT="/usr/local/sbin/netscope-mode.sh"
MODE_SERVICE="/etc/systemd/system/netscope-mode.service"
MODE_TIMER="/etc/systemd/system/netscope-mode.timer"

CAPTIVE_DNS_CONF="/etc/dnsmasq.d/netscope-captive.conf"
CAPTIVE_TOGGLE="/usr/local/sbin/netscope-captive-toggle.sh"

need_root() {
  [[ $EUID -eq 0 ]] || { echo "[-] Lance avec sudo/root"; exit 1; }
}

step() {
  echo
  echo "[+] $*"
}

backup() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "$f.bak.$(date +%Y%m%d%H%M%S)"
}

service_exists() {
  systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$1"
}

safe_enable() {
  local unit="$1"
  service_exists "$unit" && systemctl enable "$unit" >/dev/null 2>&1 || true
}

boot_paths() {
  if [[ -d /boot/firmware ]]; then
    BOOT_CONFIG="/boot/firmware/config.txt"
    BOOT_CMDLINE="/boot/firmware/cmdline.txt"
  else
    BOOT_CONFIG="/boot/config.txt"
    BOOT_CMDLINE="/boot/cmdline.txt"
  fi
}

ensure_cmdline_token() {
  local token="$1"
  local file="$2"
  local cur
  cur="$(tr -d '\n' < "$file")"
  [[ "$cur" == *"$token"* ]] || echo "${cur} ${token}" > "$file"
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y \
    hostapd dnsmasq iw iproute2 iptables iptables-persistent wireless-regdb
}

configure_usb_gadget_boot() {
  boot_paths
  backup "$BOOT_CONFIG"
  backup "$BOOT_CMDLINE"
  backup "$MODULES_FILE"

  grep -q '^dtoverlay=dwc2' "$BOOT_CONFIG" 2>/dev/null || {
    printf "\n# NETSCOPE USB gadget\ndtoverlay=dwc2\n" >> "$BOOT_CONFIG"
  }

  ensure_cmdline_token "modules-load=dwc2,g_ether" "$BOOT_CMDLINE"

  grep -qs '^dwc2$' "$MODULES_FILE" || echo "dwc2" >> "$MODULES_FILE"
  grep -qs '^g_ether$' "$MODULES_FILE" || echo "g_ether" >> "$MODULES_FILE"
}

configure_networkmanager_unmanaged() {
  mkdir -p /etc/NetworkManager/conf.d
  backup "$NM_UNMANAGED_CONF"

  cat > "$NM_UNMANAGED_CONF" <<EOF
[keyfile]
unmanaged-devices=interface-name:${AP_IF};interface-name:${USB_IF}
EOF
}

unmask_hostapd_force() {
  systemctl unmask hostapd >/dev/null 2>&1 || true

  if [[ -L /etc/systemd/system/hostapd.service ]]; then
    rm -f /etc/systemd/system/hostapd.service
  fi

  systemctl daemon-reload
  systemctl unmask hostapd >/dev/null 2>&1 || true
  safe_enable "hostapd.service"
}

configure_hostapd() {
  mkdir -p /etc/hostapd
  backup "$HOSTAPD_CONF"
  backup "$HOSTAPD_DEFAULT"

  cat > "$HOSTAPD_CONF" <<EOF
interface=${AP_IF}
driver=nl80211
ssid=${AP_SSID}
hw_mode=g
channel=${AP_CHANNEL_FALLBACK}
country_code=${COUNTRY_CODE}
ieee80211d=1
wmm_enabled=1
auth_algs=1
ignore_broadcast_ssid=0

wpa=2
wpa_passphrase=${AP_PSK}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

  cat > "$HOSTAPD_DEFAULT" <<EOF
DAEMON_CONF="/etc/hostapd/hostapd.conf"
DAEMON_OPTS=""
EOF

  unmask_hostapd_force
}

configure_dnsmasq() {
  mkdir -p /etc/dnsmasq.d
  backup "$DNSMASQ_MAIN"
  backup "$DNSMASQ_AP"
  backup "$DNSMASQ_USB"

  cat > "$DNSMASQ_MAIN" <<EOF
conf-dir=/etc/dnsmasq.d
no-resolv
server=${DNS1}
server=${DNS2}
domain-needed
bogus-priv
EOF

  cat > "$DNSMASQ_AP" <<EOF
interface=${AP_IF}
bind-dynamic
dhcp-range=${AP_DHCP_START},${AP_DHCP_END},${AP_DHCP_LEASE}
dhcp-option=option:router,${AP_IP%/*}
dhcp-option=option:dns-server,${AP_IP%/*}
EOF

  cat > "$DNSMASQ_USB" <<EOF
interface=${USB_IF}
bind-dynamic
dhcp-range=${USB_DHCP_START},${USB_DHCP_END},${USB_DHCP_LEASE}
dhcp-option=option:router,${USB_IP%/*}
dhcp-option=option:dns-server,${USB_IP%/*}
EOF

  safe_enable "dnsmasq.service"
}

configure_sysctl() {
  backup "$SYSCTL_FILE"
  cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward=1
EOF
}

configure_captive() {
  backup "$CAPTIVE_DNS_CONF"

  # DNS hijack — all domains resolve to probe IP for captive portal interception
  cat > "$CAPTIVE_DNS_CONF" <<EOF
# NETSCOPE captive portal DNS hijack — auto-generated
# Resolves ALL domains to probe IP so Flask can intercept HTTP requests
address=/#/${AP_IP%/*}
EOF

  # Captive portal toggle script (called by Flask to enable/disable)
  cat > "$CAPTIVE_TOGGLE" <<TOGGLEEOF
#!/usr/bin/env bash
# Ne PAS utiliser set -e : le filesystem peut être read-only,
# chaque opération doit être tentée indépendamment.
set -uo pipefail

CAPTIVE_DNS_CONF="/etc/dnsmasq.d/netscope-captive.conf"
STATE_FILE="/run/netscope-captive.active"
IPTABLES_BIN="\$(command -v iptables)"
AP_HOST_IP="${AP_IP%/*}"

# Tente remount rw si nécessaire, restore ro à la fin
_remount_rw() {
  if ! touch /etc/.rw-test 2>/dev/null; then
    mount -o remount,rw / 2>/dev/null && _DID_REMOUNT=1
  else
    rm -f /etc/.rw-test
  fi
}
_remount_ro() {
  [[ "\${_DID_REMOUNT:-0}" == "1" ]] && mount -o remount,ro / 2>/dev/null || true
}
_DID_REMOUNT=0

case "\${1:-status}" in
  enable)
    _remount_rw
    cat > "\$CAPTIVE_DNS_CONF" <<DNSEOF
# NETSCOPE captive portal DNS hijack — auto-generated
address=/#/\$AP_HOST_IP
DNSEOF
    systemctl restart dnsmasq 2>/dev/null || true
    echo "active" > "\$STATE_FILE"
    _remount_ro
    logger -t NETSCOPE "Captive portal enabled"
    ;;
  disable)
    # 1. Flush iptables EN PREMIER (toujours en mémoire, pas de fs)
    "\$IPTABLES_BIN" -t nat -F NETSCOPE_PREROUTING 2>/dev/null || true

    # 2. Supprimer le DNS hijack (peut nécessiter remount rw)
    _remount_rw
    rm -f "\$CAPTIVE_DNS_CONF" 2>/dev/null || true
    systemctl restart dnsmasq 2>/dev/null || true

    # 3. Supprimer le state file (/run = tmpfs, toujours writable)
    rm -f "\$STATE_FILE" 2>/dev/null || true
    _remount_ro

    logger -t NETSCOPE "Captive portal disabled"
    ;;
  status)
    if [[ -f "\$STATE_FILE" ]] && [[ "\$(cat "\$STATE_FILE" 2>/dev/null)" == "active" ]]; then
      echo "active"
    else
      echo "inactive"
    fi
    ;;
  *)
    echo "Usage: \$0 {enable|disable|status}" >&2
    exit 1
    ;;
esac
TOGGLEEOF
  chmod 0755 "$CAPTIVE_TOGGLE"

  # Activate captive portal state for first boot
  echo "active" > /run/netscope-captive.active 2>/dev/null || true
}

configure_ap0_service() {
  mkdir -p /usr/local/sbin

  cat > "$AP0_HELPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail

WIFI_UPLINK_IF="${WIFI_UPLINK_IF}"
AP_IF="${AP_IF}"
AP_IP="${AP_IP}"
USB_IF="${USB_IF}"
USB_IP="${USB_IP}"

IW_BIN="\$(command -v iw)"
IP_BIN="\$(command -v ip)"

"\$IP_BIN" link set "\$WIFI_UPLINK_IF" up || true

if ! "\$IW_BIN" dev | grep -q "Interface \$AP_IF"; then
  "\$IW_BIN" dev "\$WIFI_UPLINK_IF" interface add "\$AP_IF" type __ap
fi

if "\$IP_BIN" link show "\$AP_IF" >/dev/null 2>&1; then
  "\$IP_BIN" addr replace "\$AP_IP" dev "\$AP_IF"
  "\$IP_BIN" link set "\$AP_IF" up
fi

if "\$IP_BIN" link show "\$USB_IF" >/dev/null 2>&1; then
  "\$IP_BIN" addr replace "\$USB_IP" dev "\$USB_IF"
  "\$IP_BIN" link set "\$USB_IF" up
fi
EOF
  chmod 0755 "$AP0_HELPER"

  cat > "$AP0_SERVICE" <<EOF
[Unit]
Description=NETSCOPE create AP interface ${AP_IF} and set static IPs
After=sys-subsystem-net-devices-${WIFI_UPLINK_IF}.device
Wants=sys-subsystem-net-devices-${WIFI_UPLINK_IF}.device
Before=hostapd.service dnsmasq.service network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${AP0_HELPER}
ExecStop=/bin/sh -c '$(command -v iw) dev | grep -q "Interface ${AP_IF}" && $(command -v iw) dev ${AP_IF} del || true'

[Install]
WantedBy=multi-user.target
WantedBy=network-pre.target
EOF

  systemctl daemon-reload
  systemctl enable netscope-ap0.service >/dev/null 2>&1 || true
}

configure_mode_manager() {
  mkdir -p /usr/local/sbin

  cat > "$MODE_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail

AP_IF="${AP_IF}"
USB_IF="${USB_IF}"
WIFI_UPLINK_IF="${WIFI_UPLINK_IF}"
AP_NET="${AP_NET}"
AP_IP="${AP_IP}"
USB_NET="${USB_NET}"
USB_IP="${USB_IP}"
HOSTAPD_CONF="${HOSTAPD_CONF}"
AP_CHANNEL_FALLBACK="${AP_CHANNEL_FALLBACK}"

IP_BIN="\$(command -v ip)"
IW_BIN="\$(command -v iw)"
IPTABLES_BIN="\$(command -v iptables)"
STATE_FILE="/run/netscope-mode.state"

log() { logger -t NETSCOPE "\$*"; }

detect_eth_link() {
  for p in /sys/class/net/*; do
    i="\$(basename "\$p")"
    [[ "\$i" == "lo" ]] && continue
    [[ "\$i" == "\$USB_IF" ]] && continue
    [[ "\$i" == "\$AP_IF" ]] && continue
    [[ "\$i" == "\$WIFI_UPLINK_IF" ]] && continue
    [[ -f "/sys/class/net/\$i/type" ]] || continue
    [[ -f "/sys/class/net/\$i/carrier" ]] || continue

    if [[ "\$(cat /sys/class/net/\$i/type)" == "1" ]] && [[ "\$(cat /sys/class/net/\$i/carrier)" == "1" ]]; then
      echo "\$i"
      return 0
    fi
  done

  echo ""
}

get_sta_channel() {
  "\$IW_BIN" dev "\$WIFI_UPLINK_IF" info 2>/dev/null | awk '/channel/ {print \$2; exit}'
}

sync_hostapd_channel() {
  local ch
  ch="\$(get_sta_channel || true)"
  [[ -n "\${ch:-}" ]] || ch="\$AP_CHANNEL_FALLBACK"
  sed -i "s/^channel=.*/channel=\${ch}/" "\$HOSTAPD_CONF"
}

ensure_chains() {
  "\$IPTABLES_BIN" -t nat -N NETSCOPE_POSTROUTING 2>/dev/null || true
  "\$IPTABLES_BIN" -t nat -C POSTROUTING -j NETSCOPE_POSTROUTING 2>/dev/null || \
    "\$IPTABLES_BIN" -t nat -I POSTROUTING 1 -j NETSCOPE_POSTROUTING

  "\$IPTABLES_BIN" -t filter -N NETSCOPE_FORWARD 2>/dev/null || true
  "\$IPTABLES_BIN" -t filter -C FORWARD -j NETSCOPE_FORWARD 2>/dev/null || \
    "\$IPTABLES_BIN" -t filter -I FORWARD 1 -j NETSCOPE_FORWARD

  "\$IPTABLES_BIN" -t nat -N NETSCOPE_PREROUTING 2>/dev/null || true
  "\$IPTABLES_BIN" -t nat -C PREROUTING -j NETSCOPE_PREROUTING 2>/dev/null || \
    "\$IPTABLES_BIN" -t nat -I PREROUTING 1 -j NETSCOPE_PREROUTING
}

flush_chains() {
  "\$IPTABLES_BIN" -t nat -F NETSCOPE_POSTROUTING 2>/dev/null || true
  "\$IPTABLES_BIN" -t nat -F NETSCOPE_PREROUTING 2>/dev/null || true
  "\$IPTABLES_BIN" -t filter -F NETSCOPE_FORWARD 2>/dev/null || true
}

iptables_ensure() {
  local table="\$1"; shift
  local chain="\$1"; shift
  if "\$IPTABLES_BIN" -t "\$table" -C "\$chain" "\$@" 2>/dev/null; then
    return 0
  fi
  "\$IPTABLES_BIN" -t "\$table" -A "\$chain" "\$@"
}

set_mode_state() {
  local new_state="\$1"
  local old_state=""
  [[ -f "\$STATE_FILE" ]] && old_state="\$(cat "\$STATE_FILE" 2>/dev/null || true)"
  if [[ "\$new_state" != "\$old_state" ]]; then
    echo "\$new_state" > "\$STATE_FILE"
    log "\$new_state"
  fi
}

enter_sniff_only() {
  systemctl stop hostapd >/dev/null 2>&1 || true
  sysctl -w net.ipv4.ip_forward=0 >/dev/null
  ensure_chains
  flush_chains
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  set_mode_state "Ethernet detected -> sniff-only"
}

enter_gateway_wifi() {
  systemctl start netscope-ap0.service
  sync_hostapd_channel
  systemctl unmask hostapd >/dev/null 2>&1 || true
  systemctl start hostapd >/dev/null 2>&1 || true

  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ensure_chains
  flush_chains

  if "\$IP_BIN" link show "\$USB_IF" >/dev/null 2>&1; then
    iptables_ensure nat    NETSCOPE_POSTROUTING -s "\$USB_NET" -o "\$WIFI_UPLINK_IF" -j MASQUERADE
    iptables_ensure filter NETSCOPE_FORWARD     -i "\$USB_IF" -o "\$WIFI_UPLINK_IF" -s "\$USB_NET" -j ACCEPT
    iptables_ensure filter NETSCOPE_FORWARD     -i "\$WIFI_UPLINK_IF" -o "\$USB_IF" -d "\$USB_NET" -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  if "\$IP_BIN" link show "\$AP_IF" >/dev/null 2>&1; then
    iptables_ensure nat    NETSCOPE_POSTROUTING -s "\$AP_NET" -o "\$WIFI_UPLINK_IF" -j MASQUERADE
    iptables_ensure filter NETSCOPE_FORWARD     -i "\$AP_IF" -o "\$WIFI_UPLINK_IF" -s "\$AP_NET" -j ACCEPT
    iptables_ensure filter NETSCOPE_FORWARD     -i "\$WIFI_UPLINK_IF" -o "\$AP_IF" -d "\$AP_NET" -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  # Captive portal DNAT — redirect HTTP port 80 to probe when captive active
  if [[ -f /run/netscope-captive.active ]] && [[ "\$(cat /run/netscope-captive.active 2>/dev/null)" == "active" ]]; then
    if "\$IP_BIN" link show "\$AP_IF" >/dev/null 2>&1; then
      iptables_ensure nat NETSCOPE_PREROUTING -i "\$AP_IF" -p tcp --dport 80 -j DNAT --to-destination "\${AP_IP%/*}:80"
    fi
    if "\$IP_BIN" link show "\$USB_IF" >/dev/null 2>&1; then
      iptables_ensure nat NETSCOPE_PREROUTING -i "\$USB_IF" -p tcp --dport 80 -j DNAT --to-destination "\${USB_IP%/*}:80"
    fi
  fi

  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  set_mode_state "No Ethernet -> AP on + NAT via Wi-Fi"
}

main() {
  local eth_if
  eth_if="\$(detect_eth_link)"

  if [[ -n "\$eth_if" ]]; then
    enter_sniff_only
  else
    enter_gateway_wifi
  fi
}

main
EOF
  chmod 0755 "$MODE_SCRIPT"

  cat > "$MODE_SERVICE" <<EOF
[Unit]
Description=NETSCOPE mode manager
After=network.target dnsmasq.service netscope-ap0.service
Wants=dnsmasq.service netscope-ap0.service

[Service]
Type=oneshot
ExecStart=${MODE_SCRIPT}
EOF

  cat > "$MODE_TIMER" <<EOF
[Unit]
Description=NETSCOPE periodic mode manager

[Timer]
OnBootSec=15
OnUnitActiveSec=30
AccuracySec=1

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable netscope-mode.timer >/dev/null 2>&1 || true
}

post_install_checks() {
  echo
  echo "[CHECK] Fichiers installés :"
  ls -l "$AP0_SERVICE" || true
  ls -l "$AP0_HELPER" || true
  ls -l "$MODE_SCRIPT" || true
  ls -l "$MODE_SERVICE" || true
  ls -l "$MODE_TIMER" || true
  ls -l "$NM_UNMANAGED_CONF" || true

  echo
  echo "[CHECK] hostapd        : $(systemctl is-enabled hostapd 2>/dev/null || true)"
  echo "[CHECK] dnsmasq        : $(systemctl is-enabled dnsmasq 2>/dev/null || true)"
  echo "[CHECK] netscope-ap0   : $(systemctl is-enabled netscope-ap0 2>/dev/null || true)"
  echo "[CHECK] netscope-mode  : $(systemctl is-enabled netscope-mode.timer 2>/dev/null || true)"
}

main() {
  need_root

  step "Installation des paquets"
  apt_install

  step "Configuration USB gadget au boot"
  configure_usb_gadget_boot

  step "Configuration NetworkManager (ap0/usb0 unmanaged)"
  configure_networkmanager_unmanaged

  step "Configuration hostapd"
  configure_hostapd

  step "Configuration dnsmasq"
  configure_dnsmasq

  step "Configuration sysctl"
  configure_sysctl

  step "Configuration portail captif"
  configure_captive

  step "Installation du service ap0"
  configure_ap0_service

  step "Installation du mode manager"
  configure_mode_manager

  step "Reload systemd"
  systemctl daemon-reload

  step "Activation des services pour le prochain boot"
  safe_enable "dnsmasq.service"
  safe_enable "hostapd.service"
  systemctl enable netscope-ap0.service >/dev/null 2>&1 || true
  systemctl enable netscope-mode.timer >/dev/null 2>&1 || true

  post_install_checks

  echo
  echo "[+] Installation terminée sans toucher à la connexion réseau en cours."
  echo "[+] Reboot maintenant :"
  echo "    sudo reboot"
  echo
  echo "[+] Après reboot, vérifie :"
  echo "    ip a"
  echo "    iw dev"
  echo "    systemctl status netscope-ap0 hostapd dnsmasq --no-pager -l"
  echo "    journalctl -u netscope-ap0 -u hostapd -u dnsmasq -b --no-pager"
  echo "    journalctl -t NETSCOPE -b --no-pager"
}

main "$@"