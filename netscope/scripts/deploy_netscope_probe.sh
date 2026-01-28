#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# NETSCOPE "PERFECT + SNIFF-ONLY" INSTALLER (ALL-IN-ONE)
# ==========================================================
# What you get (flawless switching):
# - Wi-Fi uplink (STA) on wlan0 for Internet when no Ethernet sniff link
# - Wi-Fi AP (NETSCOPE_PROBE) for clients (ap0 via virtual interface)
# - USB OTG Ethernet gadget (usb0) for wired client access (PC via OTG)
# - Ethernet adapter plugged (eth0/enx*) => AUTO "SNIFF-ONLY":
#       * AP OFF
#       * ip_forward=0
#       * NETSCOPE NAT/FORWARD chains flushed (no routing, just capture)
# - Ethernet adapter unplugged => AUTO "GATEWAY via Wi-Fi":
#       * AP ON
#       * ip_forward=1
#       * NAT usb0/ap0 -> wlan0 (only if interfaces exist)
# - dnsmasq ALWAYS ON (DHCP for usb0 + ap0 via /etc/dnsmasq.d/)
#
# Notes:
# - USB gadget requires reboot the first time (dwc2 + g_ether)
# - Pi Zero 2 W: plug the PC into the OTG/data USB port (not PWR)
# - Sniff-only on Ethernet means NO routing; you just capture on eth0/enx*
#
# Usage:
#   chmod +x netscope_install.sh
#   sudo UPLINK_SSID="YourWifi" UPLINK_PSK="YourPass" ./netscope_install.sh
#   sudo reboot

# ====== CONFIG ======
# Wi-Fi uplink (STA)
WIFI_UPLINK_IF="${WIFI_UPLINK_IF:-wlan0}"
UPLINK_SSID="${UPLINK_SSID:-WIFI_SOURCE}"
UPLINK_PSK="${UPLINK_PSK:-PASSWORD}"

# Wi-Fi AP (clients)
AP_IF="${AP_IF:-ap0}"
AP_SSID="${AP_SSID:-NETSCOPE_PROBE}"
AP_PSK="${AP_PSK:-netscope123}"
AP_CHANNEL="${AP_CHANNEL:-6}"
AP_IP="${AP_IP:-192.168.88.1/24}"
AP_NET="${AP_NET:-192.168.88.0/24}"
AP_DHCP_START="${AP_DHCP_START:-192.168.88.50}"
AP_DHCP_END="${AP_DHCP_END:-192.168.88.200}"
AP_DHCP_LEASE="${AP_DHCP_LEASE:-12h}"

# USB gadget (clients via OTG)
USB_IF="${USB_IF:-usb0}"
USB_IP="${USB_IP:-192.168.50.1/24}"
USB_NET="${USB_NET:-192.168.50.0/24}"
USB_DHCP_START="${USB_DHCP_START:-192.168.50.50}"
USB_DHCP_END="${USB_DHCP_END:-192.168.50.200}"
USB_DHCP_LEASE="${USB_DHCP_LEASE:-12h}"

# Upstream DNS (dnsmasq forwards)
DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-8.8.8.8}"

# ====== FILES ======
MODULES_FILE="/etc/modules"
DHCPCD_CONF="/etc/dhcpcd.conf"
WPA_SUPP="/etc/wpa_supplicant/wpa_supplicant.conf"
HOSTAPD_CONF="/etc/hostapd/hostapd.conf"
DNSMASQ_MAIN="/etc/dnsmasq.conf"
DNSMASQ_AP="/etc/dnsmasq.d/netscope-ap.conf"
DNSMASQ_USB="/etc/dnsmasq.d/netscope-usb.conf"

AP0_SERVICE="/etc/systemd/system/netscope-ap0.service"
MODE_SCRIPT="/usr/local/sbin/netscope-mode.sh"
MODE_SERVICE="/etc/systemd/system/netscope-mode.service"
MODE_TIMER="/etc/systemd/system/netscope-mode.timer"

need_root(){ [[ $EUID -eq 0 ]] || { echo "[-] sudo required"; exit 1; }; }
backup(){ [[ -f "$1" ]] && cp -a "$1" "$1.bak.$(date +%Y%m%d%H%M%S)"; }

boot_paths() {
  if [[ -d "/boot/firmware" ]]; then
    BOOT_CONFIG="/boot/firmware/config.txt"
    BOOT_CMDLINE="/boot/firmware/cmdline.txt"
  else
    BOOT_CONFIG="/boot/config.txt"
    BOOT_CMDLINE="/boot/cmdline.txt"
  fi
}

ensure_cmdline_token() {
  local token="$1"; local file="$2"
  local cur
  cur="$(tr -d '\n' < "$file")"
  [[ "$cur" == *"$token"* ]] && return 0
  echo "${cur} ${token}" > "$file"
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y hostapd dnsmasq iptables-persistent iw dhcpcd5 wpasupplicant iproute2
}

# ---- USB gadget boot (dwc2 + g_ether) ----
configure_usb_gadget_boot() {
  boot_paths
  backup "$BOOT_CONFIG"; backup "$BOOT_CMDLINE"; backup "$MODULES_FILE"

  grep -q "^dtoverlay=dwc2" "$BOOT_CONFIG" 2>/dev/null || {
    printf "\n# NETSCOPE USB Gadget\ndtoverlay=dwc2\n" >> "$BOOT_CONFIG"
    echo "[+] Added dtoverlay=dwc2"
  }

  ensure_cmdline_token "modules-load=dwc2,g_ether" "$BOOT_CMDLINE"
  echo "[+] Ensured cmdline modules-load=dwc2,g_ether"

  grep -qs '^dwc2$' "$MODULES_FILE" || echo "dwc2" >> "$MODULES_FILE"
  grep -qs '^g_ether$' "$MODULES_FILE" || echo "g_ether" >> "$MODULES_FILE"
  echo "[+] Ensured /etc/modules contains dwc2 + g_ether"
}

# ---- Wi-Fi uplink credentials ----
configure_wifi_uplink() {
  backup "$WPA_SUPP"
  cat > "$WPA_SUPP" <<EOF
country=FR
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
network={
  ssid="${UPLINK_SSID}"
  psk="${UPLINK_PSK}"
  key_mgmt=WPA-PSK
}
EOF
  chmod 600 "$WPA_SUPP"
  systemctl enable wpa_supplicant >/dev/null 2>&1 || true
  systemctl restart wpa_supplicant || true
  echo "[+] Configured Wi-Fi uplink creds (wpa_supplicant)"
}

# ---- dhcpcd static IP blocks (ap0 + usb0) ----
configure_static_ips() {
  backup "$DHCPCD_CONF"
  sed -i "/^# NETSCOPE STATIC BEGIN$/,/^# NETSCOPE STATIC END$/d" "$DHCPCD_CONF" 2>/dev/null || true

  cat >> "$DHCPCD_CONF" <<EOF

# NETSCOPE STATIC BEGIN
interface ${AP_IF}
static ip_address=${AP_IP}

interface ${USB_IF}
static ip_address=${USB_IP}
nohook wpa_supplicant
# NETSCOPE STATIC END
EOF

  systemctl restart dhcpcd || true
  echo "[+] dhcpcd static IP blocks added for ${AP_IF} and ${USB_IF}"
}

# ---- hostapd config (AP) ----
configure_hostapd() {
  backup "$HOSTAPD_CONF"
  cat > "$HOSTAPD_CONF" <<EOF
interface=${AP_IF}
driver=nl80211
ssid=${AP_SSID}
hw_mode=g
channel=${AP_CHANNEL}
wmm_enabled=1
auth_algs=1
wpa=2
wpa_passphrase=${AP_PSK}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

  backup /etc/default/hostapd
  if [[ -f /etc/default/hostapd ]]; then
    sed -i 's|^#\?DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd || true
    grep -q '^DAEMON_CONF=' /etc/default/hostapd || echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
  else
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd
  fi

  systemctl unmask hostapd >/dev/null 2>&1 || true
  systemctl enable hostapd
  echo "[+] hostapd configured (AP: ${AP_SSID})"
}

# ---- dnsmasq: main + per-interface DHCP ----
configure_dnsmasq() {
  mkdir -p /etc/dnsmasq.d
  backup "$DNSMASQ_MAIN"

  cat > "$DNSMASQ_MAIN" <<EOF
# NETSCOPE dnsmasq main
conf-dir=/etc/dnsmasq.d

server=${DNS1}
server=${DNS2}
domain-needed
bogus-priv
EOF

  backup "$DNSMASQ_AP"
  cat > "$DNSMASQ_AP" <<EOF
# NETSCOPE AP DHCP
interface=${AP_IF}
bind-interfaces
dhcp-range=${AP_DHCP_START},${AP_DHCP_END},${AP_DHCP_LEASE}
dhcp-option=option:router,${AP_IP%/*}
dhcp-option=option:dns-server,${AP_IP%/*}
EOF

  backup "$DNSMASQ_USB"
  cat > "$DNSMASQ_USB" <<EOF
# NETSCOPE USB DHCP
interface=${USB_IF}
bind-interfaces
dhcp-range=${USB_DHCP_START},${USB_DHCP_END},${USB_DHCP_LEASE}
dhcp-option=option:router,${USB_IP%/*}
dhcp-option=option:dns-server,${USB_IP%/*}
EOF

  systemctl enable dnsmasq
  systemctl restart dnsmasq
  echo "[+] dnsmasq configured (DHCP on ${AP_IF} + ${USB_IF}, always-on)"
}

# ---- ap0 creation service (idempotent) ----
configure_ap0_service() {
  cat > "$AP0_SERVICE" <<EOF
[Unit]
Description=Create virtual AP interface ${AP_IF} on ${WIFI_UPLINK_IF} (idempotent)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/sbin/ip link set ${WIFI_UPLINK_IF} up || true; /sbin/iw dev | grep -q "Interface ${AP_IF}" || /sbin/iw dev ${WIFI_UPLINK_IF} interface add ${AP_IF} type __ap'
ExecStart=/sbin/ip link set ${AP_IF} up
ExecStop=/bin/sh -c '/sbin/iw dev | grep -q "Interface ${AP_IF}" && /sbin/iw dev ${AP_IF} del || true'
TimeoutSec=10

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable netscope-ap0.service
  echo "[+] netscope-ap0 service installed"
}

# ---- MODE manager: Ethernet link => sniff-only (no NAT), else gateway via Wi-Fi ----
configure_mode_manager() {
  cat > "$MODE_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail

AP_IF="${AP_IF}"
USB_IF="${USB_IF}"
WIFI_UPLINK_IF="${WIFI_UPLINK_IF}"
AP_NET="${AP_NET}"
USB_NET="${USB_NET}"

AP0_SVC="netscope-ap0"
AP_SVC="hostapd"

log(){ logger -t NETSCOPE "\$*"; }

# Ethernet "sniff link" detector: any type=1 iface with carrier=1 except known ones
detect_eth_link() {
  for i in \$(ls /sys/class/net); do
    [[ "\$i" == "lo" ]] && continue
    [[ "\$i" == "\$USB_IF" ]] && continue
    [[ "\$i" == "\$AP_IF" ]] && continue
    [[ "\$i" == "\$WIFI_UPLINK_IF" ]] && continue

    if [[ -f "/sys/class/net/\$i/type" ]] && [[ "\$(cat /sys/class/net/\$i/type)" == "1" ]]; then
      if [[ -f "/sys/class/net/\$i/carrier" ]] && [[ "\$(cat /sys/class/net/\$i/carrier)" == "1" ]]; then
        echo "\$i"
        return 0
      fi
    fi
  done
  echo ""
  return 0
}

ap_is_active() { systemctl is-active --quiet "\$AP_SVC"; }

start_ap() {
  systemctl start "\$AP0_SVC" >/dev/null 2>&1 || true
  systemctl start "\$AP_SVC"  >/dev/null 2>&1 || true
}

stop_ap() {
  systemctl stop "\$AP_SVC" >/dev/null 2>&1 || true
}

# Dedicated NETSCOPE chains (safe)
ensure_chains() {
  iptables -t nat -N NETSCOPE_POSTROUTING 2>/dev/null || true
  iptables -t nat -C POSTROUTING -j NETSCOPE_POSTROUTING 2>/dev/null || \
    iptables -t nat -I POSTROUTING 1 -j NETSCOPE_POSTROUTING

  iptables -t filter -N NETSCOPE_FORWARD 2>/dev/null || true
  iptables -t filter -C FORWARD -j NETSCOPE_FORWARD 2>/dev/null || \
    iptables -t filter -I FORWARD 1 -j NETSCOPE_FORWARD
}

flush_chains() {
  iptables -t nat -F NETSCOPE_POSTROUTING 2>/dev/null || true
  iptables -t filter -F NETSCOPE_FORWARD 2>/dev/null || true
}

iptables_ensure() {
  local table="\$1"; shift
  local chain="\$1"; shift
  if iptables -t "\$table" -C "\$chain" "\$@" 2>/dev/null; then
    return 0
  fi
  iptables -t "\$table" -A "\$chain" "\$@"
}

# MODE SNIFF-ONLY: AP OFF, no forwarding, no NAT
enter_sniff_only() {
  if ap_is_active; then
    log "Ethernet link detected -> AP OFF, SNIFF-ONLY (no routing)"
    stop_ap
  fi

  sysctl -w net.ipv4.ip_forward=0 >/dev/null

  ensure_chains
  flush_chains

  netfilter-persistent save >/dev/null 2>&1 || true
}

# MODE GATEWAY via Wi-Fi: AP ON, forwarding, NAT usb/ap -> wlan0 (if exists)
enter_gateway_wifi() {
  if ! ap_is_active; then
    log "No ethernet link -> AP ON, GATEWAY via Wi-Fi"
    start_ap
  fi

  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  ensure_chains
  flush_chains

  # USB -> Wi-Fi uplink (only if usb0 exists)
  if ip link show "\$USB_IF" >/dev/null 2>&1; then
    iptables_ensure nat   NETSCOPE_POSTROUTING -s "\$USB_NET" -o "\$WIFI_UPLINK_IF" -j MASQUERADE
    iptables_ensure filter NETSCOPE_FORWARD    -i "\$USB_IF" -o "\$WIFI_UPLINK_IF" -s "\$USB_NET" -j ACCEPT
    iptables_ensure filter NETSCOPE_FORWARD    -i "\$WIFI_UPLINK_IF" -o "\$USB_IF" -d "\$USB_NET" -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  # AP -> Wi-Fi uplink (only if ap0 exists)
  if ip link show "\$AP_IF" >/dev/null 2>&1; then
    iptables_ensure nat   NETSCOPE_POSTROUTING -s "\$AP_NET" -o "\$WIFI_UPLINK_IF" -j MASQUERADE
    iptables_ensure filter NETSCOPE_FORWARD    -i "\$AP_IF" -o "\$WIFI_UPLINK_IF" -s "\$AP_NET" -j ACCEPT
    iptables_ensure filter NETSCOPE_FORWARD    -i "\$WIFI_UPLINK_IF" -o "\$AP_IF" -d "\$AP_NET" -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  netfilter-persistent save >/dev/null 2>&1 || true
}

main() {
  eth_if="\$(detect_eth_link)"
  if [[ -n "\$eth_if" ]]; then
    enter_sniff_only
  else
    enter_gateway_wifi
  fi
}

main
EOF

  chmod +x "$MODE_SCRIPT"

  cat > "$MODE_SERVICE" <<EOF
[Unit]
Description=NETSCOPE mode manager (sniff-only vs gateway)
After=network.target dnsmasq.service
Wants=dnsmasq.service

[Service]
Type=oneshot
ExecStart=${MODE_SCRIPT}
EOF

  cat > "$MODE_TIMER" <<EOF
[Unit]
Description=Run NETSCOPE mode manager periodically

[Timer]
OnBootSec=6
OnUnitActiveSec=3
AccuracySec=1

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now netscope-mode.timer
  echo "[+] netscope-mode timer enabled (auto switching)"
}

main() {
  need_root
  apt_install

  configure_usb_gadget_boot
  configure_wifi_uplink

  configure_ap0_service
  configure_static_ips
  configure_hostapd
  configure_dnsmasq
  configure_mode_manager

  echo
  echo "[+] NETSCOPE installed with flawless switching:"
  echo "    - Ethernet link present (eth0/enx* carrier=1): SNIFF-ONLY (AP OFF, no NAT, no routing)"
  echo "    - Ethernet link absent: GATEWAY via Wi-Fi (AP ON, NAT to ${WIFI_UPLINK_IF})"
  echo "    - dnsmasq always ON (DHCP usb0 + ap0)"
  echo
  echo "[!] First time USB gadget requires reboot: sudo reboot"
  echo
  echo "Useful:"
  echo "  systemctl status netscope-mode.timer --no-pager"
  echo "  journalctl -t NETSCOPE -n 50 --no-pager"
  echo
  echo "Capture:"
  echo "  sudo tcpdump -i ${USB_IF} -w /tmp/usb.pcap      # PC via OTG"
  echo "  sudo tcpdump -i ${AP_IF}  -w /tmp/ap.pcap       # client Wi-Fi"
  echo "  sudo tcpdump -i ${WIFI_UPLINK_IF} -w /tmp/wifi_uplink.pcap"
  echo "  sudo tcpdump -i eth0 -w /tmp/eth_sniff.pcap     # when ethernet adapter is plugged"
}

main "$@"
