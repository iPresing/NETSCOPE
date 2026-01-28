#!/usr/bin/env bash
set -euo pipefail

# ====== CONFIG ======
UPLINK_SSID="${UPLINK_SSID:-WIFI_SOURCE}"
UPLINK_PSK="${UPLINK_PSK:-PASSWORD}"

AP_SSID="${AP_SSID:-NETSCOPE_PROBE}"
AP_PSK="${AP_PSK:-netscope123}"
AP_CHANNEL="${AP_CHANNEL:-6}"

AP_IP_CIDR="${AP_IP_CIDR:-192.168.88.1/24}"
DHCP_START="${DHCP_START:-192.168.88.50}"
DHCP_END="${DHCP_END:-192.168.88.200}"
DHCP_LEASE="${DHCP_LEASE:-12h}"

DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-8.8.8.8}"

STA_IF="${STA_IF:-wlan0}"
AP_IF="${AP_IF:-ap0}"

need_root(){ [[ $EUID -eq 0 ]] || { echo "sudo required"; exit 1; }; }
backup(){ [[ -f "$1" ]] && cp -a "$1" "$1.bak.$(date +%Y%m%d%H%M%S)"; }

iface_exists() { iw dev 2>/dev/null | grep -q "Interface $1"; }

# Convert "192.168.88.1/24" -> "192.168.88.0/24" (assumes /24, which is what we use here)
# If you change mask, adapt this.
ap_subnet_from_cidr() {
  local ipcidr="$1"
  local ip="${ipcidr%/*}"
  local mask="${ipcidr#*/}"
  IFS='.' read -r a b c d <<<"$ip"

  if [[ "$mask" != "24" ]]; then
    echo "[-] Ce script supporte nativement /24 pour AP_IP_CIDR (actuellement /$mask)."
    echo "    Mets AP_IP_CIDR en /24 (ex: 192.168.88.1/24) ou dis-moi ton masque et je l’adapte."
    exit 1
  fi

  echo "${a}.${b}.${c}.0/24"
}

ensure_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y hostapd dnsmasq iptables-persistent iw dhcpcd5 wpasupplicant tcpdump tshark net-tools
}

write_wpa() {
  local conf="/etc/wpa_supplicant/wpa_supplicant.conf"
  backup "$conf"
  cat > "$conf" <<EOF
country=FR
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
  ssid="${UPLINK_SSID}"
  psk="${UPLINK_PSK}"
  key_mgmt=WPA-PSK
}
EOF
  chmod 600 "$conf"
  systemctl enable wpa_supplicant >/dev/null 2>&1 || true
  systemctl restart wpa_supplicant || true
}

ensure_ap_iface_now() {
  ip link set "${STA_IF}" up || true

  if iface_exists "${AP_IF}"; then
    ip link set "${AP_IF}" up || true
    return 0
  fi

  iw dev "${STA_IF}" interface add "${AP_IF}" type __ap
  ip link set "${AP_IF}" up || true
}

create_ap0_service_idempotent() {
  local svc="/etc/systemd/system/netscope-ap0.service"
  cat > "$svc" <<EOF
[Unit]
Description=Create virtual AP interface ${AP_IF} on ${STA_IF} (idempotent)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/sbin/ip link set ${STA_IF} up || true; /sbin/iw dev | grep -q "Interface ${AP_IF}" || /sbin/iw dev ${STA_IF} interface add ${AP_IF} type __ap'
ExecStart=/sbin/ip link set ${AP_IF} up
ExecStop=/bin/sh -c '/sbin/iw dev | grep -q "Interface ${AP_IF}" && /sbin/iw dev ${AP_IF} del || true'
TimeoutSec=10

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable netscope-ap0.service
}

add_deps() {
  mkdir -p /etc/systemd/system/dnsmasq.service.d
  cat > /etc/systemd/system/dnsmasq.service.d/override.conf <<EOF
[Unit]
After=netscope-ap0.service
Wants=netscope-ap0.service
EOF

  mkdir -p /etc/systemd/system/hostapd.service.d
  cat > /etc/systemd/system/hostapd.service.d/override.conf <<EOF
[Unit]
After=netscope-ap0.service
Wants=netscope-ap0.service
EOF

  systemctl daemon-reload
}

write_dhcpcd() {
  local conf="/etc/dhcpcd.conf"
  backup "$conf"
  sed -i "/^# --- NETSCOPE PROBE AP static IP ---$/,/^$/d" "$conf" 2>/dev/null || true
  sed -i "/^interface ${AP_IF}$/,/^$/d" "$conf" 2>/dev/null || true

  cat >> "$conf" <<EOF

# --- NETSCOPE PROBE AP static IP ---
interface ${AP_IF}
static ip_address=${AP_IP_CIDR}
EOF
  systemctl restart dhcpcd || true
}

write_hostapd() {
  local conf="/etc/hostapd/hostapd.conf"
  backup "$conf"
  cat > "$conf" <<EOF
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

  local def="/etc/default/hostapd"
  backup "$def"
  sed -i 's|^#\?DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' "$def" 2>/dev/null || true
  grep -q '^DAEMON_CONF=' "$def" 2>/dev/null || echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> "$def"

  systemctl unmask hostapd >/dev/null 2>&1 || true
  systemctl enable hostapd
}

write_dnsmasq() {
  local conf="/etc/dnsmasq.conf"
  backup "$conf"
  cat > "$conf" <<EOF
interface=${AP_IF}
bind-interfaces

dhcp-range=${DHCP_START},${DHCP_END},${DHCP_LEASE}

domain-needed
bogus-priv

server=${DNS1}
server=${DNS2}
EOF
  systemctl enable dnsmasq
}

enable_forwarding() {
  backup /etc/sysctl.conf
  if grep -q '^net.ipv4.ip_forward=' /etc/sysctl.conf; then
    sed -i 's/^net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  else
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

iptables_ensure_rule() {
  # Usage: iptables_ensure_rule <table> <chain> <rule...>
  local table="$1"; shift
  local chain="$1"; shift
  if iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
    return 0
  fi
  iptables -t "$table" -A "$chain" "$@"
}

setup_nat_idempotent() {
  local ap_subnet
  ap_subnet="$(ap_subnet_from_cidr "$AP_IP_CIDR")"

  # NAT for AP subnet to uplink
  iptables_ensure_rule nat POSTROUTING -s "$ap_subnet" -o "$STA_IF" -j MASQUERADE

  # Forward rules
  iptables_ensure_rule filter FORWARD -i "$AP_IF" -o "$STA_IF" -s "$ap_subnet" -j ACCEPT
  iptables_ensure_rule filter FORWARD -i "$STA_IF" -o "$AP_IF" -d "$ap_subnet" -m state --state RELATED,ESTABLISHED -j ACCEPT

  netfilter-persistent save
}

main(){
  need_root
  echo "[*] Paquets..."
  ensure_packages

  echo "[*] wpa_supplicant (uplink STA)..."
  write_wpa

  echo "[*] Service ap0 idempotent + deps..."
  create_ap0_service_idempotent
  add_deps

  echo "[*] Création immédiate de ap0 (si absent)..."
  ensure_ap_iface_now

  echo "[*] IP statique + hostapd + dnsmasq..."
  write_dhcpcd
  write_hostapd
  write_dnsmasq

  echo "[*] IP forwarding + NAT (idempotent, subnet-aware)..."
  enable_forwarding
  setup_nat_idempotent

  echo "[*] Start services..."
  systemctl restart netscope-ap0 || true
  systemctl restart hostapd
  systemctl restart dnsmasq

  echo
  echo "[+] OK : Hotspot ${AP_SSID} / pass ${AP_PSK}"
  echo "    AP IP: ${AP_IP_CIDR}"
  echo "    NAT:  $(ap_subnet_from_cidr "$AP_IP_CIDR") -> ${STA_IF}"
  echo
  echo "Sniff: sudo tcpdump -i ${AP_IF} -w capture.pcap"
  echo "DNS :  sudo tshark -i ${AP_IF} -Y dns"
  echo "Reboot conseillé: sudo reboot"
}

main "$@"
