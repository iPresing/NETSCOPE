#!/bin/bash
# NETSCOPE Ethernet Configuration Script
# Configure DHCP for eth0 interface with optional static fallback
#
# This script ensures the Raspberry Pi obtains an IP via DHCP
# on the Ethernet interface. If DHCP fails, a fallback static
# IP can be configured.
#
# Requirements:
#   - Run as root
#
# Usage:
#   sudo ./setup_ethernet.sh [--fallback]
#
# Options:
#   --fallback    Configure static IP fallback if DHCP fails

set -e

# Constants
ETH_INTERFACE="eth0"
DHCPCD_CONF="/etc/dhcpcd.conf"
FALLBACK_IP="192.168.1.100"
FALLBACK_ROUTER="192.168.1.1"
FALLBACK_DNS="8.8.8.8"

# Parse arguments
CONFIGURE_FALLBACK=false
if [[ "$1" == "--fallback" ]]; then
    CONFIGURE_FALLBACK=true
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root"
    exit 1
fi

echo "[INFO][scripts.setup_ethernet] Starting Ethernet configuration"

# Backup original file
if [[ -f "$DHCPCD_CONF" ]] && [[ ! -f "${DHCPCD_CONF}.bak" ]]; then
    cp "$DHCPCD_CONF" "${DHCPCD_CONF}.bak"
    echo "[INFO][scripts.setup_ethernet] Backed up $DHCPCD_CONF"
fi

# Verify default DHCP configuration for eth0
# By default, dhcpcd enables DHCP on all interfaces, so eth0 should work
echo "[INFO][scripts.setup_ethernet] Verifying DHCP configuration for $ETH_INTERFACE"

# Check if interface is explicitly disabled
if grep -q "^denyinterfaces.*$ETH_INTERFACE" "$DHCPCD_CONF" 2>/dev/null; then
    echo "[WARNING][scripts.setup_ethernet] $ETH_INTERFACE is denied in dhcpcd.conf"
    echo "[INFO][scripts.setup_ethernet] Removing deny entry..."
    sed -i "s/denyinterfaces.*$ETH_INTERFACE//" "$DHCPCD_CONF"
fi

# Optional: Configure static fallback
if [[ "$CONFIGURE_FALLBACK" == true ]]; then
    echo "[INFO][scripts.setup_ethernet] Configuring static fallback for $ETH_INTERFACE"

    if ! grep -q "# NETSCOPE Ethernet Fallback" "$DHCPCD_CONF" 2>/dev/null; then
        cat >> "$DHCPCD_CONF" << EOF

# NETSCOPE Ethernet Fallback Configuration
# Used when DHCP is unavailable on eth0
profile static_$ETH_INTERFACE
static ip_address=${FALLBACK_IP}/24
static routers=$FALLBACK_ROUTER
static domain_name_servers=$FALLBACK_DNS

# Apply fallback after DHCP timeout
interface $ETH_INTERFACE
fallback static_$ETH_INTERFACE
EOF
        echo "[INFO][scripts.setup_ethernet] Configured fallback IP $FALLBACK_IP for $ETH_INTERFACE"
    else
        echo "[INFO][scripts.setup_ethernet] Fallback already configured"
    fi
fi

# Restart dhcpcd to apply changes
echo "[INFO][scripts.setup_ethernet] Restarting dhcpcd service"
systemctl restart dhcpcd || true

# Wait for interface to come up
echo "[INFO][scripts.setup_ethernet] Waiting for $ETH_INTERFACE to obtain IP..."
sleep 5

# Check current IP
CURRENT_IP=$(ip -4 addr show "$ETH_INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

if [[ -n "$CURRENT_IP" ]]; then
    echo "[INFO][scripts.setup_ethernet] $ETH_INTERFACE IP: $CURRENT_IP"
else
    echo "[WARNING][scripts.setup_ethernet] $ETH_INTERFACE has no IP assigned"
    echo "[INFO][scripts.setup_ethernet] DHCP may not be available on this network"
fi

echo ""
echo "[INFO][scripts.setup_ethernet] Ethernet configuration complete"
echo ""
echo "Summary:"
echo "  - Interface: $ETH_INTERFACE"
echo "  - Mode: DHCP"
if [[ "$CONFIGURE_FALLBACK" == true ]]; then
    echo "  - Fallback IP: $FALLBACK_IP (if DHCP fails)"
fi
if [[ -n "$CURRENT_IP" ]]; then
    echo "  - Current IP: $CURRENT_IP"
fi
