#!/bin/bash
# NETSCOPE USB Ethernet Gadget Setup Script
# Configure g_ether for Raspberry Pi USB OTG mode
#
# This script configures the Raspberry Pi to act as a USB Ethernet gadget
# when connected to a PC via USB. The Pi will have IP 192.168.50.1 and
# the connected PC can access NETSCOPE at http://192.168.50.1
#
# Requirements:
#   - Raspberry Pi Zero, Pi 4, or Pi 5 (with USB OTG support)
#   - Run as root
#
# Usage:
#   sudo ./setup_usb_gadget.sh
#
# After running, reboot is required for changes to take effect.

set -e

# Constants
USB_GADGET_IP="192.168.50.1"
USB_INTERFACE="usb0"
MODULES_FILE="/etc/modules"
DHCPCD_CONF="/etc/dhcpcd.conf"

# Detect boot partition path (Pi 5 Bookworm uses /boot/firmware/, older uses /boot/)
if [[ -d "/boot/firmware" ]]; then
    BOOT_CONFIG="/boot/firmware/config.txt"
    BOOT_CMDLINE="/boot/firmware/cmdline.txt"
    echo "[INFO][scripts.setup_usb_gadget] Detected Pi 5 / Bookworm boot path"
else
    BOOT_CONFIG="/boot/config.txt"
    BOOT_CMDLINE="/boot/cmdline.txt"
    echo "[INFO][scripts.setup_usb_gadget] Detected legacy boot path"
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root"
    exit 1
fi

echo "[INFO][scripts.setup_usb_gadget] Starting USB gadget configuration"

# Backup original files
backup_file() {
    local file=$1
    if [[ -f "$file" ]] && [[ ! -f "${file}.bak" ]]; then
        cp "$file" "${file}.bak"
        echo "[INFO][scripts.setup_usb_gadget] Backed up $file"
    fi
}

backup_file "$BOOT_CONFIG"
backup_file "$BOOT_CMDLINE"
backup_file "$DHCPCD_CONF"

# Step 1: Add dwc2 overlay to config.txt
echo "[INFO][scripts.setup_usb_gadget] Configuring dtoverlay in $BOOT_CONFIG"
if ! grep -q "dtoverlay=dwc2" "$BOOT_CONFIG" 2>/dev/null; then
    echo "" >> "$BOOT_CONFIG"
    echo "# NETSCOPE USB Gadget Configuration" >> "$BOOT_CONFIG"
    echo "dtoverlay=dwc2" >> "$BOOT_CONFIG"
    echo "[INFO][scripts.setup_usb_gadget] Added dtoverlay=dwc2 to $BOOT_CONFIG"
else
    echo "[INFO][scripts.setup_usb_gadget] dtoverlay=dwc2 already configured"
fi

# Step 2: Add modules-load to cmdline.txt
echo "[INFO][scripts.setup_usb_gadget] Configuring modules-load in $BOOT_CMDLINE"
if ! grep -q "modules-load=dwc2,g_ether" "$BOOT_CMDLINE" 2>/dev/null; then
    # Read current content and append modules-load (on same line, no newline)
    current_cmdline=$(cat "$BOOT_CMDLINE" | tr -d '\n')
    echo "${current_cmdline} modules-load=dwc2,g_ether" > "$BOOT_CMDLINE"
    echo "[INFO][scripts.setup_usb_gadget] Added modules-load=dwc2,g_ether to $BOOT_CMDLINE"
else
    echo "[INFO][scripts.setup_usb_gadget] modules-load already configured"
fi

# Step 3: Add modules to /etc/modules for persistent loading
echo "[INFO][scripts.setup_usb_gadget] Configuring modules in $MODULES_FILE"
if ! grep -q "^dwc2$" "$MODULES_FILE" 2>/dev/null; then
    echo "dwc2" >> "$MODULES_FILE"
    echo "[INFO][scripts.setup_usb_gadget] Added dwc2 to $MODULES_FILE"
fi

if ! grep -q "^g_ether$" "$MODULES_FILE" 2>/dev/null; then
    echo "g_ether" >> "$MODULES_FILE"
    echo "[INFO][scripts.setup_usb_gadget] Added g_ether to $MODULES_FILE"
fi

# Step 4: Configure static IP for usb0 in dhcpcd.conf
echo "[INFO][scripts.setup_usb_gadget] Configuring static IP for $USB_INTERFACE"
if ! grep -q "interface $USB_INTERFACE" "$DHCPCD_CONF" 2>/dev/null; then
    cat >> "$DHCPCD_CONF" << EOF

# NETSCOPE USB Gadget Configuration
# Static IP for USB Ethernet Gadget mode
interface $USB_INTERFACE
static ip_address=${USB_GADGET_IP}/24
nohook wpa_supplicant
EOF
    echo "[INFO][scripts.setup_usb_gadget] Configured static IP $USB_GADGET_IP for $USB_INTERFACE"
else
    echo "[INFO][scripts.setup_usb_gadget] $USB_INTERFACE already configured in $DHCPCD_CONF"
fi

echo ""
echo "[INFO][scripts.setup_usb_gadget] USB Gadget configuration complete"
echo ""
echo "Summary:"
echo "  - USB interface: $USB_INTERFACE"
echo "  - Static IP: $USB_GADGET_IP"
echo "  - Access URL: http://$USB_GADGET_IP"
echo ""
echo "IMPORTANT: Reboot required for changes to take effect."
echo "Run: sudo reboot"
