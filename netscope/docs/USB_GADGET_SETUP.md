# Configuration USB Ethernet Gadget pour NETSCOPE

Ce document décrit la procédure de configuration du mode USB Ethernet Gadget sur Raspberry Pi pour NETSCOPE.

## Prérequis

- Raspberry Pi Zero, Pi 4, ou Pi 5 (avec support USB OTG)
- Raspberry Pi OS installé
- Accès root au système

## Mode USB Gadget

Le mode USB Gadget permet au Raspberry Pi d'apparaître comme une interface Ethernet lorsqu'il est connecté via USB à un ordinateur. Cela permet d'accéder à NETSCOPE via `http://192.168.50.1` sans nécessiter de configuration réseau sur le PC hôte.

## Installation Automatique

```bash
cd /path/to/netscope/scripts
sudo ./setup_usb_gadget.sh
sudo reboot
```

### Activation du Service Systemd (Optionnel)

Pour charger automatiquement le module g_ether au démarrage:

```bash
sudo cp /path/to/netscope/scripts/netscope-usb-gadget.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable netscope-usb-gadget.service
```

## Installation Manuelle

### 1. Configuration boot/config.txt

Ajouter à `/boot/config.txt`:

```
dtoverlay=dwc2
```

### 2. Configuration boot/cmdline.txt

Ajouter à la fin de la ligne existante (sans nouvelle ligne):

```
modules-load=dwc2,g_ether
```

### 3. Configuration /etc/modules

Ajouter:

```
dwc2
g_ether
```

### 4. Configuration dhcpcd.conf

Ajouter à `/etc/dhcpcd.conf`:

```
interface usb0
static ip_address=192.168.50.1/24
nohook wpa_supplicant
```

### 5. Redémarrage

```bash
sudo reboot
```

## Utilisation

1. Brancher le Raspberry Pi à un PC via le port USB données
2. Attendre que le Pi démarre complètement (LED verte stable)
3. Sur le PC, une nouvelle interface réseau apparaît
4. Accéder à `http://192.168.50.1` dans un navigateur

## Dépannage

### L'interface usb0 n'apparaît pas

```bash
# Vérifier que les modules sont chargés
lsmod | grep g_ether

# Charger manuellement si nécessaire
sudo modprobe g_ether
```

### Le PC ne reconnaît pas l'interface

- Vérifier que le câble USB supporte les données (pas uniquement l'alimentation)
- Utiliser le port USB données du Pi (pas le port alimentation)
- Installer les drivers RNDIS sur Windows si nécessaire

### IP non assignée

```bash
# Vérifier la configuration dhcpcd
ip addr show usb0

# Redémarrer dhcpcd
sudo systemctl restart dhcpcd
```

## Configuration PC Hôte

### Windows

Windows devrait détecter automatiquement l'interface RNDIS. Si des drivers sont nécessaires, installer "RNDIS/Ethernet Gadget" depuis le gestionnaire de périphériques.

### Linux

Aucune configuration supplémentaire requise. L'interface apparaît automatiquement.

### macOS

L'interface apparaît automatiquement comme "RNDIS/Ethernet Gadget".

## Alimentation

NETSCOPE supporte plusieurs modes d'alimentation (AC3):

| Mode | Description | Notes |
|------|-------------|-------|
| **USB** | Alimentation via port USB données | Suffisant pour utilisation standard |
| **Chargeur 5V/2.5A** | Alimentation via port USB-C power | Recommandé pour opérations intensives |
| **PoE** | Power over Ethernet (Pi 4/5 avec HAT PoE) | Configuration matérielle uniquement, aucune config logicielle requise |

> **Note:** L'alimentation PoE nécessite un HAT PoE compatible et un switch/injecteur PoE. Aucune configuration logicielle n'est nécessaire - le Pi démarre automatiquement lorsqu'il reçoit l'alimentation via Ethernet.

## Notes

- Le mode USB Gadget est incompatible avec certaines configurations USB (hubs, dongles)
- Pour le monitoring réseau en production, préférer la connexion Ethernet filaire
- L'alimentation via USB seul peut être insuffisante pour des opérations intensives
