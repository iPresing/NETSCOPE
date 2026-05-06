<div align="center">
  <img src="https://github.com/user-attachments/assets/074c3466-2042-48f5-b723-48ab99828575" alt="Logo NETSCOPE" width="80" height="85" />
  
  # NETSCOPE
  ### Sonde Réseau Portable pour Raspberry Pi
  
  **Un outil pédagogique d'analyse réseau basé sur Python**  
  <br>Scanner le trafic Wi-Fi/Ethernet · Attribuer un Score de Santé · Visualiser les connexions
  <br>Guide pas-à-pas pour installer NETSCOPE sur un Raspberry Pi, de la création de l'image SD au lancement en mode debug.
  
  [![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
  ![Raspberry Pi](https://img.shields.io/badge/platform-RaspberryPi-red)
  [![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)](https://flask.palletsprojects.com/)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#)
</div>

---

## 1. Prérequis matériel

- **Raspberry Pi** : Zero 2 W, Pi 3, Pi 4 ou Pi 5
- **Carte microSD** : 16 Go minimum (classe 10 recommandée)
- **Alimentation** : 5V / 2.5A minimum
- **PC** avec lecteur de carte SD et **Raspberry Pi Imager** installé

---

## 2. Création de l'image Raspberry Pi OS

1. **Télécharger et installer** [Raspberry Pi Imager](https://www.raspberrypi.com/software/)
2. **Lancer** Raspberry Pi Imager
3. **Choisir l'OS** : `Raspberry Pi OS (other)` > **Raspberry Pi OS Lite (64-bit)** (Bookworm)
   - La version Lite suffit (pas besoin de desktop)
4. **Choisir la carte SD** comme support de destination
5. **Cliquer sur l'engrenage** (ou `Ctrl+Shift+X`) pour ouvrir les **options avancées** :
   - **Nom d'hôte** : Définir un nom d'hôte pour le raspberry
   - **Localisation** : Sélectionner votre lieu pour suggérer un fuseau horaire et un type de clavier
   - **Définir le nom d'utilisateur et mot de passe** :
     - Utilisateur : `pi` (ou au choix)
     - Mot de passe : (choisir un mot de passe)
   - **Configurer le Wi-Fi** :
     - SSID : le `nom` de votre réseau Wi-Fi
     - Mot de passe : le `mot de passe` de votre réseau Wi-Fi
   - **Activer SSH** : cocher `Activer SSH` > `Utiliser un mot de passe`
   - **Rasberry pi connect** : (optionnel) 
  
6. **Écrire** l'image sur la carte SD

---

## 3. Premier démarrage du Pi

1. **Insérer** la carte SD dans le Raspberry Pi
2. **Brancher** le Pi à l'alimentation (et au réseau Wi-Fi configuré à l'étape précédente)
3. **Attendre ~1-2 min** le temps du premier boot et de l'expansion du filesystem
4. **Trouver l'IP du Pi** sur votre réseau :
   - Depuis votre PC : `ping raspberrypi.local` (si mDNS disponible)
   - Télécharger **Wireless Network Watcher** : https://www.nirsoft.net/utils/wireless_network_watcher.html
5. **Se connecter en SSH** :
   ```bash
   ssh pi@<IP_DU_PI>
   ```

---

## SECTION INSTALLATION AUTOMATIQUE 
Pour installer automatiquement les dépendances et le système 
```bash
curl -sSL https://raw.githubusercontent.com/iPresing/NETSCOPE/main/netscope/scripts/bootstrap.sh | sudo bash
```

## SECTION INSTALLATION MANUELLE 
Pour installer manuellement les dépendances et le système  
## 1. Installation des dépendances système

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git tcpdump
```

> **Note** : `tcpdump` est indispensable pour la capture réseau (niveau 1).

---

## 2. Cloner le projet NETSCOPE

```bash
cd ~
git clone https://github.com/iPresing/NETSCOPE.git netscope
cd NETSCOPE/netscope
```

---

## 3. Créer l'environnement virtuel Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Configurer l'environnement

```bash
cp .env.example .env
```

Éditer le fichier `.env` si besoin :

```bash
nano .env
```

Contenu recommandé pour le debug :

```env
NETSCOPE_CONFIG=development
FLASK_DEBUG=1
SECRET_KEY=une-cle-secrete-quelconque
NETSCOPE_CONFIG_PATH=data/config/netscope.yaml
```

---

## 5. (Optionnel) Déployer le réseau probe

Si vous souhaitez configurer le mode AP (point d'accès Wi-Fi) :

```bash
sudo bash scripts/deploy_netscope_probe.sh
```

Ce script configure :
- **Point d'accès Wi-Fi** (`ap0`) : réseau `NETSCOPE_PROBE`, mot de passe `netscope123` (IP `192.168.88.1`)
- **Commutation automatique** : sniff Ethernet branché / AP+NAT si débranché

Un **reboot est nécessaire** après ce script :

```bash
sudo reboot
```

---

## 6. Lancer NETSCOPE en mode debug

```bash
cd ~/netscope/netscope
source venv/bin/activate
sudo venv/bin/python run.py
```

> **`sudo` est requis** car la capture réseau (tcpdump/scapy) nécessite les droits root.

L'application démarre sur **`http://<IP_DU_PI>:5000`**.

### Accéder à l'interface web

| Mode de connexion | URL |
|---|---|
| Via Wi-Fi (même réseau) | `http://<IP_DU_PI>:5000` |
| Via AP NETSCOPE_PROBE | `http://192.168.88.1:5000` |

---

## Vérifier que tout fonctionne

1. Ouvrir l'URL dans un navigateur
2. Le **dashboard** doit s'afficher avec le health score
3. Lancer une capture depuis l'interface pour valider la chaîne complète

---

## Résumé des commandes (copier-coller rapide)

```bash
# Sur le Pi, après SSH
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git tcpdump

cd ~
git clone https://github.com/iPresing/NETSCOPE.git netscope
cd NETSCOPE/netscope

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

cp .env.example .env
# Editer .env : FLASK_DEBUG=1

# (Optionnel) Déployer le réseau probe
# sudo bash scripts/deploy_netscope_probe.sh && sudo reboot

# Lancer en debug
sudo venv/bin/python run.py
```

---

## Dépannage

| Problème | Solution |
|---|---|
| `Permission denied` sur tcpdump | Lancer avec `sudo` |
| Pi introuvable sur le réseau | Vérifier la config Wi-Fi dans Imager, ou brancher un écran/clavier |
| Port 5000 inaccessible | Vérifier le firewall : `sudo iptables -L` |
| Module `scapy` introuvable | Vérifier que le venv est activé : `source venv/bin/activate` |
