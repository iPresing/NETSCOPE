<div align="center">
  <img src="https://github.com/user-attachments/assets/074c3466-2042-48f5-b723-48ab99828575" alt="Logo NETSCOPE" width="80" height="85" />
  
  # NETSCOPE
  ### Sonde Réseau Portable pour Raspberry Pi
  
  **Un outil pédagogique d'analyse réseau basé sur Python**  
  Scanner le trafic Wi-Fi/Ethernet · Attribuer un Score de Santé · Visualiser les connexions
  
  [![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
  ![Raspberry Pi](https://img.shields.io/badge/platform-RaspberryPi-red)
  [![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)](https://flask.palletsprojects.com/)
  [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#)
</div>

---

## 📝 Objectifs

Les administrateurs réseau débutants et PME font face à un problème : **Wireshark** requiert des compétences et une expertise avancée. Il n'existe pas de solution simple pour répondre rapidement à la question : **Est-ce que le réseau de ma machine est sécurisé ?**

### 💡 Notre Projet

**NETSCOPE** répond à cette problématique en offrant un service adapté aux besoins du public cible :

```
✓ Surveillance passive du trafic réseau
✓ Détection visuelle des anomalies (code couleur 🟢/🟡/🔴) de façon détaillée et simple
✓ Investigation approfondie sur demande
✓ Installation plug & play en moins de 5 minutes
```

*Il est toujours en phase de développement*

---

## ⚡ Fonctionnalités
- **🎯 Dashboard temps réel**  
Vue d'ensemble de la santé réseau avec score global

- **🔍 Détection d'anomalies**  
IPs suspectes, ports inhabituels, volumes anormaux

- **🛡️ Blacklists intégrées**  
IPs malveillantes, domaines suspects, termes de recherche

- **📊 4 Analyses Essentielles**  
Top talkers, distribution protocoles, ports inhabituels, connexions externes

- **🏗️ Architecture 3 niveaux**  
• Niveau 1 : Surveillance légère (tcpdump headers-only)  
• Niveau 2 : Inspection ciblée (Scapy métadonnées)  
• Niveau 3 : Deep packet inspection optionnel

---

## 🔧 Stack Technique

| Composant | Technologie |
|-----------|-------------|
| **Backend** | Flask 3.x, Python 3.11+ |
| **Capture** | tcpdump, Scapy |
| **Frontend** | HTML/CSS/JS, DataTables |
| **Serveur** | Gunicorn |
| **Cible** | Raspberry Pi Zero 2 W |


## 🛠️ Prérequis

### Matériel
- **Raspberry Pi Zero 2 W** (recommandé) ou Pi 3/4/5
- Carte microSD (8 Go minimum)
- Câble USB ou adaptateur Ethernet
- Setup du Raspberry Pi : https://github.com/iPresing/NETSCOPE/blob/main/netscope/docs/SETUP_RASPBERRY_PI.md

### Logiciel
- Python 3.11+
- tcpdump (capture réseau)

---

## 🚀 Installation

### 1️⃣ Cloner le dépôt

```bash
git clone https://github.com/iPresing/NETSCOPE.git
cd netscope
```

### 2️⃣ Créer l'environnement virtuel

```bash
cd netscope
python -m venv venv
source venv/bin/activate  # Linux/macOS
# ou
venv\Scripts\activate     # Windows
```

### 3️⃣ Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4️⃣ Lancer l'application

```bash
# Mode développement
python run.py

# Mode production (Raspberry Pi)
gunicorn -c gunicorn.conf.py "app:create_app('production')"
```

### 5️⃣ Accéder à l'interface

Ouvrez votre navigateur : **`http://<IP_RASPBERRY>:5000`**

---

## 📁 Structure du Projet

```
netscope/
├──  app/
│   ├──  blueprints/         # Routes Flask (dashboard, api, admin)
│   ├──  core/
│   │   ├──  analysis/       # Scoring et analyses
│   │   ├──  capture/        # Capture réseau (tcpdump, BPF)
│   │   └──  detection/      # Détection anomalies, blacklists
│   ├──  models/             # Modèles de données
│   ├──  services/           # Services (hardware, threads)
│   ├──  static/             # CSS, JS, images
│   └──  templates/          # Templates Jinja2
├──  data/
│   └──  config/             # Configuration YAML
├──  tests/                  # Tests unitaires et intégration
├──  requirements.txt
├──  gunicorn.conf.py
└──  run.py
```

---

## 📖 Utilisation

### Dashboard

Le dashboard affiche en temps réel :
- **Score de santé réseau** (0-100)
- **Nombre d'anomalies** détectées par sévérité
- **Dernière capture** analysée

### Lancer une capture

1. Cliquez sur **"Nouvelle Capture"**
2. Sélectionnez la **durée** et les **filtres**
3. Attendez **l'analyse automatique**
4. Consultez les **résultats et anomalies**

### Interpréter les résultats


| Couleur | Signification |
|:-------:|:-------------:|
| 🟢 **Vert** | Trafic normal |
| 🟡 **Jaune** | À surveiller |
| 🔴 **Rouge** | Anomalie détectée |



<div align="center">
  <img src="https://github.com/user-attachments/assets/074c3466-2042-48f5-b723-48ab99828575" alt="Logo" width="48" height="51" />
  
  **NETSCOPE** - Projet Étudiant Ynov STRASBOURG
</div>
