# NETSCOPE — Guide Utilisateur

**Terminal de surveillance réseau pour Raspberry Pi**

---

## Table des matières

1. [Présentation](#1-présentation)
2. [Prise en main](#2-prise-en-main)
3. [Dashboard](#3-dashboard)
4. [Anomalies](#4-anomalies)
5. [Blacklists](#5-blacklists)
6. [Whitelists](#6-whitelists)
7. [Inspection de paquets](#7-inspection-de-paquets)
8. [Jobs d'inspection](#8-jobs-dinspection)
9. [Export de données](#9-export-de-données)
10. [Administration](#10-administration)
11. [Mises à jour OTA](#11-mises-à-jour-ota)
12. [Portail captif](#12-portail-captif)
13. [API](#13-api)
14. [Dépannage](#14-dépannage)

---

## 1. Présentation

NETSCOPE est un outil de surveillance réseau conçu pour fonctionner sur Raspberry Pi. Il capture le trafic réseau, détecte les anomalies, calcule un score de santé réseau et fournit une interface web pour l'analyse.

### Fonctionnalités principales

- **Capture réseau** via tcpdump avec adaptation automatique au matériel
- **Détection d'anomalies** par scoring multi-critères et correspondance avec des blacklists
- **Score de santé réseau** en temps réel avec historique d'évolution
- **Visionneuse de paquets** avec dissection couches réseau
- **Export CSV/JSON** pour intégration avec des outils externes (SIEM, tableurs, BI)
- **Gestion blacklists/whitelists** depuis l'interface web
- **Mises à jour OTA** avec backup automatique et rollback
- **Portail captif** pour le mode sonde Wi-Fi
- **Thème sombre cinématique** avec fond vidéo et glassmorphism

### Matériel supporté

| Modèle | Support | Notes |
|--------|---------|-------|
| Raspberry Pi Zero / Zero W | Complet | Performances adaptées automatiquement |
| Raspberry Pi 3 | Complet | Mode recommandé |
| Raspberry Pi 4 | Complet | Meilleures performances |
| Raspberry Pi 5 | Complet | — |
| Autre (PC/VM) | Partiel | Fonctionne sans détection hardware |

---

## 2. Prise en main

### Accès à l'interface

Ouvrez un navigateur et accédez à l'adresse du Raspberry Pi :

```
http://<adresse-ip-du-pi>
```

L'interface s'ouvre directement sur le **Dashboard**.

### Navigation

La barre de navigation en haut de l'écran donne accès aux sections principales :

| Section | Description |
|---------|-------------|
| **Dashboard** | Vue d'ensemble avec score de santé |
| **Anomalies** | Liste des anomalies détectées |
| **Inspection** | Jobs d'inspection et visionneuse de paquets |
| **Blacklists** | Gestion des listes noires |
| **Admin** | Administration et mises à jour |

La version de NETSCOPE est affichée dans le footer.

---

## 3. Dashboard

Le Dashboard est la page d'accueil. Il affiche :

### Score de santé réseau

- **Indicateur circulaire** avec le score global (0-100)
- **Code couleur** : vert (bon), jaune (attention), rouge (critique)
- **Évolution** entre les captures successives (tendance)

### Cartes de statut

Quatre cartes résument l'état du réseau :

- **Paquets analysés** — nombre total de paquets dans la dernière capture
- **Anomalies détectées** — nombre d'anomalies avec répartition par criticité
- **Hits blacklist** — correspondances trouvées avec les listes noires
- **Score de santé** — score calculé et tendance

### Lancer une capture

1. Cliquez sur le bouton **Capturer** dans le Dashboard
2. NETSCOPE lance tcpdump en arrière-plan
3. La capture se termine automatiquement selon la durée configurée
4. Les résultats s'affichent sur le Dashboard une fois l'analyse terminée

---

## 4. Anomalies

La page **Anomalies** (`/anomalies`) liste toutes les anomalies détectées lors des captures.

### Informations affichées

Pour chaque anomalie :
- **Adresse IP** source et destination
- **Ports** et protocole
- **Score** de criticité
- **Raison** de la détection (blacklist match, scoring, pattern anormal)
- **Type de correspondance** (IP, domaine, terme)

### Actions disponibles

- **Filtrer** par criticité, type, ou terme de recherche
- **Trier** par colonne (score, IP, date)
- **Inspecter** — ouvre la visionneuse de paquets pour cette anomalie
- **Ajouter en whitelist** — supprime les faux positifs des futurs résultats

---

## 5. Blacklists

La page **Blacklists** (`/blacklist`) permet de gérer les listes noires utilisées pour la détection.

### Types de blacklists

| Type | Description | Exemple |
|------|-------------|---------|
| **IP** | Adresses IP connues malveillantes | `192.168.1.100` |
| **Domaine** | Domaines suspects | `malware-c2.example.com` |
| **Terme** | Mots-clés dans le trafic | `exploit`, `backdoor` |

### Gestion depuis l'interface

- **Ajouter** une entrée manuellement (IP, domaine ou terme)
- **Supprimer** une entrée existante
- **Rechercher** dans les listes
- **Enrichissement automatique** via sources externes (AlienVault OTX, etc.)

### Sources d'enrichissement

NETSCOPE peut interroger des sources tierces pour enrichir les blacklists :
- Recherche par IP ou domaine
- Intégration des résultats dans les listes locales
- Sources configurables

---

## 6. Whitelists

La page **Whitelists** (`/whitelist`) permet d'exclure des faux positifs de la détection.

### Utilisation

- **Ajouter** une IP, un domaine ou un terme à la whitelist
- **Supprimer** une entrée de la whitelist
- **Impact** : les entrées en whitelist sont exclues du scoring et n'apparaissent plus comme anomalies

### Transparence

Le Dashboard affiche un indicateur de **hits whitelist** pour garder la visibilité sur les éléments filtrés. Le score de santé différencie le score brut (avant whitelist) du score affiché (après whitelist).

---

## 7. Inspection de paquets

La page **Paquets** (`/packets`) offre une visionneuse détaillée du trafic capturé.

### Fonctionnalités

- **Liste des paquets** avec numéro, timestamp, IPs, protocole, taille
- **Filtrage** par anomalie spécifique (`/packets?anomaly_id=X`)
- **Panel de détail** pour chaque paquet :
  - Dissection par couche réseau (Ethernet, IP, TCP/UDP, Application)
  - Vue hexadécimale (hex dump)
  - Vue ASCII
  - Métadonnées complètes

### Navigation

- Cliquez sur un paquet dans la liste pour afficher son détail
- Utilisez les filtres pour cibler un flux spécifique
- Le bouton **Inspecter** depuis la page Anomalies mène directement aux paquets de l'anomalie

---

## 8. Jobs d'inspection

La page **Jobs** (`/jobs`) gère les tâches d'inspection en arrière-plan.

### Fonctionnalités

- **Lancer une inspection** avec paramètres granulaires (IP, port, direction, durée)
- **File d'attente séquentielle** — un seul job actif à la fois
- **Suivi de progression** en temps réel (pourcentage, paquets capturés)
- **Annuler** un job en cours ou en attente
- **Résultats** — accès direct à la visionneuse de paquets une fois terminé

### Statuts des jobs

| Statut | Description |
|--------|-------------|
| **PENDING** | En attente dans la file |
| **RUNNING** | En cours d'exécution |
| **COMPLETED** | Terminé avec succès |
| **CANCELLED** | Annulé manuellement |
| **FAILED** | Échec (voir message d'erreur) |

### Dégradation gracieuse

Si les ressources système sont insuffisantes (mémoire, CPU), NETSCOPE passe en mode dégradé :
- **NORMAL** → **DEGRADED** → **CRITICAL**
- Les jobs sont suspendus en mode critique
- Reprise automatique quand les ressources se libèrent

---

## 9. Export de données

NETSCOPE permet d'exporter les données de capture pour analyse externe.

### Export CSV

- **Format** : RFC 4180, compatible Excel et Google Sheets
- **Colonnes** : Timestamp, IP source, IP destination, Ports, Protocole, Score, Blacklist match, Raison
- **Accès** : bouton d'export sur la page de résultats

### Export JSON

- **Format** : RFC 8259, parsable par outils BI
- **Contenu** : métadonnées de capture + liste des anomalies avec contexte complet
- **Structure** : objet racine avec `metadata` et `anomalies`

### Filtrage à l'export

- **Toutes les données** — export complet de la capture
- **Anomalies uniquement** — filtre les entrées avec score > 0 ou blacklist match

### Utilisation avec des outils externes

Les exports sont conçus pour s'intégrer avec :
- **Tableurs** : Excel, Google Sheets, LibreOffice Calc
- **SIEM** : import CSV/JSON standard
- **Outils BI** : Grafana, Power BI, Tableau
- **Scripts** : Python, jq, PowerShell

---

## 10. Administration

La page **Admin** (`/admin/`) affiche les informations système et donne accès à la configuration.

### Informations système

| Champ | Description |
|-------|-------------|
| **Version** | Version actuelle de NETSCOPE (ex: v0.1.0) |
| **Date d'installation** | Date de déploiement du fichier VERSION |
| **Modèle Pi** | Modèle Raspberry Pi détecté automatiquement |
| **Uptime** | Durée de fonctionnement du système |

### Pages d'administration

- **Système** (`/admin/`) — vue d'ensemble
- **Mises à jour** (`/admin/update`) — gestion OTA
- **Configuration** (`/admin/config`) — paramètres avancés

---

## 11. Mises à jour OTA

NETSCOPE supporte les mises à jour Over-The-Air depuis GitHub Releases.

### Vérifier les mises à jour

1. Allez dans **Admin** → **Mises à jour**
2. Cliquez sur **Vérifier les mises à jour**
3. NETSCOPE interroge l'API GitHub et affiche :
   - Version actuelle vs version disponible
   - Changelog résumé
   - Lien vers la release

### Appliquer une mise à jour

1. Cliquez sur **Mettre à jour** quand une nouvelle version est disponible
2. Le processus automatique :
   - **Backup** de la version actuelle (avant le téléchargement)
   - **Téléchargement** de la release depuis GitHub
   - **Extraction** et installation dans `/opt/netscope`
   - **Health check** sur `/api/health` après redémarrage
   - **Rollback automatique** si le health check échoue (délai 30s)

### Suivi du statut

La page de mise à jour affiche en temps réel :
- **Progression** (étape en cours, pourcentage)
- **Succès** ou **échec** avec raison détaillée
- **Historique** des tentatives précédentes

### Sécurité

- Validation du domaine de téléchargement (GitHub uniquement)
- Vérification des symlinks dans l'archive
- Backup conservé pour rollback manuel si nécessaire

---

## 12. Portail captif

En mode sonde Wi-Fi, NETSCOPE inclut un portail captif.

### Fonctionnement

1. Le client se connecte au réseau Wi-Fi de NETSCOPE
2. Toutes les requêtes HTTP sont redirigées vers le portail
3. Le client voit la page d'accueil NETSCOPE avec un bouton **Continuer vers Internet**
4. Après clic, le client est « libéré » et peut naviguer normalement
5. Les règles DNS/iptables sont désactivées globalement

### Compatibilité

Le portail gère automatiquement la détection captive de :
- **Android** (connectivitycheck.gstatic.com)
- **iOS/macOS** (captive.apple.com)
- **Windows** (msftconnecttest.com)
- **Firefox** (detectportal.firefox.com)

---

## 13. API

NETSCOPE expose une API REST minimale.

### Endpoints

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/health` | État du service et version |
| GET | `/api/hardware` | Informations matériel et cibles de performance |
| POST | `/admin/update/check` | Déclencher la vérification de mise à jour |

### Exemple

```bash
curl http://<ip-du-pi>/api/health
```

Réponse :
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

## 14. Dépannage

### L'interface ne se charge pas

- Vérifiez que le service NETSCOPE est lancé : `systemctl status netscope`
- Vérifiez le port 80 : `ss -tlnp | grep 80`
- Consultez les logs : `journalctl -u netscope -f`

### La capture ne démarre pas

- Vérifiez que tcpdump est installé : `which tcpdump`
- Vérifiez les permissions : tcpdump nécessite les droits root ou la capability `cap_net_raw`
- Vérifiez l'interface réseau configurée dans `netscope.yaml`

### Le score de santé affiche N/A

- Aucune capture n'a encore été effectuée
- Lancez une capture depuis le Dashboard

### Les blacklists ne détectent rien

- Vérifiez que les listes contiennent des entrées
- Les entrées en whitelist sont exclues de la détection
- Le rechargement des listes est automatique (hot-reload)

### La mise à jour OTA échoue

- Vérifiez la connexion Internet du Pi
- Vérifiez que le repo GitHub est accessible
- En cas d'échec post-install, le rollback automatique restaure la version précédente
- En dernier recours, reflashez la carte SD

### Mode dégradé activé

- Le Pi manque de ressources (mémoire ou CPU)
- Fermez les applications inutiles
- La reprise est automatique quand les ressources se libèrent
- Consultez `/api/hardware` pour les seuils configurés

---

*NETSCOPE v0.1.0 — Terminal de surveillance réseau pour Raspberry Pi*
*Documentation générée le 2026-05-10*
