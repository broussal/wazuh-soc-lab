#  Guide d'installation - Wazuh SOC Lab

Ce document décrit l'installation complète du lab Wazuh SIEM depuis zéro.

---

##  Prérequis

### Matériel recommandé
- **RAM :** 8 GB minimum
- **CPU :** 4 cores minimum
- **Disque :** 100 GB d'espace libre
- **Hyperviseur :** VMware Workstation (mon choix)/ VirtualBox / ESXi

### Connaissances requises
- Administration Linux de base
- Configuration réseau
- Ligne de commande Windows et PowerShell

---

##  ÉTAPE 1 : Déploiement du Wazuh Manager

### 1.1 Création de la VM Ubuntu

**Spécifications de la VM :**
```
OS        : Ubuntu Server 22.04 LTS
RAM       : 4 GB (8 GB recommandé pour production)
CPU       : 2 vCPUs
Disque    : 60 GB (thin provisioning)
Réseau    : NAT ou Host-Only (192.168.3.0/24)
Nom       : wazuh-manager
IP        : 192.168.3.129 (statique)
```

**Configuration réseau statique :**
```bash
# Éditer la configuration Netplan
sudo nano /etc/netplan/00-installer-config.yaml
```

Contenu :
```yaml
network:
  version: 2
  ethernets:
    ens33:  # Adapter selon votre interface
      dhcp4: no
      addresses:
        - 192.168.3.129/24
      gateway4: 192.168.3.2
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

Appliquer :
```bash
sudo netplan apply
```

### 1.2 Installation du Wazuh All-in-One

**Télécharger et exécuter le script d'installation :**
```bash
# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Installation de curl
sudo apt install curl -y

# Téléchargement du script d'installation
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

# Installation All-in-One (Manager + Indexer + Dashboard)
sudo bash wazuh-install.sh -a
```

⏱ **Durée :** 10-15 minutes

**Sauvegarder les credentials générés !**
```
Username: admin
Password: ********************************
```

**Vérifier l'installation :**
```bash
# Vérifier les services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# Tous doivent être "active (running)"
```

**Accès au Dashboard :**
- URL : `https://192.168.3.129`
- Utilisateur : `admin`
- Mot de passe : celui généré lors de l'installation

 **Certificat auto-signé :** Accepter l'exception de sécurité dans le navigateur.

---

##  ÉTAPE 2 : Déploiement de l'Agent Windows

### 2.1 Création de la VM Windows

**Spécifications de la VM :**
```
OS        : Windows 10 Pro
RAM       : 4 GB
CPU       : 2 vCPUs
Disque    : 40 GB
Réseau    : Même réseau que le manager (192.168.3.0/24)
Nom       : WIN-AGENT-01
IP        : 192.168.3.130
```

**Configuration IP statique (optionnel) :**
```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.3.130 -PrefixLength 24 -DefaultGateway 192.168.3.2
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 8.8.8.8,8.8.4.4
```

### 2.2 Installation de l'Agent Wazuh

**Depuis le Dashboard Wazuh :**
1. Se connecter au Dashboard (`https://192.168.3.129`)
2. Menu **"Agents"** → **"Deploy new agent"**
3. Sélectionner :
   - **OS :** Windows
   - **Server address :** 192.168.3.129
   - **Agent name :** WIN-AGENT-01

**Commande générée (exemple) :**
```powershell
# Télécharger l'agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile ${env:tmp}\wazuh-agent.msi

# Installer avec configuration
msiexec.exe /i ${env:tmp}\wazuh-agent.msi /q WAZUH_MANAGER='192.168.3.129' WAZUH_AGENT_NAME='WIN-AGENT-01'

# Démarrer le service
NET START WazuhSvc
```

**Vérifier l'installation :**
```powershell
# Vérifier le service
Get-Service wazuh

# Vérifier la connexion au manager
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

Rechercher : `Connected to the server`

**Dans le Dashboard Wazuh :**
- Menu **"Agents"** → L'agent doit apparaître avec le status **"Active"**
- Agent ID : **001**

### 2.3 Installation de Sysmon

Sysmon enrichit considérablement la visibilité sur les événements Windows.

**Télécharger Sysmon :**
```powershell
# Télécharger Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Sysmon.zip

# Extraire
Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon

# Télécharger la config SwiftOnSecurity
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Sysmon\sysmonconfig.xml
```

**Installer Sysmon :**
```powershell
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Vérifier :**
```powershell
Get-Service Sysmon64  # Doit être "Running"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

##  ÉTAPE 3 : Configuration avancée

### 3.1 Configuration de l'agent Windows

**Localisation du fichier de configuration :**
```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

 **IMPORTANT :** Utiliser un éditeur qui préserve les line endings Unix (LF), pas CRLF !
-  Recommandé : Notepad++, VSCode, vim
-  À éviter : Notepad Windows (cause des problèmes)

**Éditer le fichier (PowerShell admin) :**
```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

**Configuration recommandée (extrait) :**

```xml
<ossec_config>
  <!-- Configuration du serveur -->
  <client>
    <server>
      <address>192.168.3.129</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <!-- Collecte des logs de sécurité Windows -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <!-- Exclure les événements bruyants -->
    <query>Event/System[EventID != 5145 and EventID != 4662 and EventID != 4688]</query>
  </localfile>

  <!-- Collecte des logs système -->
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Collecte des logs application -->
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Collecte des logs Sysmon -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency> <!-- 12 heures -->
    <directories check_all="yes">C:\Windows\System32</directories>
    <directories check_all="yes">C:\Program Files</directories>
    <directories check_all="yes">C:\Program Files (x86)</directories>
  </syscheck>

  <!-- Security Configuration Assessment -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </sca>
</ossec_config>
```

**Redémarrer l'agent après modification :**
```powershell
Restart-Service wazuh
```

**Si le service ne démarre pas (problème de line endings) :**
```powershell
# Convertir CRLF → LF
$file = "C:\Program Files (x86)\ossec-agent\ossec.conf"
(Get-Content $file -Raw) -replace "`r`n", "`n" | Set-Content $file -NoNewline

# Redémarrer
Restart-Service wazuh
```

### 3.2 Gestion du stockage (Manager)

Si le disque se remplit rapidement, étendre le volume logique LVM.

**Vérifier l'espace disque :**
```bash
df -h
# Si /dev/mapper/ubuntu--vg-ubuntu--lv est plein...
```

**Étendre le volume logique :**
```bash
# Vérifier l'espace disponible
sudo vgdisplay

# Étendre le LV pour utiliser tout l'espace libre
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv

# Redimensionner le filesystem
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv

# Vérifier
df -h  # Doit montrer l'espace augmenté
```

### 3.3 Configuration de la rétention des logs (ISM Policy)

Par défaut, Wazuh conserve les logs indéfiniment. Pour un lab, 14 jours suffisent.

**Créer la politique ISM 14 jours :**
```bash
curl -X PUT "https://localhost:9200/_plugins/_ism/policies/wazuh-14day-retention" \
  -u admin:VOTRE_MOT_DE_PASSE \
  -k \
  -H 'Content-Type: application/json' \
  -d '{
  "policy": {
    "description": "Wazuh 14 day retention policy",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "14d"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": {
      "index_patterns": ["wazuh-alerts-*"],
      "priority": 100
    }
  }
}'
```

**Vérifier la politique :**
```bash
curl -X GET "https://localhost:9200/_plugins/_ism/policies/wazuh-14day-retention" \
  -u admin:VOTRE_MOT_DE_PASSE -k | jq
```

---

##  Vérification de l'installation

### Checklist finale

**Sur le Manager :**
```bash
# Tous les services actifs
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard

# Agent connecté
sudo /var/ossec/bin/agent_control -l
# Doit afficher : ID: 001, Name: WIN-AGENT-01, Status: Active

# Voir les logs en temps réel
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

**Sur l'Agent Windows :**
```powershell
# Service actif
Get-Service wazuh  # Status = Running

# Logs récents
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20

# Sysmon actif
Get-Service Sysmon64  # Status = Running
```

**Dashboard Wazuh :**
1. Connexion à `https://192.168.3.129`
2. Menu **"Agents"** → Agent 001 visible et **Active**
3. Cliquer sur l'agent → Onglet **"Security events"** → Des événements doivent apparaître

---

##  Test de fonctionnement

**Générer un événement de test sur Windows :**
```powershell
# Exécuter des commandes de reconnaissance
whoami
ipconfig
net user
systeminfo
```

**Vérifier la réception dans Wazuh :**
- Dashboard → **"Security events"**
- Filtrer par : `agent.id: 001`
- Les commandes doivent apparaître dans les dernières minutes
- Techniques MITRE détectées : T1087, T1082, T1059.001

---

##  Troubleshooting commun

### Problème : Agent n'apparaît pas dans le Dashboard

**Solution :**
```bash
# Sur le manager
sudo /var/ossec/bin/manage_agents -l  # Lister tous les agents

# Si l'agent n'est pas listé
sudo /var/ossec/bin/manage_agents -a -n WIN-AGENT-01 -i 001

# Sur Windows, vérifier la connexion
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
# Chercher : "Connected to the server"
```

### Problème : Service wazuh ne démarre pas (Windows)

**Cause probable :** Fichier ossec.conf corrompu (line endings)

**Solution :**
```powershell
# Convertir les line endings
$file = "C:\Program Files (x86)\ossec-agent\ossec.conf"
(Get-Content $file -Raw) -replace "`r`n", "`n" | Set-Content $file -NoNewline

# Redémarrer
Restart-Service wazuh
```

### Problème : Aucun événement ne remonte de Sysmon

**Vérifier la collecte :**
```xml
<!-- Dans ossec.conf, vérifier cette section -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Vérifier que Sysmon génère des événements :**
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

---

##  Résultat attendu

À la fin de ce setup, on possède :

-  Manager Wazuh fonctionnel accessible via Dashboard Web
-  Agent Windows connecté et actif
-  Logs Windows (Security, System, Application) collectés
-  Sysmon installé et événements collectés
-  File Integrity Monitoring activé
-  Rétention des logs configurée (14 jours)
-  Environ 100-500 événements par jour générés

**Temps total d'installation :** 2-3 heures
