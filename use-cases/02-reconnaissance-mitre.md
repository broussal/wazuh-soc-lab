# Cas SOC #2 : Reconnaissance et Discovery MITRE ATT&CK

## 📋 Résumé exécutif

**Type d'incident :** Activité de reconnaissance système  
**Sévérité :** 🟡 Notable (Level 3-5)  
**Statut :** Détecté par le SIEM  
**Vecteur d'attaque :** Commandes de discovery exécutées localement  
**Cible :** Système WIN-AGENT-01  
**Résultat :** Collecte d'informations système réussie (simulation)

> **📝 Note :** Ce cas simule les actions qu'un attaquant effectue après avoir obtenu un accès initial à un système Windows, afin de cartographier l'environnement avant de poursuivre son attaque.

---

## 🎯 MITRE ATT&CK Framework

| Technique | ID | Tactique | Description |
|-----------|----|---------|----|
| **Account Discovery** | T1087 | Discovery | Énumération des comptes utilisateurs |
| **System Information Discovery** | T1082 | Discovery | Collecte d'informations système |
| **Process Discovery** | T1057 | Discovery | Liste des processus en cours |
| **System Network Configuration Discovery** | T1016 | Discovery | Configuration réseau du système |
| **System Network Connections Discovery** | T1049 | Discovery | Connexions réseau actives |
| **Command and Scripting Interpreter: PowerShell** | T1059.001 | Execution | Utilisation de PowerShell |

**Kill Chain Phase :** Reconnaissance (post-exploitation)

---

## 📅 Timeline de l'incident

```
[2026-01-03 15:45:00] Début de la phase de reconnaissance
[2026-01-03 15:45:02] Commande 1 : whoami (Account Discovery)
[2026-01-03 15:45:05] Commande 2 : ipconfig /all (Network Config Discovery)
[2026-01-03 15:45:10] Commande 3 : net user (Account Discovery)
[2026-01-03 15:45:15] Commande 4 : net localgroup administrators (Privileged Account Discovery)
[2026-01-03 15:45:22] Commande 5 : systeminfo (System Information Discovery)
[2026-01-03 15:45:30] Commande 6 : tasklist (Process Discovery)
[2026-01-03 15:45:38] Commande 7 : netstat -ano (Network Connections Discovery)
[2026-01-03 15:45:45] Commande 8 : arp -a (Network Discovery)
[2026-01-03 15:45:52] Commande 9 : wmic process get name,processid,parentprocessid (Process Discovery via WMI)
[2026-01-03 15:46:00] ⚠️ ALERTES WAZUH - Reconnaissance activity detected
[2026-01-03 15:46:02] Fin de la phase de reconnaissance
```

**Durée totale :** ~2 minutes  
**Événements générés :** 568 événements Sysmon + Windows Event Logs

---

## 🧪 Simulation de l'attaque

### Contexte

Après avoir compromis un compte utilisateur (phishing, vulnérabilité exploitée), l'attaquant effectue une **reconnaissance système** pour :
- Identifier son niveau de privilèges actuel
- Cartographier les comptes administrateurs (cibles d'escalade)
- Comprendre la configuration réseau (lateral movement)
- Lister les processus (AV/EDR détection, persistence)

### Script de reconnaissance exécuté

**Via PowerShell ou CMD :**

```powershell
# Phase de reconnaissance post-exploitation
# Simulation d'un attaquant collectant des informations système

Write-Host "[*] Starting reconnaissance..." -ForegroundColor Yellow

# 1. Identifier le contexte actuel
Write-Host "[+] Current user context:" -ForegroundColor Cyan
whoami
whoami /priv
whoami /groups

# 2. Énumération des comptes
Write-Host "`n[+] User enumeration:" -ForegroundColor Cyan
net user
net localgroup administrators
net localgroup users

# 3. Informations système
Write-Host "`n[+] System information:" -ForegroundColor Cyan
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
hostname

# 4. Configuration réseau
Write-Host "`n[+] Network configuration:" -ForegroundColor Cyan
ipconfig /all
route print

# 5. Connexions réseau actives
Write-Host "`n[+] Active network connections:" -ForegroundColor Cyan
netstat -ano

# 6. Table ARP (machines voisines)
Write-Host "`n[+] ARP table:" -ForegroundColor Cyan
arp -a

# 7. Processus en cours d'exécution
Write-Host "`n[+] Running processes:" -ForegroundColor Cyan
tasklist /v

# 8. Découverte via WMI
Write-Host "`n[+] Process discovery via WMI:" -ForegroundColor Cyan
wmic process get name,processid,parentprocessid,executablepath

# 9. Services installés
Write-Host "`n[+] Installed services:" -ForegroundColor Cyan
wmic service get name,displayname,pathname,startmode | findstr /i "auto"

Write-Host "`n[*] Reconnaissance complete." -ForegroundColor Green
```

### Résultat de l'exécution

**Informations collectées par l'attaquant :**

```
✅ Compte actuel : WIN-AGENT-01\hbw (Administrateur local)
✅ OS : Windows 10 Pro
✅ Processeur : x64
✅ Antivirus : Windows Defender (actif)
✅ IP : 192.168.3.130
✅ Gateway : 192.168.3.2
✅ Machines réseau : 192.168.3.1, 192.168.3.129 (Wazuh Manager)
✅ Connexions actives : RDP, DNS, HTTP
✅ Processus critiques : svchost.exe, lsass.exe, etc.
✅ Services auto-start : 47 services identifiés
```

**L'attaquant dispose maintenant d'une carte complète du système.**

---

## 🚨 Détection Wazuh

### Alertes générées

**Règle principale déclenchée :** `61603 - Windows: Reconnaissance activity detected`

```json
{
  "rule": {
    "id": "61603",
    "level": 5,
    "description": "Windows: Reconnaissance activity detected",
    "groups": ["windows", "reconnaissance"],
    "mitre": {
      "id": ["T1087", "T1082"],
      "technique": ["Account Discovery", "System Information Discovery"],
      "tactic": ["Discovery"]
    }
  },
  "agent": {
    "id": "001",
    "name": "WIN-AGENT-01",
    "ip": "192.168.3.130"
  },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "whoami",
        "user": "WIN-AGENT-01\\hbw",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      }
    }
  },
  "timestamp": "2026-01-03T15:45:02.145Z"
}
```

### Événements Sysmon corrélés

**Event ID 1 - Process Creation** (multiples occurrences)

Processus détectés :
- `cmd.exe` exécutant `whoami`, `net user`, `systeminfo`
- `ipconfig.exe` avec arguments `/all`
- `netstat.exe` avec arguments `-ano`
- `arp.exe` avec arguments `-a`
- `tasklist.exe` avec arguments `/v`
- `wmic.exe` avec multiples requêtes WMI

**Extrait des logs Sysmon (Event ID 1) :**

```xml
<Event>
  <EventData>
    <Data Name="Image">C:\Windows\System32\whoami.exe</Data>
    <Data Name="CommandLine">whoami</Data>
    <Data Name="User">WIN-AGENT-01\hbw</Data>
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="ParentCommandLine">"C:\Windows\system32\cmd.exe"</Data>
  </EventData>
</Event>
```

**Volume d'événements :**

| Source | Event ID | Count | Description |
|--------|----------|-------|-------------|
| Sysmon | 1 | 245 | Process Creation (chaque commande + sous-processus) |
| Sysmon | 3 | 87 | Network Connection (ipconfig, netstat, arp) |
| Sysmon | 10 | 12 | ProcessAccess (WMIC accédant à d'autres processus) |
| Security | 4688 | 124 | Process Creation (audit Windows) |
| Security | 4689 | 100 | Process Termination |
| **Total** | - | **568** | Événements générés en 2 minutes |

---

## 🔍 Investigation SOC L1

### Étape 1 : Qualification de l'alerte

✅ **Alerte confirmée comme vraie positive**

**Critères de validation :**
- ✅ Pattern suspect : Multiples commandes de discovery en succession rapide
- ✅ Commandes typiques d'attaquant : whoami, net user, systeminfo, netstat
- ✅ Séquence logique : Account → System → Network → Process discovery
- ✅ Aucune tâche légitime ne justifie cette séquence

**Comportement attendu vs observé :**

| Utilisateur normal | Attaquant (observé) |
|-------------------|---------------------|
| Commandes occasionnelles | Commandes en rafale (9 commandes en 2 min) |
| Via GUI principalement | Via CLI exclusivement |
| Actions sporadiques | Séquence méthodique |
| Pas de WMIC process | Utilisation de WMIC |

### Étape 2 : Analyse de contexte

**Questions d'investigation :**

| Question | Réponse | Analyse |
|----------|---------|---------|
| Qui a exécuté les commandes ? | Compte hbw (admin local) | Compte privilégié compromis |
| Où ? | WIN-AGENT-01 (localhost) | Poste de travail compromis |
| Quand ? | 15:45 - Heures ouvrables | Pas d'anomalie horaire flagrante |
| Processus parent ? | PowerShell / CMD | Shell interactif (présence humaine ou script) |
| Utilisateur connecté ? | Oui, session active | Accès initial déjà obtenu |
| Autres activités suspectes ? | À investiguer | Vérifier avant/après |

**Hypothèse :** Attaquant ayant compromis le compte `hbw` (phishing, malware) et effectuant une reconnaissance système avant de progresser vers des objectifs secondaires (lateral movement, data exfiltration).

### Étape 3 : Identification des techniques MITRE

**Mapping ATT&CK des commandes détectées :**

| Commande | Technique MITRE | ID | Informations obtenues |
|----------|-----------------|----|-----------------------|
| `whoami` | Account Discovery | T1087.001 | Compte actuel + groupes |
| `whoami /priv` | Account Discovery | T1087.001 | Privilèges du compte |
| `net user` | Account Discovery | T1087.001 | Liste des comptes locaux |
| `net localgroup administrators` | Permission Groups Discovery | T1069.001 | Membres du groupe Admins |
| `systeminfo` | System Information Discovery | T1082 | OS, version, patches |
| `hostname` | System Information Discovery | T1082 | Nom de la machine |
| `ipconfig /all` | System Network Configuration Discovery | T1016 | Adresses IP, DNS, Gateway |
| `route print` | System Network Configuration Discovery | T1016 | Tables de routage |
| `netstat -ano` | System Network Connections Discovery | T1049 | Connexions actives, ports |
| `arp -a` | Remote System Discovery | T1018 | Machines voisines sur le réseau |
| `tasklist` | Process Discovery | T1057 | Processus en cours (AV/EDR) |
| `wmic process` | Process Discovery (WMI) | T1057 | Processus via WMI |
| `wmic service` | System Services Discovery | T1007 | Services Windows |

**6 techniques MITRE détectées couvrant la phase Discovery complète.**

### Étape 4 : Timeline enrichie et Kill Chain

```
[Phase 1 - Initial Access] (Non observé dans ce cas)
└─> Compromission compte hbw (phishing probable)

[Phase 2 - Discovery] ✅ DÉTECTÉ (ce cas)
├─> T1087 - Account Discovery (whoami, net user)
├─> T1082 - System Information Discovery (systeminfo)
├─> T1016 - Network Config Discovery (ipconfig, route)
├─> T1049 - Network Connections Discovery (netstat)
├─> T1057 - Process Discovery (tasklist, wmic)
└─> T1018 - Remote System Discovery (arp -a)

[Phase 3 - Lateral Movement] (Probable prochaine étape)
└─> Cible identifiée : 192.168.3.129 (Wazuh Manager)

[Phase 4 - Collection / Exfiltration] (Non encore observé)
└─> Objectif probable : Vol de données ou ransomware
```

**L'attaquant est à la phase 2 sur 7 de la Kill Chain.**

### Étape 5 : Collecte d'IOCs

**Indicateurs de compromission :**

```yaml
# Compte compromis
- Type: User Account
  Value: hbw
  Context: Exécution de commandes de reconnaissance
  
# Processus suspects
- Type: Process
  Value: cmd.exe, powershell.exe
  Context: Lancement rapide de multiples binaires LOLBins
  
# Commandes exécutées
- Type: Command Line
  Values:
    - whoami
    - net user
    - net localgroup administrators
    - systeminfo
    - ipconfig /all
    - netstat -ano
    - arp -a
    - tasklist /v
    - wmic process get name,processid,parentprocessid
  Context: Séquence typique de reconnaissance post-exploitation
  
# Timestamp
- Type: Temporal
  Value: 2026-01-03 15:45:00 - 15:46:02
  Context: Fenêtre d'activité suspecte de 2 minutes
```

### Étape 6 : Requêtes d'investigation

**Recherche d'activité avant/après la reconnaissance :**

```
Dashboard Wazuh > Discover > Requêtes DQL :

1. Activité du compte hbw dans les 2 heures précédant la reconnaissance :
   agent.id: "001" AND data.win.eventdata.user: "*hbw*" 
   AND @timestamp >= "2026-01-03T13:45:00" AND @timestamp <= "2026-01-03T15:45:00"

2. Connexions réseau suspectes après la reconnaissance :
   agent.id: "001" AND rule.mitre.id: "T1049" OR rule.mitre.id: "T1021"
   AND @timestamp >= "2026-01-03T15:46:00"

3. Tentatives de lateral movement :
   rule.mitre.id: "T1021*" AND agent.id: "001"

4. Création de fichiers suspects (data staging) :
   rule.mitre.id: "T1074" AND agent.id: "001"

5. Toutes les techniques Discovery détectées :
   rule.mitre.tactic: "Discovery" AND agent.id: "001"
```

**Résultat :** Investigation complète pour identifier :
- ✅ Vecteur d'accès initial (avant 15:45)
- ✅ Actions post-reconnaissance (après 15:46)
- ✅ Propagation potentielle (autres machines)

---

## ✅ Réponse et recommandations

### Actions immédiates (en environnement production)

**🔴 Confinement urgent :**
1. **Isoler WIN-AGENT-01 du réseau**
   ```powershell
   # Bloquer toutes communications réseau sauf vers le SIEM
   New-NetFirewallRule -DisplayName "Incident Response - Block All" `
     -Direction Outbound -Action Block -Enabled True
   ```

2. **Suspendre le compte hbw**
   ```powershell
   Disable-LocalUser -Name "hbw"
   ```

3. **Tuer les sessions actives**
   ```powershell
   query session
   logoff <SESSION_ID>
   ```

**🟡 Investigation approfondie :**
1. Capturer la mémoire RAM (Volatility, FTK Imager)
2. Dump du disque pour forensics
3. Analyser les événements 24h avant l'incident
4. Vérifier les autres postes du réseau (192.168.3.x)

**🟢 Éradication :**
1. Scanner avec antivirus offline (Kaspersky Rescue Disk)
2. Vérifier persistence mechanisms :
   - Registry Run keys
   - Scheduled tasks
   - Services
   - Startup folder
3. Réinitialiser le mot de passe hbw
4. Réinstaller le système si malware persistant détecté

### Recommandations long terme

**1. Détection améliorée**

**Créer une règle de corrélation custom :**
```xml
<!-- Règle custom : Détection reconnaissance rapide -->
<rule id="100001" level="8">
  <if_matched_sid>61603</if_matched_sid>
  <same_user />
  <timeframe>120</timeframe>  <!-- 2 minutes -->
  <frequency>5</frequency>     <!-- 5+ commandes -->
  <description>Suspicious reconnaissance activity: Multiple discovery commands in short time</description>
  <mitre>
    <id>T1087</id>
    <id>T1082</id>
  </mitre>
</rule>
```

**2. Monitoring comportemental**

Créer des baselines pour détecter des anomalies :
- Fréquence normale de commandes CLI par utilisateur/heure
- Commandes typiques vs atypiques par profil utilisateur
- Alerter sur combinaisons suspectes (whoami + net user + systeminfo en < 5 min)

**3. Hardening Windows**

**Activer PowerShell Script Block Logging :**
```powershell
# Via GPO ou registre
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1
```

**Activer Command Line Auditing :**
```powershell
# Audit toutes les commandes avec arguments complets
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

**Restreindre WMIC pour utilisateurs standards :**
```
# Via GPO : Bloquer l'exécution de wmic.exe sauf pour les admins
```

**4. EDR / Application Whitelisting**

- Déployer un EDR (CrowdStrike, SentinelOne, Defender ATP)
- Application Control : Bloquer exécution de scripts PowerShell non signés
- Privilège Access Management : Limiter les comptes admin permanents

**5. Sensibilisation utilisateurs**

- Formation anti-phishing (vecteur d'accès initial probable)
- Politique "Least Privilege" : Pas d'admin quotidien
- MFA obligatoire pour tous les comptes

---

## 📊 Résultat et conclusion

### Bilan de l'incident

| Indicateur | Valeur |
|------------|--------|
| **Temps de détection (TTD)** | < 30 secondes (corrélation Wazuh) |
| **Temps de qualification** | 10 minutes |
| **Phase de l'attaque détectée** | Discovery (Phase 2/7) |
| **Techniques MITRE identifiées** | 6 techniques |
| **Événements analysés** | 568 événements |
| **Impact** | ⚠️ Reconnaissance réussie (informations collectées) |
| **Escalade** | ❌ Aucune (détecté avant lateral movement) |

### Leçons apprises

✅ **Points forts :**
- Sysmon Event ID 1 capture les commandes avec arguments complets
- Wazuh corrèle automatiquement les événements de reconnaissance
- Mapping MITRE ATT&CK facilite la compréhension de la phase d'attaque
- Détection rapide (< 1 minute) permet une intervention précoce

⚠️ **Points d'amélioration :**
- Pas d'alerte immédiate Level 10+ pour reconnaissance (seulement Level 5)
- Pas d'Active Response automatique (isolation réseau)
- PowerShell Script Block Logging désactivé (logs incomplets)
- Aucune baseline comportementale (difficulté à différencier admin légitime vs attaquant)

### Scénario en environnement réel

**Sans détection SIEM, l'attaquant aurait pu :**
1. ✅ Identifier les comptes administrateurs (net localgroup administrators)
2. ✅ Cartographier le réseau (arp -a → 192.168.3.129 identifié)
3. ⚠️ Tenter un lateral movement vers le Wazuh Manager
4. ⚠️ Installer un backdoor persistant
5. ⚠️ Exfiltrer des données sensibles
6. ⚠️ Déployer un ransomware

**Grâce à Wazuh, l'attaque a été détectée avant ces phases critiques.**

---

## 📚 Références

- **MITRE ATT&CK :** [TA0007 - Discovery](https://attack.mitre.org/tactics/TA0007/)
- **T1087 :** [Account Discovery](https://attack.mitre.org/techniques/T1087/)
- **T1082 :** [System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- **T1057 :** [Process Discovery](https://attack.mitre.org/techniques/T1057/)
- **Sysmon :** [Event ID 1 - Process Creation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **Wazuh :** [Rule 61603 - Reconnaissance Detection](https://documentation.wazuh.com/current/user-manual/ruleset/)

---

**📅 Incident simulé le :** 3 janvier 2026  
**👤 Analyste :** Portfolio SOC Lab  
**⏱️ Durée d'investigation :** 30 minutes  
**✅ Statut final :** Incident clos - Simulation lab (reconnaissance détectée avec succès)

---

*Ce cas démontre la capacité de Wazuh + Sysmon à détecter les phases de reconnaissance post-exploitation et l'importance du mapping MITRE ATT&CK pour comprendre la progression d'une attaque.*
