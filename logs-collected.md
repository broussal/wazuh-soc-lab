# 📊 Documentation des Logs Collectés - Wazuh SOC Lab

Ce document liste exhaustivement tous les types de logs collectés par le lab Wazuh et leur utilité pour la détection.

---

## 📋 Vue d'ensemble

### Sources de logs actives

| Source | Type | Volume quotidien | Format | Utilité principale |
|--------|------|------------------|--------|-------------------|
| **Windows Security** | Event Log | ~200-300 événements | XML/JSON | Authentification, accès, modifications |
| **Windows System** | Event Log | ~50-100 événements | XML/JSON | Services, démarrages, erreurs système |
| **Windows Application** | Event Log | ~50-100 événements | XML/JSON | Erreurs applicatives, crashes |
| **Sysmon** | Event Log | ~100-200 événements | XML/JSON | Activité processus granulaire |
| **File Integrity Monitoring** | Wazuh FIM | ~10-20 événements | JSON | Modifications fichiers critiques |
| **Security Config Assessment** | Wazuh SCA | 1 scan/12h | JSON | Compliance et hardening |

**Volume total quotidien :** ~500-700 événements  
**Taille moyenne :** ~1.5-2 MB/jour

---

## 🪟 1. Windows Event Logs

### 1.1 Security Log

**Channel :** `Security`  
**Format :** eventchannel (XML → JSON)  
**Niveau de verbosité :** Moyen (filtré)

#### Configuration actuelle
```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID != 5145 and EventID != 4662 and EventID != 4688]</query>
</localfile>
```

**Événements exclus :**
- **5145 :** Network share object accessed (trop verbeux)
- **4662 :** Operation performed on object (trop verbeux en environnement AD)
- **4688 :** Process creation (déjà collecté par Sysmon Event ID 1)

#### Événements critiques collectés

| Event ID | Nom | Niveau Wazuh | Utilité SOC |
|----------|-----|--------------|-------------|
| **4625** | Logon failure | 5 | Détection bruteforce, compte invalide |
| **4624** | Logon success | 3 | Baseline authentification, anomalies horaires |
| **4672** | Special privileges assigned to new logon | 7 | Élévation privilèges, logon admin |
| **4720** | User account created | 8 | Création compte suspect |
| **4732** | Member added to security-enabled local group | 8 | Ajout à Administrators |
| **4740** | User account locked out | 6 | Account lockout (après bruteforce) |
| **4768** | Kerberos TGT requested | 3 | Détection Pass-the-Ticket |
| **4769** | Kerberos service ticket requested | 3 | Détection Kerberoasting |
| **4776** | NTLM authentication | 5 | Détection NTLM relay |
| **4648** | Logon with explicit credentials (RunAs) | 4 | Lateral movement |

#### Règles Wazuh déclenchées (exemples)

**Règle 60204 :** "Multiple Windows Logon Failures"
- **Trigger :** 5+ Event ID 4625 en 2 minutes
- **Level :** 10 (Critique)
- **MITRE :** T1110 - Brute Force

**Règle 60106 :** "Windows User Successfully Logged in"
- **Trigger :** Event ID 4624 avec Logon Type 10 (RDP)
- **Level :** 3
- **Utilité :** Détection accès RDP hors heures ouvrables

---

### 1.2 System Log

**Channel :** `System`  
**Format :** eventchannel  
**Niveau de verbosité :** Faible

#### Configuration
```xml
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
</localfile>
```

#### Événements clés collectés

| Event ID | Nom | Niveau Wazuh | Utilité SOC |
|----------|-----|--------------|-------------|
| **7045** | Service installed | 7 | Détection persistence via service malveillant |
| **7040** | Service start type changed | 5 | Modification configuration service |
| **1074** | System shutdown initiated | 3 | Audit shutdown (ransomware cleanup) |
| **6005** | Event Log service started | 3 | Reboot système |
| **6006** | Event Log service stopped | 3 | Shutdown anormal |
| **104** | Event log cleared | 12 | Anti-forensics (LOG CLEARING) |

#### Règles Wazuh déclenchées

**Règle 18103 :** "New Service Installed"
- **Trigger :** Event ID 7045
- **Level :** 7
- **MITRE :** T1543.003 - Create or Modify System Process: Windows Service

**Règle 18102 :** "Windows audit log was cleared"
- **Trigger :** Event ID 104
- **Level :** 12
- **MITRE :** T1070.001 - Indicator Removal: Clear Windows Event Logs

---

### 1.3 Application Log

**Channel :** `Application`  
**Format :** eventchannel  
**Niveau de verbosité :** Faible

#### Configuration
```xml
<localfile>
  <location>Application</location>
  <log_format>eventchannel</log_format>
</localfile>
```

#### Événements collectés
- Erreurs applicatives (Event ID 1000, 1001)
- Crashes d'applications (.NET, Office, navigateurs)
- Événements Windows Defender (si activé)
- Installations MSI (Event ID 11707, 11724)

**Utilité SOC :**
- Détection exploits causant crashes répétés
- Corrélation avec alertes antivirus
- Investigation post-incident (timeline)

---

## 🔍 2. Sysmon (Microsoft-Windows-Sysmon/Operational)

**Channel :** `Microsoft-Windows-Sysmon/Operational`  
**Configuration :** SwiftOnSecurity sysmonconfig-export.xml  
**Format :** eventchannel  
**Niveau de verbosité :** Élevé (filtré par config)

#### Configuration agent
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 2.1 Événements Sysmon collectés

#### **Event ID 1 : Process Creation**
**Fréquence :** ~50-100/jour  
**Champs clés :**
- ParentImage (processus parent)
- CommandLine (arguments complets)
- Hashes (SHA256, MD5, IMPHASH)
- User, IntegrityLevel

**Cas d'usage :**
- Détection commandes suspectes (whoami, net user, mimikatz)
- Hunting de LOLBins (rundll32.exe, regsvr32.exe)
- Analyse chaîne de processus (process tree)

**Règles déclenchées :**
- **61603 :** "Windows: Reconnaissance activity detected" (T1087, T1082)
- **92051 :** "Possible Powershell Empire launcher" (T1059.001)

---

#### **Event ID 3 : Network Connection**
**Fréquence :** ~20-50/jour  
**Champs clés :**
- DestinationIp, DestinationPort
- Image (processus initiant la connexion)
- Protocol, Initiated (true/false)

**Cas d'usage :**
- Détection beaconing C2
- Connexions sur ports suspects (4444, 8080, 443 depuis cmd.exe)
- Communication vers IP malveillantes (threat intel)

**Règles déclenchées :**
- **61608 :** "Windows: Suspicious network activity" (port 4444, 5555, etc.)

---

#### **Event ID 7 : Image Loaded (DLL)**
**Fréquence :** ~10-30/jour (filtré par config)  
**Champs clés :**
- ImageLoaded (chemin de la DLL)
- Signed, Signature, SignatureStatus

**Cas d'usage :**
- Détection DLL hijacking
- DLL non signées chargées dans processus critiques
- Injection de code (malware)

---

#### **Event ID 8 : CreateRemoteThread**
**Fréquence :** Rare (~1-5/jour)  
**Utilité :** Détection injection de code inter-processus

**Règles déclenchées :**
- **61611 :** "Possible process injection detected"

---

#### **Event ID 10 : ProcessAccess**
**Fréquence :** Modéré (~10-20/jour)  
**Utilité :** Détection credential dumping (LSASS access)

**Exemples d'alertes :**
- Accès à lsass.exe par processus non-système
- Mimikatz, ProcDump tentant de dumper credentials

---

#### **Event ID 11 : FileCreate**
**Fréquence :** ~20-40/jour (filtré par config)  
**Champs clés :**
- TargetFilename
- CreationUtcTime

**Cas d'usage :**
- Fichiers créés dans %TEMP%, %APPDATA%
- Détection droppers (malware)
- Webshells dans répertoires IIS/Apache

**Règles déclenchées :**
- **92213 :** "Executable file dropped in folder commonly used by malware" (Level 15)

---

#### **Event ID 13 : RegistryEvent (Value Set)**
**Fréquence :** ~10-20/jour  
**Utilité :** Détection persistence via registry

**Clés surveillées :**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\System\CurrentControlSet\Services\`

**Règles déclenchées :**
- **61612 :** "Windows registry modification for persistence"

---

#### **Event ID 22 : DNSEvent (DNS Query)**
**Fréquence :** ~30-50/jour  
**Utilité :** Détection DNS tunneling, C2 beaconing

**Exemples d'alertes :**
- Requêtes vers domaines DGA (Domain Generation Algorithm)
- Résolution de domaines newly registered

---

### 2.2 Avantages de Sysmon vs Event Logs natifs

| Fonctionnalité | Event Logs natifs | Sysmon |
|----------------|-------------------|--------|
| Command line complète | ❌ (4688 limitée) | ✅ Event ID 1 |
| Hashes fichiers | ❌ | ✅ SHA256, MD5, IMPHASH |
| Connexions réseau | ❌ | ✅ Event ID 3 |
| DLL loading | ❌ | ✅ Event ID 7 |
| Process injection | ❌ | ✅ Event ID 8, 10 |
| Registry changes | Partiel | ✅ Event ID 13 |
| DNS queries | ❌ | ✅ Event ID 22 |

**Conclusion :** Sysmon est **essentiel** pour la détection avancée.

---

## 📁 3. File Integrity Monitoring (FIM)

**Type :** Module natif Wazuh  
**Format :** JSON  
**Fréquence de scan :** Toutes les 12 heures (43200 secondes)

### Configuration
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <directories check_all="yes">C:\Windows\System32</directories>
  <directories check_all="yes">C:\Program Files</directories>
  <directories check_all="yes">C:\Program Files (x86)</directories>
</syscheck>
```

### Répertoires surveillés

| Répertoire | Justification | Menaces détectées |
|------------|---------------|-------------------|
| `C:\Windows\System32` | Binaires système critiques | Remplacement de DLL système, rootkits |
| `C:\Program Files` | Applications 64-bit | Backdoors dans logiciels installés |
| `C:\Program Files (x86)` | Applications 32-bit | Trojans dans anciens logiciels |

### Attributs surveillés
- **Hash :** SHA256 (changement = modification)
- **Permissions :** DACL (détection privilege escalation)
- **Owner :** Propriétaire du fichier
- **Size :** Taille (détection ajout de code)
- **Timestamps :** Création, modification, accès

### Événements générés

**Exemple d'alerte FIM :**
```json
{
  "agent": "001",
  "syscheck": {
    "path": "C:\\Windows\\System32\\calc.exe",
    "event": "modified",
    "sha256_after": "abc123...",
    "sha256_before": "def456...",
    "size_after": 835584,
    "size_before": 835584
  },
  "rule": {
    "id": "550",
    "level": 7,
    "description": "Integrity checksum changed"
  }
}
```

**Règle Wazuh associée :**
- **Règle 550 :** "Integrity checksum changed" (Level 7)
- **Règle 553 :** "File deleted" (Level 7)
- **Règle 554 :** "File added to the system" (Level 5)

---

## 🔒 4. Security Configuration Assessment (SCA)

**Type :** Module natif Wazuh  
**Format :** JSON  
**Fréquence de scan :** Toutes les 12 heures + au démarrage

### Configuration
```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
</sca>
```

### Benchmarks appliqués

#### **CIS Microsoft Windows 10 Enterprise Benchmark**
- 200+ checks de configuration
- Catégories : Politiques de compte, audit, services, pare-feu, registre

**Exemples de checks :**
- ✅ "Minimum password length is set to 14 or more characters"
- ❌ "Guest account is enabled" → Finding
- ✅ "Windows Firewall is turned on"

#### **CIS Microsoft Windows 10 Standalone Benchmark**
- Adapté pour postes standalone (non-domaine)

### Résultat du dernier scan
```
Score: 87/100
Passed: 174 checks
Failed: 26 checks
Not applicable: 15 checks
```

**Findings critiques (exemples) :**
- Compte Guest activé
- RDP autorisé sans restriction IP
- Windows Update désactivé

**Utilité SOC :**
- Identifier vulnérabilités de configuration
- Prioriser le hardening
- Compliance PCI-DSS, ISO 27001

---

## 📊 5. Statistiques et volumes

### 5.1 Répartition des logs (7 derniers jours)

| Source | Événements | % du total | Taille |
|--------|------------|-----------|--------|
| Windows Security | 1650 | 55% | 4.5 MB |
| Sysmon | 980 | 33% | 3.2 MB |
| Windows System | 220 | 7% | 0.6 MB |
| Windows Application | 110 | 4% | 0.3 MB |
| FIM | 32 | 1% | 0.1 MB |
| **Total** | **2992** | **100%** | **8.7 MB** |

### 5.2 Top 10 Event IDs collectés

| Rang | Event ID | Source | Nom | Count |
|------|----------|--------|-----|-------|
| 1 | 4624 | Security | Successful Logon | 485 |
| 2 | 1 | Sysmon | Process Creation | 312 |
| 3 | 4634 | Security | Logoff | 401 |
| 4 | 3 | Sysmon | Network Connection | 187 |
| 5 | 4672 | Security | Special Privileges Assigned | 156 |
| 6 | 5158 | Security | Filtering Platform Connection | 98 |
| 7 | 11 | Sysmon | File Created | 89 |
| 8 | 7045 | System | Service Installed | 12 |
| 9 | 13 | Sysmon | Registry Set Value | 76 |
| 10 | 4625 | Security | Logon Failure | 23 |

---

## 🎯 6. Mapping MITRE ATT&CK

### Techniques détectées automatiquement

| Technique | Nom | Source | Règle Wazuh |
|-----------|-----|--------|-------------|
| **T1087** | Account Discovery | Sysmon EID 1 | 61603 |
| **T1082** | System Information Discovery | Sysmon EID 1 | 61603 |
| **T1057** | Process Discovery | Sysmon EID 1 | 61603 |
| **T1049** | Network Discovery | Sysmon EID 1 | 61603 |
| **T1059.001** | PowerShell Execution | Sysmon EID 1 | 91816 |
| **T1110** | Brute Force | Security 4625 | 60204 |
| **T1543.003** | Windows Service | System 7045 | 18103 |
| **T1070.001** | Clear Event Logs | System 104 | 18102 |
| **T1055** | Process Injection | Sysmon EID 8 | 61611 |

---

## 🔧 7. Optimisation de la collecte

### Événements volontairement exclus

**Trop verbeux (bruit) :**
- Security Event ID 5145 (Network shares)
- Security Event ID 4662 (Object access AD)
- Security Event ID 4688 (doublons avec Sysmon)

**Stratégie `logall=no` :**
- Seuls les événements matchant une règle Wazuh sont envoyés
- Réduit la bande passante de 70%
- Recommandé pour environnements production

### Événements à ajouter (évolutions futures)

**PowerShell Logging (Event ID 4104) :**
```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=4104]</query>
</localfile>
```
**Utilité :** Détection scripts PowerShell obfusqués

**Windows Defender (Event ID 1116, 1117) :**
```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
**Utilité :** Corrélation avec alertes antivirus

---

## 📚 Ressources

- [Windows Event ID Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Sysmon Configuration Guide](https://github.com/SwiftOnSecurity/sysmon-config)
- [Wazuh Ruleset Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/)
- [MITRE ATT&CK Matrix](https://attack.mitre.org/)

---

*Documentation mise à jour : Janvier 2025*
