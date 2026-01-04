# 🛡️ Wazuh SOC Lab - Portfolio Cybersécurité

## 📌 Vue d'ensemble

Ce projet présente un laboratoire SIEM (Security Information and Event Management) basé sur **Wazuh** déployé dans un environnement VMware. Il a été conçu pour démontrer des compétences pratiques en analyse de sécurité de niveau SOC L1, notamment la détection d'attaques alignées sur le framework **MITRE ATT&CK**.

**Objectif :** Développer une expérience pratique en détection, investigation et réponse aux incidents de sécurité dans un environnement contrôlé.

---

## 🎯 Compétences démontrées

- ✅ Déploiement et configuration d'un SIEM (Wazuh)
- ✅ Gestion d'infrastructure Linux (Ubuntu, LVM, systemd)
- ✅ Configuration d'agents de surveillance Windows
- ✅ Collecte et normalisation de logs (Sysmon, Event Logs)
- ✅ Détection d'attaques MITRE ATT&CK
- ✅ Investigation d'alertes de sécurité
- ✅ Gestion du cycle de vie des données (ISM policies)
- ✅ Documentation technique et troubleshooting

---

## 🏗️ Architecture

L'environnement comprend :

- **Wazuh Manager** (Ubuntu 22.04) - All-in-One deployment
  - Wazuh Manager (collecte et analyse)
  - OpenSearch Indexer (stockage des événements)
  - Dashboard Web (visualisation)

- **Agent Windows** (Windows 10 Pro) - Poste de travail supervisé
  - Agent Wazuh
  - Sysmon (monitoring avancé)
  - File Integrity Monitoring (FIM)

- **Réseau :** Réseau isolé 192.168.3.0/24 (VMware)

*Voir [architecture.md](./architecture.md) pour le schéma détaillé.*

---

## 📊 Cas d'usage implémentés

### ✅ Cas 1 : Détection de bruteforce
- **Attaque simulée :** 15 tentatives d'authentification échouées
- **Règle déclenchée :** 60204 - "Multiple Windows Logon Failures" (Level 10)
- **Résultat :** Alerte critique générée et détectée dans le dashboard

### ✅ Cas 2 : Reconnaissance MITRE ATT&CK
- **Techniques détectées :** BOF
  - T1087 - Account Discovery
  - T1082 - System Information Discovery
  - T1057 - Process Discovery
  - T1049 - Network Discovery
  - T1059.001 - PowerShell Execution
- **Volume :** 568+ événements générés

### ✅ Cas 3 : Fichier malveillant suspect (partiel)
- **Règle déclenchée :** 92213 - "Executable file dropped in malware folder" (Level 15)
- **Catégorie :** Command and Control

### 🔄 En cours
- Cas 4 : PowerShell encodé/obfusqué
- Cas 5 : Création de compte administrateur suspect
- Cas 6 : Simulation de phishing

---

## 📁 Structure du projet

```
wazuh-soc-lab/
├── README.md                    # Ce fichier
├── setup.md                     # Guide d'installation détaillé
├── architecture.md              # Schéma et description de l'infrastructure
├── logs-collected.md            # Documentation des logs collectés
├── use-cases/                   # Cas d'usage SOC L1
│   ├── 01-bruteforce-detection.md
│   ├── 02-reconnaissance-mitre.md
│   └── 03-malware-suspected.md
├── threat-hunting/              # Requêtes de hunting (à venir)
└── runbooks/                    # Procédures de réponse (à venir)
```

---

## 🔧 Technologies utilisées

| Composant | Version | Fonction |
|-----------|---------|----------|
| Wazuh | 4.x | SIEM / XDR Platform |
| OpenSearch | Intégré | Indexation et stockage |
| Ubuntu Server | 22.04 LTS | OS du manager |
| Windows 10 | Pro | Agent endpoint |
| Sysmon | Config SwiftOnSecurity | Monitoring avancé Windows |
| VMware Workstation | - | Hyperviseur |

---

## 📈 Métriques du lab

- **Événements collectés :** 2900+ événements indexés
- **Alertes Level ≥10 :** 2+ alertes critiques détectées BOF
- **Techniques MITRE :** 5+ techniques identifiées BOF
- **Rétention des logs :** 14 jours (ISM policy)
- **Taux de disponibilité :** 100% (environnement de lab)

---

## 🧠 Défis techniques résolus

1. **Saturation disque** - Extension LVM à chaud (29GB → 58GB)
2. **Problème de line endings** - Fichier de config corrompu (CRLF → LF)
3. **Gestion de la rétention** - Configuration ISM policy 14 jours
4. **Optimisation des logs** - Filtrage des événements bruyants (EventID 5145)

*Voir [setup.md](./setup.md) pour les détails de résolution.*

---

## 📚 Documentation

- **[setup.md](./setup.md)** - Guide complet d'installation et configuration
- **[architecture.md](./architecture.md)** - Schéma d'infrastructure et flux de données
- **[logs-collected.md](./logs-collected.md)** - Liste exhaustive des sources de logs

---

## 🎓 Apprentissages clés

- Compréhension approfondie du fonctionnement d'un SIEM en production
- Maîtrise de la corrélation d'événements pour la détection d'attaques
- Connaissance pratique du framework MITRE ATT&CK
- Expérience en troubleshooting système Linux et Windows
- Importance de la documentation et des runbooks en SOC

---

## 🚀 Prochaines étapes

- [ ] Implémenter les 3 cas SOC L1 restants
- [ ] Créer des requêtes de threat hunting (LOLBins, persistence)
- [ ] Rédiger des runbooks de réponse aux incidents
- [ ] Ajouter un agent Linux (serveur web avec logs Apache)
- [ ] Intégrer des IOCs (IP/domains malveillants)

---

## 👤 Auteur

**Hector Broussalis**  
Projet réalisé dans le cadre du développement de compétences pratiques en cybersécurité.

---

## 📄 Licence

Ce projet est à usage éducatif et de démonstration de compétences professionnelles.

---

*Dernière mise à jour : Janvier 2025*
