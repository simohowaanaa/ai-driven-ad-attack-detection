# 🛡️ Détection d'attaques Active Directory par IA — PFA SOC Dataprotect

> **Projet de Fin d'Année** — Stage au **Security Operations Center (SOC)** de **Dataprotect** (Business Unit Security Intelligence).

Chaîne complète de détection d'attaques Active Directory : documentation théorique, lab isolé, SIEM Wazuh avec règles sur-mesure, et agent IA de détection comportementale.

**Binôme :** Maimouni Mohammed & Chafak Othmane · **Encadrant :** Benkirane Abbes

---

## 🎯 Objectifs

1. **Documenter** les 48 principales attaques Active Directory (MITRE ATT&CK, Event IDs, règles Sigma, remédiation)
2. **Simuler** ces attaques dans un lab isolé (GOAD-Light sur Azure) et générer les logs
3. **Détecter** avec Wazuh : règles natives + 7 règles sur-mesure couvrant les angles morts
4. **Automatiser** avec un agent IA (Isolation Forest) pour les attaques sans signature fixe

---

## 📊 État d'avancement

| Phase | Description | Statut |
|:-----:|-------------|:------:|
| **1** | Documentation de **48 attaques AD** | ✅ Terminé |
| **2** | Lab **GOAD-Light** sur Azure (virtualisation imbriquée) | ✅ Terminé |
| **3** | SIEM **Wazuh** + agents sur 3 machines | ✅ Terminé |
| **4** | Simulation de **12 attaques** + vérification détection | ✅ Terminé |
| **5** | **7 règles Wazuh custom** (angles morts couverts) | ✅ Terminé |
| **6** | **Agent IA** Isolation Forest — 4 anomalies détectées/23 comptes | ✅ Terminé |

---

## 🗂️ Structure du dépôt

```
.
├── docs/               ← Phase 1 : 48 fiches d'attaques AD (théorie + détection)
├── simulation/         ← Phases 2-4 : lab, attaques simulées
│   ├── attaques/       ← 12 playbooks d'attaques (commandes + captures)
│   ├── scripts/        ← scripts shell (déploiement Azure, Wazuh)
│   └── screenshots/    ← Captures du lab et des attaques
├── detection/          ← Phases 5-6 : règles Wazuh custom + agent IA
└── rapports/           ← Rapports d'avancement
```

---

## 🔗 Points d'entrée

| | Lien | Description |
|-|------|-------------|
| 📚 | [Catalogue des 48 attaques](docs/README.md) | Index complet par phase MITRE ATT&CK |
| 🏗️ | [Déploiement du lab Azure](simulation/01-deploiement-azure.md) | GOAD-Light + VirtualBox + Vagrant |
| 🛡️ | [Installation Wazuh](simulation/02-siem-wazuh.md) | SIEM + 3 agents Windows |
| ⚔️ | [Simulation des attaques](simulation/03-attaques.md) | 12 attaques rejouées + détection |
| 🔍 | [Règles custom Phase 5](detection/01-regles-wazuh.md) | 7 règles Wazuh (DCSync, Kerberoasting, ADCS, MSSQL, PtH…) |
| 🤖 | [Agent IA Phase 6](detection/02-agent-ia.md) | Isolation Forest — Golden Ticket, PtH furtif |
| 📊 | [Spectre de détection](simulation/spectre-detection.md) | Synthèse : détectés / angles morts / Phase 6 |
| 🗺️ | [Mapping MITRE ATT&CK](simulation/mitre-mapping.md) | Vue matricielle des 12 attaques |
| 📖 | [Glossaire](simulation/glossaire.md) | AD, Kerberos, Wazuh |
| 📄 | [Rapport d'avancement (08/2026)](rapports/rapport-avancement-2026-08-04.pdf) | Rapport superviseur |

---

## 🔥 Attaques simulées & détection (Phase 4 + 5)

| # | Attaque | MITRE | Phase 4 | Phase 5 |
|---|---------|-------|---------|---------|
| 01 | [Kerberoasting](simulation/attaques/01-kerberoasting.md) | T1558.003 | ✅ Détecté (connexion attaquant) | ✅ Règle 100011 (RC4 0x17) |
| 02 | [AS-REP Roasting](simulation/attaques/02-asrep-roasting.md) | T1558.004 | ⚠️ Angle mort | ✅ Règle 100014 (preAuthType=0) |
| 03 | [Énumération LDAP](simulation/attaques/03-enumeration.md) | T1087.002 | 🔴 Angle mort | ⚠️ Non couvrable (SACLs objet requis) → Phase 6 |
| 04 | [LLMNR Poisoning](simulation/attaques/04-llmnr-poisoning.md) | T1557.001 | 🔴 Angle mort | ⚠️ Non couvrable (attaque réseau pure) |
| 05 | [Password Spraying](simulation/attaques/05-password-spraying.md) | T1110.003 | ✅ Détecté (rafale 4625) | — |
| 06 | [DCSync](simulation/attaques/06-dcsync.md) | T1003.006 | ⚠️ Angle mort critique | ✅ Règle 100010 (Event 4662) |
| 07 | [Abus d'ACL](simulation/attaques/07-acl-abuse.md) | T1222.001 | ✅ Détecté (Event 4728) | — |
| 08 | [ADCS ESC1](simulation/attaques/08-adcs-esc1.md) | T1649 | 🔴 Angle mort critique | ✅ Règle 100012 (Event 4887) |
| 09 | [Pass-the-Hash](simulation/attaques/09-pass-the-hash.md) | T1550.002 | 🟡 Partielle | ✅ Règle 100017 (NTLM type 3) + Phase 6 |
| 10 | [MSSQL RCE (xp_cmdshell)](simulation/attaques/10-mssql-rce.md) | T1210 | 🔴 Angle mort | ✅ Règle 100013 (parentProcess=sqlservr.exe) |
| 11 | [Golden Ticket](simulation/attaques/11-golden-ticket.md) | T1558.001 | 🟡 Partielle | ✅ Phase 6 (tgs_without_tgt=610) |
| 12 | [Trust inter-domaine](simulation/attaques/12-trust-inter-domaine.md) | T1482 | 🟡 Partielle | ✅ Règle 100019 (NTLM NORTH cross-domain) |

---

## 🛠️ Stack technique

- **Lab AD :** GOAD-Light (Orange Cyberdefense), VirtualBox, Vagrant/Ansible
- **Infrastructure :** Microsoft Azure (VM Linux, virtualisation imbriquée)
- **SIEM :** Wazuh (indexer + manager + dashboard), règles custom SOC
- **Outils d'attaque :** impacket, NetExec, Responder
- **Agent IA :** scikit-learn (Isolation Forest), pandas, numpy
- **Référentiel :** MITRE ATT&CK · Windows Event Logs

---

## ⚠️ Cadre éthique

Toutes les attaques sont réalisées **exclusivement** dans un lab **isolé et volontairement vulnérable** (GOAD), à des fins de recherche défensive. **Aucune** de ces techniques ne doit être utilisée sur un système réel sans autorisation explicite.
