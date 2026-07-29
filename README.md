# 🛡️ Détection d'attaques Active Directory par IA — Projet SOC

> **Projet de Fin d'Année (PFA)** — Stage au **Security Operations Center (SOC)** de **Dataprotect** (Business Unit Security Intelligence).

Concevoir une chaîne complète de **détection d'attaques Active Directory** : documenter les techniques, les rejouer dans un lab contrôlé, vérifier leur détection par un SIEM, puis construire un **agent IA** de détection au niveau du contrôleur de domaine.

**Binôme :** Maimouni Mohammed & Chafak Othmane · **Encadrant Dataprotect :** Benkirane Abbes

---

## 🎯 Objectifs
1. **Documenter** les principales attaques Active Directory (reconnaissance, vol d'identifiants, escalade de privilèges, mouvement latéral, persistance, trusts).
2. **Simuler** ces attaques dans un lab isolé et générer les logs correspondants.
3. **Détecter** les attaques via un SIEM (Wazuh) et des règles adaptées.
4. **Automatiser** la détection avec un **agent IA** (ML / détection d'anomalies).

---

## 📊 État d'avancement

| Phase | Description | Statut |
|:-----:|-------------|:------:|
| **1** | Documentation de **48 attaques AD** (MITRE ATT&CK, Event IDs, règles Sigma/QRadar/Elastic, remédiation) | ✅ **Terminé** |
| **2** | Déploiement du lab **GOAD-Light** (AD vulnérable) sur une VM **Azure** | ✅ **Terminé** |
| **3** | Installation du SIEM **Wazuh** + agents sur les 3 machines (collecte des logs) | ✅ **Terminé** |
| **4** | **Simulation des attaques** (12 attaques) + vérification de la détection Wazuh | ✅ **Terminé** |
| **5** | Écriture de **règles de détection sur-mesure** | 🔄 **En cours** |
| **6** | **Agent IA** de détection (ML / anomalies) | ⬜ À venir |

---

## 🧩 Structure du dépôt

| Dossier | Contenu |
|---------|---------|
| [`docs/`](docs/) | 📚 **Documentation des 48 attaques AD** — une fiche par attaque (théorie, MITRE, Event IDs, règles de détection, remédiation), classées par phase d'attaque |
| [`simulation/`](simulation/) | 🧪 **Lab & simulations** — déploiement (GOAD sur Azure), installation Wazuh, et **fiches d'attaques rejouées** avec captures (attaque + détection) |

**Points d'entrée utiles :**
- 🗺️ [Catalogue des 48 attaques](docs/README.md)
- 🏗️ [Guide de déploiement du lab (Azure)](simulation/01-deploiement-azure.md)
- 🛡️ [Installation du SIEM Wazuh](simulation/02-siem-wazuh.md)
- ⚔️ [Simulation des attaques & détection](simulation/03-attaques.md)
- 🛡️ [Phase 5 — Audits & règles de détection](simulation/04-detection-avancee.md)

---

## 🔥 Attaques déjà simulées & analysées (Phase 4)

| # | Attaque | MITRE | Détection Wazuh |
|---|---------|-------|-----------------|
| 01 | [Kerberoasting](simulation/attaques/01-kerberoasting.md) | T1558.003 | ✅ Détecté (connexion attaquant, alerte niveau 6) |
| 02 | [AS-REP Roasting](simulation/attaques/02-asrep-roasting.md) | T1558.004 | ⚠️ Angle mort identifié (audit à configurer) → justifie la Phase 5 |
| 03 | [Énumération](simulation/attaques/03-enumeration.md) | T1087.002 | 🔴 Angle mort (recon LDAP furtive) |
| 04 | [LLMNR/NBT-NS Poisoning](simulation/attaques/04-llmnr-poisoning.md) | T1557.001 | 🔴 Angle mort (empoisonnement réseau) → crack NTLMv1 = `sexywolfy` |
| 05 | [Password Spraying](simulation/attaques/05-password-spraying.md) | T1110.003 | ✅ **Détecté** (rafale de 4625) — l'attaque témoin qui marche |
| 06 | [DCSync](simulation/attaques/06-dcsync.md) | T1003.006 | ⚠️ Angle mort **critique** (compromission totale invisible) → justifie la Phase 5 |
| 07 | [Abus d'ACL](simulation/attaques/07-acl-abuse.md) | T1222.001 | 🟢 **Détecté** (Event 4728 — ajout à Domain Admins) — 2ᵉ cas de détection |
| 08 | [ADCS ESC1](simulation/attaques/08-adcs-esc1.md) | T1649 | 🔴 Angle mort **critique** (Domain User → Enterprise Admin, 100% silencieux) |
| 09 | [Pass-the-Hash](simulation/attaques/09-pass-the-hash.md) | T1550.002 | 🟡 Partielle (connexions vues mais non alertées) → baselining / IA (Phase 6) |
| 10 | [MSSQL (xp_cmdshell RCE)](simulation/attaques/10-mssql-rce.md) | T1210 | 🔴 Angle mort (RCE via SQL, audit de processus 4688 désactivé) |
| 11 | [Golden Ticket](simulation/attaques/11-golden-ticket.md) | T1558.001 | 🟡 Anomalie détectable (compte inexistant, incohérence nom/SID) → IA (Phase 6) |
| 12 | [Abus de trust inter-domaine](simulation/attaques/12-trust-inter-domaine.md) | T1482 | 🟡 Anomalie détectable (Child→Parent, compte forgé `hacker` RID 500) → IA (Phase 6) |

---

## 🛠️ Stack technique
- **Lab AD :** GOAD-Light (Orange Cyberdefense), VirtualBox, Vagrant/Ansible
- **Infrastructure :** Microsoft Azure (VM Linux, virtualisation imbriquée)
- **SIEM :** Wazuh (indexer + manager + dashboard, règles SOC Fortress)
- **Outils d'attaque :** impacket, NetExec
- **Référentiel :** MITRE ATT&CK · Windows Event Logs
- **IA (à venir) :** détection d'anomalies / apprentissage automatique

---

## ⚠️ Cadre éthique
Toutes les attaques sont réalisées **exclusivement** dans un lab **isolé et volontairement vulnérable** (GOAD), à des fins d'apprentissage et de recherche défensive. **Aucune** de ces techniques ne doit être utilisée sur un système réel sans autorisation explicite.
