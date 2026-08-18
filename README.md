<div align="center">

# Détection d'attaques Active Directory par IA

**Projet de Fin d'Année · SOC Dataprotect · Business Unit Security Intelligence**

![Phase 1](https://img.shields.io/badge/Phase%201%20Documentation-✓%20Terminé-22c55e?style=flat-square)
![Phase 2](https://img.shields.io/badge/Phase%202%20Lab%20Azure-✓%20Terminé-22c55e?style=flat-square)
![Phase 3](https://img.shields.io/badge/Phase%203%20Wazuh-✓%20Terminé-22c55e?style=flat-square)
![Phase 4](https://img.shields.io/badge/Phase%204%20Simulation-✓%20Terminé-22c55e?style=flat-square)
![Phase 5](https://img.shields.io/badge/Phase%205%20Règles%20Custom-✓%20Terminé-22c55e?style=flat-square)
![Phase 6](https://img.shields.io/badge/Phase%206%20Agent%20IA-✓%20Terminé-22c55e?style=flat-square)

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-005571?style=flat-square&logo=wazuh)
![Python](https://img.shields.io/badge/IA-Python%20%7C%20scikit--learn-3776ab?style=flat-square&logo=python)
![Azure](https://img.shields.io/badge/Lab-Azure%20%7C%20GOAD--Light-0078d4?style=flat-square&logo=microsoftazure)
![MITRE](https://img.shields.io/badge/Référentiel-MITRE%20ATT%26CK-da3434?style=flat-square)

</div>

---

## Présentation

Ce projet construit une **chaîne complète de détection d'attaques Active Directory**, de la documentation théorique jusqu'à un agent IA de détection comportementale, en passant par un lab de simulation réel et un SIEM instrumenté.

**Binôme :** Maimouni Mohammed & Chafak Othmane · **Encadrant :** Benkirane Abbes

---

## Sommaire

- [Architecture du lab](#️-architecture-du-lab)
- [Organisation du dépôt](#-organisation-du-dépôt)
- [Phase 1 — Documentation](#-phase-1--documentation-des-48-attaques)
- [Phase 2 — Lab Azure](#️-phase-2--déploiement-du-lab-azure)
- [Phase 3 — SIEM Wazuh](#️-phase-3--installation-du-siem-wazuh)
- [Phase 4 — Simulation](#️-phase-4--simulation-des-attaques)
- [Phase 5 — Règles custom](#-phase-5--règles-wazuh-custom)
- [Phase 6 — Agent IA](#-phase-6--agent-ia-isolation-forest)
- [Stack technique](#️-stack-technique)

---

## 🏗️ Architecture du lab

> Lab Active Directory vulnérable (GOAD-Light) déployé sur une VM Linux Azure avec virtualisation imbriquée (VirtualBox).

```
  VM Azure Linux · Ubuntu 24.04 · Standard_E4s_v3 · 4 vCPU · 32 Go RAM
  ┌───────────────────────────────────────────────────────────────────┐
  │                        VirtualBox                                  │
  │                                                                    │
  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐ │
  │  │     DC01     │    │     DC02     │    │        SRV02         │ │
  │  │ kingslanding │    │  winterfell  │    │    castelblack       │ │
  │  │   .10        │    │   .11        │    │   .22  ·  MSSQL      │ │
  │  └──────┬───────┘    └──────┬───────┘    └─────────┬────────────┘ │
  │         │  Wazuh agent      │  Wazuh agent          │  Wazuh agent │
  │         └───────────────────┼───────────────────────┘             │
  │                      ┌──────▼──────┐                              │
  │                      │  Wazuh .51  │  SIEM — logs · règles · UI  │
  │                      └─────────────┘                              │
  │                  Réseau host-only · 192.168.56.0/24               │
  └───────────────────────────────────────────────────────────────────┘
                ▲  SSH + tunnel depuis le PC local
```

| Machine | IP | Rôle | Domaine |
|---------|:--:|------|---------|
| `kingslanding` | .10 | Contrôleur de domaine principal (DC01) | `sevenkingdoms.local` |
| `winterfell` | .11 | Contrôleur de domaine enfant (DC02) | `north.sevenkingdoms.local` |
| `castelblack` | .22 | Serveur membre + MSSQL Server | `north.sevenkingdoms.local` |
| Wazuh | .51 | SIEM — collecte, indexation, alertes | — |

Les deux domaines sont reliés par un **trust inter-forêt**, permettant de simuler les attaques cross-domain.

---

## 📁 Organisation du dépôt

Le projet se lit dans l'ordre des phases. Chaque dossier correspond à une étape logique de la démarche :

```
Phase 1          Phase 2 + 3         Phase 4              Phase 5 + 6
  │                   │                  │                     │
docs/           simulation/         simulation/            detection/
  │            (déploiement)         (attaques/)          (règles + IA)
  │                   │                  │                     │
On documente    On construit        On rejoue les        On détecte ce
les attaques    le lab et le        attaques et on       que Wazuh seul
sur le papier   SIEM Wazuh          observe ce que       ne voyait pas
                                    Wazuh détecte
```

---

### 📂 `docs/` — La bibliothèque (Phase 1)

> **Pour qui ?** Toute personne qui veut comprendre ce qu'est une attaque AD avant de la voir en action.

48 fiches théoriques, une par attaque. Chaque fiche répond à : *Comment fonctionne l'attaque ? Quels logs elle génère ? Comment la détecter ? Comment s'en protéger ?*

```
docs/
├── 01-recon/                 ← Attaques de reconnaissance (BloodHound, SPN Scanning…)
├── 02-credential-access/     ← Vol de credentials (Kerberoasting, DCSync, LLMNR…)
├── 03-lateral-movement/      ← Mouvement latéral (Pass-the-Hash, NTLM Relay…)
├── 04-privilege-escalation/  ← Élévation de privilèges (Golden Ticket, ADCS ESC1…)
├── 05-persistence/           ← Persistance (Skeleton Key, DCShadow, GPO Abuse…)
├── 06-defense-evasion/       ← Évasion (Zerologon, Shadow Credentials…)
└── 07-domain-trusts/         ← Attaques inter-domaines (Trust Abuse, Golden gMSA)
```

→ [Ouvrir le catalogue complet](docs/README.md)

---

### 📂 `simulation/` — Le lab en pratique (Phases 2, 3 et 4)

> **Pour qui ?** Quelqu'un qui veut reproduire le projet ou comprendre comment le lab est construit et comment les attaques ont été rejouées.

Ce dossier contient tout ce qui a été fait concrètement : monter le lab, brancher le SIEM, puis rejouer chaque attaque et observer ce que Wazuh détecte (ou ne détecte pas).

```
simulation/
├── 01-deploiement-azure.md   ← Comment déployer le lab AD sur Azure (Phase 2)
├── 02-siem-wazuh.md          ← Comment installer et configurer Wazuh (Phase 3)
├── 03-attaques.md            ← Index des 12 attaques simulées + résultats (Phase 4)
│
├── attaques/                 ← Un fichier par attaque : commandes exactes + captures
│   ├── 01-kerberoasting.md
│   ├── 02-asrep-roasting.md
│   └── … (12 au total)
│
├── spectre-detection.md      ← Synthèse : quelles attaques sont détectées, lesquelles pas
├── mitre-mapping.md          ← Les 12 attaques positionnées sur la matrice MITRE ATT&CK
├── glossaire.md              ← Définitions : AD, Kerberos, TGT, DCSync, SIEM…
├── scripts/                  ← Scripts shell pour déployer le lab et démarrer Wazuh
└── screenshots/              ← Captures d'écran du lab et de chaque attaque
```

→ [Lire le guide de déploiement](simulation/01-deploiement-azure.md) · [Voir les attaques](simulation/03-attaques.md)

---

### 📂 `detection/` — Combler les angles morts (Phases 5 et 6)

> **Pour qui ?** Quelqu'un qui veut comprendre comment on passe d'un SIEM "de base" à une détection avancée, et comment l'IA prend le relais là où les règles s'arrêtent.

La Phase 4 a montré que 6 attaques sur 12 passaient complètement inaperçues. Ce dossier contient la réponse : des règles Wazuh sur-mesure pour les attaques avec signature, et un agent IA pour les attaques sans signature (comme le Golden Ticket).

```
detection/
├── 01-regles-wazuh.md        ← 7 règles écrites à la main, testées en live (Phase 5)
├── 02-agent-ia.md            ← Comment l'Isolation Forest détecte les anomalies (Phase 6)
└── anomaly_detection.py      ← Le script Python à exécuter sur les logs Wazuh
```

→ [Lire les règles custom](detection/01-regles-wazuh.md) · [Lire la doc de l'agent IA](detection/02-agent-ia.md)

---

### 📂 `rapports/` — Documents officiels

Rapports d'avancement remis au superviseur Dataprotect.

→ [Rapport août 2026 (PDF)](rapports/rapport-avancement-2026-08-04.pdf)

---

## 📚 Phase 1 — Documentation des 48 attaques

48 fiches standardisées couvrant les principales techniques offensives Active Directory, classées par tactique MITRE ATT&CK. Chaque fiche contient : description, prérequis, procédure de simulation, Event IDs générés, règle de détection (Sigma), contre-mesures.

| Tactique | Nb | Exemples |
|----------|----|---------|
| Reconnaissance | 4 | LDAP Enumeration, SPN Scanning, Null Sessions |
| Credential Access | 12 | Kerberoasting, AS-REP Roasting, DCSync, LLMNR Poisoning |
| Lateral Movement | 5 | Pass-the-Hash, Pass-the-Ticket, NTLM Relay |
| Privilege Escalation | 14 | Golden Ticket, ADCS ESC1–ESC8, noPac, PetitPotam |
| Persistence | 7 | Skeleton Key, DCShadow, GPO Abuse, SID History |
| Defense Evasion | 4 | Zerologon, Shadow Credentials, Timeroasting |
| Domain Trusts | 2 | Trust Abuse, Golden gMSA |

→ [Catalogue complet](docs/README.md)

---

## 🏗️ Phase 2 — Déploiement du lab (Azure)

Lab Active Directory vulnérable [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) déployé sur une VM Linux Azure avec virtualisation imbriquée (VirtualBox + Vagrant + Ansible).

| Étape | Détail |
|-------|--------|
| **VM Azure** | Ubuntu 24.04 · Standard_E4s_v3 · 4 vCPU · 32 Go RAM · nested virt activée |
| **GOAD-Light** | 3 machines Windows (2 DC + 1 serveur membre) provisionnées via Ansible |
| **Réseau** | Host-only `192.168.56.0/24` — isolé, sans accès internet |
| **Accès** | SSH + tunnel local depuis le PC · RDP tunnelé pour les sessions interactives |

→ [Guide de déploiement](simulation/01-deploiement-azure.md) · [Script d'installation](simulation/scripts/azure-goad-setup.sh)

---

## 🛡️ Phase 3 — Installation du SIEM Wazuh

Wazuh déployé sur une 4ᵉ VM (192.168.56.51) avec agents installés sur les 3 machines Windows.

| Composant | Rôle |
|-----------|------|
| **Wazuh Indexer** | Stockage et indexation des alertes (OpenSearch) |
| **Wazuh Manager** | Réception des logs agents, application des règles |
| **Wazuh Dashboard** | Interface de visualisation (Kibana-like) |
| **Agents Windows** | Collecte des Event Logs sur DC01, DC02, SRV02 |

**Couverture :** 3/3 agents actifs · 100 % des machines du lab supervisées.

→ [Guide d'installation Wazuh](simulation/02-siem-wazuh.md)

---

## ⚔️ Phase 4 — Simulation des attaques

12 attaques rejouées en live sur GOAD-Light. Chaque attaque dispose d'un [playbook dédié](simulation/attaques/) avec les commandes exactes et les captures de détection Wazuh.

| # | Attaque | MITRE | Résultat Phase 4 |
|:-:|---------|-------|:----------------:|
| 01 | [Kerberoasting](simulation/attaques/01-kerberoasting.md) | T1558.003 | 🟡 Partiel |
| 02 | [AS-REP Roasting](simulation/attaques/02-asrep-roasting.md) | T1558.004 | 🔴 Angle mort |
| 03 | [Énumération LDAP](simulation/attaques/03-enumeration.md) | T1087.002 | 🔴 Angle mort |
| 04 | [LLMNR Poisoning](simulation/attaques/04-llmnr-poisoning.md) | T1557.001 | 🔴 Angle mort |
| 05 | [Password Spraying](simulation/attaques/05-password-spraying.md) | T1110.003 | ✅ Détecté |
| 06 | [DCSync](simulation/attaques/06-dcsync.md) | T1003.006 | 🔴 Angle mort |
| 07 | [Abus d'ACL](simulation/attaques/07-acl-abuse.md) | T1222.001 | ✅ Détecté |
| 08 | [ADCS ESC1](simulation/attaques/08-adcs-esc1.md) | T1649 | 🔴 Angle mort |
| 09 | [Pass-the-Hash](simulation/attaques/09-pass-the-hash.md) | T1550.002 | 🟡 Partiel |
| 10 | [MSSQL RCE](simulation/attaques/10-mssql-rce.md) | T1210 | 🔴 Angle mort |
| 11 | [Golden Ticket](simulation/attaques/11-golden-ticket.md) | T1558.001 | 🟡 Partiel |
| 12 | [Trust inter-domaine](simulation/attaques/12-trust-inter-domaine.md) | T1482 | 🟡 Partiel |

**Bilan :** 2 détectés · 4 partiels · 6 angles morts → **justifie les Phases 5 et 6**

→ [Synthèse complète](simulation/spectre-detection.md) · [Mapping MITRE ATT&CK](simulation/mitre-mapping.md)

---

## 🔍 Phase 5 — Règles Wazuh custom

Activation des catégories d'audit Windows manquantes sur les 2 DC, puis écriture de 7 règles dans `/var/ossec/etc/rules/local_rules.xml`, toutes validées en conditions réelles.

| ID règle | Attaque ciblée | Event Windows | Validation live |
|:--------:|----------------|:-------------:|:---------------:|
| 100010 | DCSync | 4662 — réplication DS | ✅ 3 hits · `tywin.lannister` identifié |
| 100011 | Kerberoasting | 4769 + chiffrement RC4 (0x17) | ✅ 3 hits · rafale impacket détectée |
| 100012 | ADCS ESC1 | 4887 — certificat émis | ✅ 2 hits · certificat `administrator` émis |
| 100013 | MSSQL RCE | 4688 — parent = `sqlservr.exe` | ✅ 7 hits · `xp_cmdshell whoami` capturé |
| 100014 | AS-REP Roasting | 4768 + `preAuthType = 0` | ✅ 1 hit · compte sans pré-authentification |
| 100017 | Pass-the-Hash | 4624 + NTLM + LogonType 3 | ✅ 5 hits · `jon.snow` via hash NTLM |
| 100019 | Trust Abuse | NTLM cross-domain NORTH→SEVENKINGDOMS | ✅ 18 hits · mouvement inter-domaine |

→ [Documentation complète Phase 5](detection/01-regles-wazuh.md)

---

## 🤖 Phase 6 — Agent IA (Isolation Forest)

Pipeline non supervisé sur les alertes Wazuh exportées depuis OpenSearch. Le modèle construit **10 features comportementales** par compte sur 24h et isole les anomalies.

**Feature clé — `tgs_without_tgt`**  
Compte le nombre de tickets TGS demandés sans AS-REQ (TGT) précédent. Un Golden Ticket est forgé hors-ligne et présenté directement au KDC — aucune demande de TGT n'apparaît dans les logs. Cette signature comportementale est **indétectable par règle classique**.

```
Wazuh OpenSearch  →  Export JSON (5 000 alertes)  →  Feature engineering  →  Isolation Forest  →  Anomaly scores
```

### Résultats (18 août 2026 · 23 comptes analysés)

| Compte | Score | Signal détecté | Interprétation |
|--------|:-----:|----------------|----------------|
| `robb.stark` | **-0.170** | 1 461 events en 24h | Bot RDP automatisé |
| `eddard.stark` | **-0.086** | 17 logons NTLM | **Pass-the-Hash** |
| `robb.stark@NORTH…` | **-0.083** | 610 TGS sans TGT | **Golden Ticket** ← détection comportementale |
| `sql_svc` | **-0.022** | 7 alertes `xp_cmdshell` | **MSSQL RCE** |

> [!NOTE]
> Le Golden Ticket (robb.stark@NORTH, `tgs_without_tgt = 610`) est le résultat le plus significatif : c'est la seule approche du projet capable de détecter cette attaque, cryptographiquement identique à un ticket légitime.

→ [Documentation complète Phase 6](detection/02-agent-ia.md) · [Script Python](detection/anomaly_detection.py)

---

## 🛠️ Stack technique

| Couche | Technologie |
|--------|-------------|
| Lab AD vulnérable | [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) — VirtualBox · Vagrant · Ansible |
| Infrastructure | Microsoft Azure — VM Linux, virtualisation imbriquée (nested virt) |
| SIEM | [Wazuh](https://wazuh.com/) — indexer · manager · dashboard · agents Windows |
| Outils d'attaque | [Impacket](https://github.com/fortra/impacket) · [NetExec](https://github.com/Pennyw0rth/NetExec) · [Certipy](https://github.com/ly4k/Certipy) · Responder |
| Agent IA | Python 3 · scikit-learn · pandas · numpy |
| Référentiel | [MITRE ATT&CK](https://attack.mitre.org/) Enterprise Matrix |

---

## ⚠️ Cadre éthique

Toutes les attaques sont réalisées **exclusivement** dans un environnement isolé et volontairement vulnérable (GOAD), à des fins de recherche défensive et pédagogique.  
**Aucune de ces techniques ne doit être utilisée sur un système réel sans autorisation écrite explicite.**
