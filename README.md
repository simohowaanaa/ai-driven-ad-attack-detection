# Détection d'attaques Active Directory par IA

**Projet de Fin d'Année (PFA)** — Stage SOC, [Dataprotect](https://www.dataprotect.ma/) · Business Unit Security Intelligence

> Concevoir une chaîne complète de détection d'attaques Active Directory : documentation théorique, lab de simulation isolé, SIEM Wazuh avec règles sur-mesure, et agent IA de détection comportementale.

**Binôme :** Maimouni Mohammed & Chafak Othmane  
**Encadrant Dataprotect :** Benkirane Abbes

---

## Table des matières

1. [Objectifs](#objectifs)
2. [Avancement](#avancement)
3. [Architecture du lab](#architecture-du-lab)
4. [Structure du dépôt](#structure-du-dépôt)
5. [Résultats de détection](#résultats-de-détection)
6. [Stack technique](#stack-technique)
7. [Cadre éthique](#cadre-éthique)

---

## Objectifs

| # | Objectif |
|:-:|----------|
| 1 | **Documenter** les 48 principales attaques Active Directory — théorie, MITRE ATT&CK, Event IDs, règles Sigma, remédiation |
| 2 | **Simuler** ces attaques dans un lab isolé (GOAD-Light sur Azure) et générer les logs Windows correspondants |
| 3 | **Détecter** avec Wazuh : analyse des règles natives, puis écriture de 7 règles sur-mesure pour combler les angles morts |
| 4 | **Automatiser** avec un agent IA (Isolation Forest) pour détecter les attaques sans signature fixe (Golden Ticket, PtH furtif) |

---

## Avancement

| Phase | Description | Statut |
|:-----:|-------------|:------:|
| **1** | Documentation des **48 attaques AD** | ✅ Terminé |
| **2** | Lab **GOAD-Light** déployé sur Azure (virtualisation imbriquée) | ✅ Terminé |
| **3** | SIEM **Wazuh** installé + agents sur 3 machines Windows | ✅ Terminé |
| **4** | **12 attaques** simulées et analysées — détection native Wazuh | ✅ Terminé |
| **5** | **7 règles Wazuh custom** — angles morts comblés, validées en live | ✅ Terminé |
| **6** | **Agent IA** (Isolation Forest) — 4 anomalies détectées / 23 comptes | ✅ Terminé |

---

## Architecture du lab

```
        VM Azure Linux · Ubuntu 24.04 · Standard_E4s_v3 (4 vCPU, 32 Go)
        ┌─────────────────────────────────────────────────────────────┐
        │   VirtualBox (virtualisation imbriquée)                      │
        │                                                              │
        │   ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐   │
        │   │    DC01     │  │    DC02     │  │      SRV02       │   │
        │   │kingslanding │  │ winterfell  │  │  castelblack     │   │
        │   │  .10        │  │  .11        │  │  .22  (MSSQL)    │   │
        │   └──────┬──────┘  └──────┬──────┘  └────────┬─────────┘   │
        │          │ agent          │ agent             │ agent       │
        │          └────────────────┼───────────────────┘            │
        │                    ┌──────▼──────┐                         │
        │                    │ Wazuh  .51  │  ← SIEM                 │
        │                    └─────────────┘                         │
        │           Réseau host-only · 192.168.56.0/24               │
        └─────────────────────────────────────────────────────────────┘
                    ▲ Accès SSH + tunnel depuis le PC local
```

| Machine | Rôle | Domaine |
|---------|------|---------|
| `kingslanding` · .10 | DC01 — contrôleur de domaine principal | `sevenkingdoms.local` |
| `winterfell` · .11 | DC02 — contrôleur de domaine enfant | `north.sevenkingdoms.local` |
| `castelblack` · .22 | Serveur membre + MSSQL Server | `north.sevenkingdoms.local` |
| Wazuh · .51 | SIEM — collecte logs, règles custom, dashboard | — |

Les deux domaines sont reliés par un **trust inter-forêt**, permettant de simuler les attaques cross-domain (Trust Abuse, SID History).

---

## Structure du dépôt

```
.
├── docs/                    Phase 1 — documentation théorique des 48 attaques
│   ├── README.md            Catalogue complet avec liens
│   ├── 01-recon/
│   ├── 02-credential-access/
│   ├── 03-lateral-movement/
│   ├── 04-privilege-escalation/
│   ├── 05-persistence/
│   ├── 06-defense-evasion/
│   └── 07-domain-trusts/
│
├── simulation/              Phases 2–4 — lab, déploiement, attaques simulées
│   ├── README.md
│   ├── 01-deploiement-azure.md
│   ├── 02-siem-wazuh.md
│   ├── 03-attaques.md       Index des 12 attaques + résultats détection
│   ├── attaques/            12 playbooks (commandes + captures Wazuh)
│   ├── scripts/             Scripts shell (déploiement Azure, Wazuh)
│   ├── screenshots/         Captures du lab et des attaques
│   ├── spectre-detection.md Synthèse : détectés / partiels / angles morts
│   ├── mitre-mapping.md     Mapping MITRE ATT&CK des 12 attaques
│   ├── glossaire.md         Glossaire AD, Kerberos, Wazuh
│   └── archive/             Approche locale abandonnée (trace de démarche)
│
├── detection/               Phases 5–6 — règles custom et agent IA
│   ├── README.md
│   ├── 01-regles-wazuh.md   7 règles Wazuh validées en live
│   ├── 02-agent-ia.md       Pipeline Isolation Forest + résultats
│   └── anomaly_detection.py Script Python de l'agent IA
│
└── rapports/                Rapports d'avancement superviseur
    ├── rapport-avancement-2026-08-04.pdf
    └── rapport-avancement-2026-08-04.docx
```

---

## Résultats de détection

### Phase 4 — Détection native Wazuh (12 attaques simulées)

| # | Attaque | MITRE | Wazuh natif | Règle custom (Phase 5) |
|:-:|---------|-------|:-----------:|:----------------------:|
| 01 | [Kerberoasting](simulation/attaques/01-kerberoasting.md) | T1558.003 | 🟡 Partiel | ✅ Règle 100011 |
| 02 | [AS-REP Roasting](simulation/attaques/02-asrep-roasting.md) | T1558.004 | 🔴 Angle mort | ✅ Règle 100014 |
| 03 | [Énumération LDAP](simulation/attaques/03-enumeration.md) | T1087.002 | 🔴 Angle mort | ⚠️ Non couvrable par signature → Phase 6 |
| 04 | [LLMNR Poisoning](simulation/attaques/04-llmnr-poisoning.md) | T1557.001 | 🔴 Angle mort | ⚠️ Attaque réseau, hors SIEM |
| 05 | [Password Spraying](simulation/attaques/05-password-spraying.md) | T1110.003 | ✅ Détecté | — |
| 06 | [DCSync](simulation/attaques/06-dcsync.md) | T1003.006 | 🔴 Angle mort | ✅ Règle 100010 |
| 07 | [Abus d'ACL](simulation/attaques/07-acl-abuse.md) | T1222.001 | ✅ Détecté | — |
| 08 | [ADCS ESC1](simulation/attaques/08-adcs-esc1.md) | T1649 | 🔴 Angle mort | ✅ Règle 100012 |
| 09 | [Pass-the-Hash](simulation/attaques/09-pass-the-hash.md) | T1550.002 | 🟡 Partiel | ✅ Règle 100017 + Phase 6 |
| 10 | [MSSQL RCE](simulation/attaques/10-mssql-rce.md) | T1210 | 🔴 Angle mort | ✅ Règle 100013 |
| 11 | [Golden Ticket](simulation/attaques/11-golden-ticket.md) | T1558.001 | 🟡 Partiel | ✅ Phase 6 (tgs_without_tgt = 610) |
| 12 | [Trust inter-domaine](simulation/attaques/12-trust-inter-domaine.md) | T1482 | 🟡 Partiel | ✅ Règle 100019 |

### Phase 5 — 7 règles Wazuh custom validées en live

| Règle | Attaque détectée | Event Windows | Résultat |
|-------|-----------------|---------------|----------|
| 100010 | DCSync | 4662 (réplication DS) | ✅ 3 hits — `tywin.lannister` identifié |
| 100011 | Kerberoasting | 4769 + RC4 (0x17) | ✅ 3 hits — rafale de tickets RC4 |
| 100012 | ADCS ESC1 | 4887 (certificat émis) | ✅ 2 hits — cert `administrator` émis |
| 100013 | MSSQL RCE | 4688 (parent = sqlservr.exe) | ✅ 7 hits — `xp_cmdshell whoami` |
| 100014 | AS-REP Roasting | 4768 + preAuthType=0 | ✅ 1 hit — compte sans pré-auth |
| 100017 | Pass-the-Hash | 4624 + NTLM + LogonType 3 | ✅ 5 hits — `jon.snow` via hash NTLM |
| 100019 | Trust Abuse | NTLM cross-domain NORTH→SEVENKINGDOMS | ✅ 18 hits — mouvement inter-domaine |

### Phase 6 — Agent IA (Isolation Forest) — 4 anomalies / 23 comptes

| Compte | Score | Signal | Interprétation |
|--------|:-----:|--------|----------------|
| `robb.stark` | -0.170 | 1 461 events / 24h | Bot RDP automatisé |
| `eddard.stark` | -0.086 | 17 logons NTLM | **Pass-the-Hash** |
| `robb.stark@NORTH…` | -0.083 | 610 TGS sans TGT | **Golden Ticket** ← détection clé |
| `sql_svc` | -0.022 | alertes xp_cmdshell | **MSSQL RCE** |

> **Résultat clé :** le Golden Ticket — indétectable par règle de signature — est révélé par la feature `tgs_without_tgt = 610` (tickets TGS présentés sans AS-REQ précédent, signature comportementale du ticket forgé hors-ligne).

---

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Lab AD | [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) (Orange Cyberdefense) — VirtualBox + Vagrant + Ansible |
| Infrastructure | Microsoft Azure — VM Linux, virtualisation imbriquée |
| SIEM | [Wazuh](https://wazuh.com/) — indexer + manager + dashboard + agents |
| Outils d'attaque | [Impacket](https://github.com/fortra/impacket), [NetExec](https://github.com/Pennyw0rth/NetExec), [Certipy](https://github.com/ly4k/Certipy), Responder |
| Agent IA | Python — scikit-learn (Isolation Forest), pandas, numpy |
| Référentiel | [MITRE ATT&CK](https://attack.mitre.org/) Enterprise |

---

## Cadre éthique

Toutes les attaques sont réalisées **exclusivement** dans un environnement **isolé et volontairement vulnérable** (GOAD), à des fins de recherche défensive et pédagogique.  
**Aucune de ces techniques ne doit être utilisée sur un système réel sans autorisation écrite explicite.**
