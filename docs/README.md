# Documentation des attaques Active Directory — PFA SOC Dataprotect

> **Projet de Fin d'Année** — Business Unit Security Intelligence (SOC)
> **Binôme :** Simo Howaana & Chafak Othmane
> **Encadrement :** Dataprotect
> **Objectif global :** Documenter 30+ attaques AD → les simuler pour générer des logs → matcher les règles de détection SIEM (QRadar / Elastic) → développer un **agent IA au niveau du DC** pour la détection.

---

## 1. Vue d'ensemble du projet

| Phase | Livrable | Statut |
|-------|----------|--------|
| 1. Documentation | Fiches standardisées des 48 attaques AD (ce dossier) | ✅ **Terminé (48/48)** |
| 2. Lab de simulation | Environnement DC + victimes + attaquant + collecte de logs | ⚪ À faire |
| 3. Génération de logs | Rejouer chaque attaque, capturer les Event IDs | ⚪ À faire |
| 4. Règles de détection | Sigma → QRadar (AQL) / Elastic (KQL/EQL) | ⚪ À faire |
| 5. Agent IA (DC) | Détection par ML/anomalie, pipeline temps réel | ⚪ À faire |

**Stack Dataprotect ciblée :** Cortex XSOAR (SOAR), IBM QRadar + Elastic Stack (Elasticsearch, Filebeat/Winlogbeat) comme SIEM, AXAT (EDR), NDR.

---

## 2. Catalogue des attaques (48) par phase MITRE ATT&CK

### 🔍 Reconnaissance / Discovery
| # | Attaque | Tactique MITRE | Technique |
|---|---------|----------------|-----------|
| 01 | LDAP Enumeration (BloodHound/SharpHound) | Discovery | T1087, T1069 |
| 02 | SPN Scanning | Discovery | T1046 |
| 03 | Null / Anonymous Sessions | Discovery | T1087 |
| 04 | AS-REP Roasting Recon | Discovery | T1087 |

### 🔑 Credential Access
| # | Attaque | Tactique MITRE | Technique |
|---|---------|----------------|-----------|
| 05 | Kerberoasting | Credential Access | T1558.003 |
| 06 | AS-REP Roasting | Credential Access | T1558.004 |
| 07 | LLMNR / NBT-NS Poisoning (Responder) | Credential Access | T1557.001 |
| 08 | DCSync | Credential Access | T1003.006 |
| 09 | LSASS Dumping (Mimikatz) | Credential Access | T1003.001 |
| 10 | NTDS.dit Extraction | Credential Access | T1003.003 |
| 11 | Password Spraying | Credential Access | T1110.003 |
| 12 | Brute Force / Account Lockout | Credential Access | T1110 |
| 37 | GPP Passwords (cPassword / MS14-025) | Credential Access | T1552.006 |
| 38 | LAPS Password Abuse | Credential Access | T1552 |
| 39 | gMSA Password Abuse (ReadGMSAPassword) | Credential Access | T1078 / T1552 |
| 40 | DPAPI Abuse | Credential Access | T1555 / T1552 |

### ↔️ Lateral Movement
| # | Attaque | Tactique MITRE | Technique |
|---|---------|----------------|-----------|
| 13 | Pass-the-Hash | Lateral Movement | T1550.002 |
| 14 | Pass-the-Ticket | Lateral Movement | T1550.003 |
| 15 | Overpass-the-Hash | Lateral Movement | T1550.002 |
| 16 | PsExec / WMI / WinRM Lateral | Lateral Movement | T1021 |
| 17 | NTLM Relay (SMB Relay) | Lateral Movement | T1557.001 |

### ⬆️ Privilege Escalation
| # | Attaque | Tactique MITRE | Technique |
|---|---------|----------------|-----------|
| 18 | Golden Ticket | Persistence / PrivEsc | T1558.001 |
| 19 | Silver Ticket | Persistence / PrivEsc | T1558.002 |
| 20 | Diamond Ticket | Persistence / PrivEsc | T1558 |
| 21 | Kerberos Delegation Abuse (Unconstrained/Constrained/RBCD) | PrivEsc | T1558 |
| 22 | PrivExchange | PrivEsc | T1068 |
| 23 | noPac (CVE-2021-42278 / 42287) | PrivEsc | T1068 |
| 24 | PetitPotam | PrivEsc | T1187 |
| 25 | ADCS Abuse (ESC1–ESC8, Certipy) | PrivEsc | T1649 |
| 41 | ACL / DACL Abuse (GenericAll, WriteDACL, WriteOwner…) | PrivEsc / Persistence | T1222 / T1098 |
| 42 | PrinterBug / SpoolSample (MS-RPRN) | PrivEsc | T1187 |
| 43 | Certifried (CVE-2022-26923) | PrivEsc | T1649 |
| 44 | Bronze Bit (CVE-2020-17049) | PrivEsc | T1558 |
| 45 | MS14-068 (Kerberos PAC Forgery) | PrivEsc | T1558 |
| 46 | PrintNightmare (CVE-2021-34527) | PrivEsc | T1068 |

### 🔒 Persistence
| # | Attaque | Tactique MITRE | Technique |
|---|---------|----------------|-----------|
| 26 | Skeleton Key | Persistence | T1556.001 |
| 27 | DCShadow | Persistence / Defense Evasion | T1207 |
| 28 | AdminSDHolder Abuse | Persistence | T1098 |
| 29 | GPO Abuse | Persistence | T1484.001 |
| 30 | SID History Injection | Persistence | T1134.005 |
| 31 | Custom SSP | Persistence | T1547.005 |
| 32 | Golden Certificate | Persistence | T1649 |

### 🥷 Defense Evasion / Misc
| # | Attaque | Tactique MITRE | Technique |
|---|---------|----------------|-----------|
| 33 | Zerologon (CVE-2020-1472) | PrivEsc / Defense Evasion | T1068 |
| 34 | sAMAccountName Spoofing | PrivEsc | T1078 |
| 35 | Shadow Credentials (msDS-KeyCredentialLink) | Credential Access | T1556 |
| 36 | Timeroasting | Credential Access | T1558 |

### 🌐 Domain / Forest Trusts
| # | Attaque | Tactique MITRE | Technique |
|---|---------|----------------|-----------|
| 47 | Domain / Forest Trust Abuse (SID History & Trust Key) | PrivEsc / Lateral Movement | T1134.005 / T1482 |
| 48 | Golden gMSA (KDS Root Key Abuse) | Credential Access / Persistence | T1552 / T1649 |

---

## 3. Organisation du dossier

```
docs/
├── README.md                     ← ce fichier (catalogue + suivi)
├── 01-recon/
├── 02-credential-access/
├── 03-lateral-movement/
├── 04-privilege-escalation/
├── 05-persistence/
├── 06-defense-evasion/
└── 07-domain-trusts/
```

Chaque fiche suit le même format standardisé : description, prérequis, MITRE, procédure de simulation, **Event IDs générés**, sources de logs, **règle de détection (Sigma)**, contre-mesures, et features exploitables par l'**agent IA**.

---

## 4. Références transverses

- **MITRE ATT&CK** — https://attack.mitre.org/ (matrice Enterprise)
- **The Hacker Recipes** — https://www.thehacker.recipes/ (référence AD offensive)
- **Atomic Red Team** — https://github.com/redcanaryco/atomic-red-team (simulation)
- **Sigma HQ** — https://github.com/SigmaHQ/sigma (règles de détection portables)
- **BloodHound** — https://github.com/SpecterOps/BloodHound
- **Impacket** — https://github.com/fortra/impacket
