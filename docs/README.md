# 📚 Documentation des 48 attaques Active Directory

> **Phase 1 du PFA** — SOC Dataprotect (Business Unit Security Intelligence)
> **Binôme :** Maimouni Mohammed & Chafak Othmane · **Encadrant :** Benkirane Abbes

48 fiches standardisées couvrant les principales attaques Active Directory, classées par phase MITRE ATT&CK. Chaque fiche inclut : description, prérequis, technique MITRE, Event IDs générés, règle de détection (Sigma), contre-mesures, et features exploitables par l'agent IA.

---

## Catalogue (48 attaques)

### 🔍 Reconnaissance / Discovery

| # | Attaque | MITRE |
|---|---------|-------|
| 01 | [LDAP Enumeration (BloodHound/SharpHound)](01-recon/01-ldap-enumeration.md) | T1087, T1069 |
| 02 | [SPN Scanning](01-recon/02-spn-scanning.md) | T1046 |
| 03 | [Null / Anonymous Sessions](01-recon/03-null-anonymous-sessions.md) | T1087 |
| 04 | [AS-REP Roasting Recon](01-recon/04-asrep-roasting-recon.md) | T1087 |

### 🔑 Credential Access

| # | Attaque | MITRE |
|---|---------|-------|
| 05 | [Kerberoasting](02-credential-access/05-kerberoasting.md) | T1558.003 |
| 06 | [AS-REP Roasting](02-credential-access/06-asrep-roasting.md) | T1558.004 |
| 07 | [LLMNR / NBT-NS Poisoning (Responder)](02-credential-access/07-llmnr-nbtns-poisoning.md) | T1557.001 |
| 08 | [DCSync](02-credential-access/08-dcsync.md) | T1003.006 |
| 09 | [LSASS Dumping (Mimikatz)](02-credential-access/09-lsass-dumping.md) | T1003.001 |
| 10 | [NTDS.dit Extraction](02-credential-access/10-ntds-extraction.md) | T1003.003 |
| 11 | [Password Spraying](02-credential-access/11-password-spraying.md) | T1110.003 |
| 12 | [Brute Force / Account Lockout](02-credential-access/12-brute-force-lockout.md) | T1110 |
| 37 | [GPP Passwords (cPassword / MS14-025)](02-credential-access/37-gpp-passwords.md) | T1552.006 |
| 38 | [LAPS Password Abuse](02-credential-access/38-laps-abuse.md) | T1552 |
| 39 | [gMSA Password Abuse](02-credential-access/39-gmsa-abuse.md) | T1078 / T1552 |
| 40 | [DPAPI Abuse](02-credential-access/40-dpapi-abuse.md) | T1555 / T1552 |

### ↔️ Lateral Movement

| # | Attaque | MITRE |
|---|---------|-------|
| 13 | [Pass-the-Hash](03-lateral-movement/13-pass-the-hash.md) | T1550.002 |
| 14 | [Pass-the-Ticket](03-lateral-movement/14-pass-the-ticket.md) | T1550.003 |
| 15 | [Overpass-the-Hash](03-lateral-movement/15-overpass-the-hash.md) | T1550.002 |
| 16 | [PsExec / WMI / WinRM](03-lateral-movement/16-psexec-wmi-winrm.md) | T1021 |
| 17 | [NTLM Relay (SMB Relay)](03-lateral-movement/17-ntlm-relay.md) | T1557.001 |

### ⬆️ Privilege Escalation

| # | Attaque | MITRE |
|---|---------|-------|
| 18 | [Golden Ticket](04-privilege-escalation/18-golden-ticket.md) | T1558.001 |
| 19 | [Silver Ticket](04-privilege-escalation/19-silver-ticket.md) | T1558.002 |
| 20 | [Diamond Ticket](04-privilege-escalation/20-diamond-ticket.md) | T1558 |
| 21 | [Kerberos Delegation Abuse](04-privilege-escalation/21-kerberos-delegation-abuse.md) | T1558 |
| 22 | [PrivExchange](04-privilege-escalation/22-privexchange.md) | T1068 |
| 23 | [noPac (CVE-2021-42278/42287)](04-privilege-escalation/23-nopac.md) | T1068 |
| 24 | [PetitPotam](04-privilege-escalation/24-petitpotam.md) | T1187 |
| 25 | [ADCS Abuse (ESC1–ESC8)](04-privilege-escalation/25-adcs-abuse.md) | T1649 |
| 41 | [ACL / DACL Abuse](04-privilege-escalation/41-acl-dacl-abuse.md) | T1222 / T1098 |
| 42 | [PrinterBug / SpoolSample](04-privilege-escalation/42-printerbug-spoolsample.md) | T1187 |
| 43 | [Certifried (CVE-2022-26923)](04-privilege-escalation/43-certifried.md) | T1649 |
| 44 | [Bronze Bit (CVE-2020-17049)](04-privilege-escalation/44-bronze-bit.md) | T1558 |
| 45 | [MS14-068 (Kerberos PAC Forgery)](04-privilege-escalation/45-ms14-068.md) | T1558 |
| 46 | [PrintNightmare (CVE-2021-34527)](04-privilege-escalation/46-printnightmare.md) | T1068 |

### 🔒 Persistence

| # | Attaque | MITRE |
|---|---------|-------|
| 26 | [Skeleton Key](05-persistence/26-skeleton-key.md) | T1556.001 |
| 27 | [DCShadow](05-persistence/27-dcshadow.md) | T1207 |
| 28 | [AdminSDHolder Abuse](05-persistence/28-adminsdholder.md) | T1098 |
| 29 | [GPO Abuse](05-persistence/29-gpo-abuse.md) | T1484.001 |
| 30 | [SID History Injection](05-persistence/30-sid-history-injection.md) | T1134.005 |
| 31 | [Custom SSP](05-persistence/31-custom-ssp.md) | T1547.005 |
| 32 | [Golden Certificate](05-persistence/32-golden-certificate.md) | T1649 |

### 🥷 Defense Evasion

| # | Attaque | MITRE |
|---|---------|-------|
| 33 | [Zerologon (CVE-2020-1472)](06-defense-evasion/33-zerologon.md) | T1068 |
| 34 | [sAMAccountName Spoofing](06-defense-evasion/34-samaccountname-spoofing.md) | T1078 |
| 35 | [Shadow Credentials](06-defense-evasion/35-shadow-credentials.md) | T1556 |
| 36 | [Timeroasting](06-defense-evasion/36-timeroasting.md) | T1558 |

### 🌐 Domain / Forest Trusts

| # | Attaque | MITRE |
|---|---------|-------|
| 47 | [Domain / Forest Trust Abuse](07-domain-trusts/47-domain-trust-abuse.md) | T1134.005 / T1482 |
| 48 | [Golden gMSA (KDS Root Key Abuse)](07-domain-trusts/48-golden-gmsa.md) | T1552 / T1649 |

---

## Structure du dossier

```
docs/
├── README.md                     ← ce fichier (catalogue)
├── 01-recon/                     ← 4 attaques de reconnaissance
├── 02-credential-access/         ← 12 attaques de vol d'identifiants
├── 03-lateral-movement/          ← 5 attaques de mouvement latéral
├── 04-privilege-escalation/      ← 14 attaques d'élévation de privilèges
├── 05-persistence/               ← 7 mécanismes de persistance
├── 06-defense-evasion/           ← 4 techniques d'évasion
└── 07-domain-trusts/             ← 2 attaques inter-domaines/forêts
```

---

## Références

- [MITRE ATT&CK](https://attack.mitre.org/) — matrice Enterprise
- [The Hacker Recipes](https://www.thehacker.recipes/) — référence offensive AD
- [Sigma HQ](https://github.com/SigmaHQ/sigma) — règles de détection portables
- [BloodHound](https://github.com/SpecterOps/BloodHound) — cartographie AD
- [Impacket](https://github.com/fortra/impacket) — outils d'attaque réseau
