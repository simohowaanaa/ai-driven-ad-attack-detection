# Phase 1 — Documentation des 48 attaques Active Directory

> **Point de départ du projet.** Avant de simuler quoi que ce soit, on documente : comprendre comment chaque attaque fonctionne, ce qu'elle laisse comme trace dans les logs Windows, et comment la détecter.

---

## Pourquoi cette phase existe

Un analyste SOC qui reçoit une alerte doit pouvoir répondre à trois questions en quelques secondes :

1. **Qu'est-ce qui s'est passé ?** — quelle technique l'attaquant a utilisée
2. **Où chercher ?** — quels Event IDs regarder dans les logs
3. **Comment réagir ?** — remédiation et contre-mesures

Ces 48 fiches sont conçues pour répondre à ces trois questions, pour chaque attaque connue sur Active Directory.

---

## Comment lire une fiche

Chaque fiche suit le même format :

| Section | Contenu |
|---------|---------|
| **Description** | Explication simple de l'attaque — comment elle fonctionne, pourquoi elle marche |
| **Prérequis** | Ce dont l'attaquant a besoin pour lancer l'attaque (compte, accès réseau…) |
| **MITRE ATT&CK** | Identifiant officiel de la technique dans le référentiel mondial |
| **Event IDs** | Les numéros d'événements Windows générés par l'attaque |
| **Règle de détection** | Règle Sigma — format universel, traduisible en Wazuh, QRadar, Elastic… |
| **Contre-mesures** | Comment empêcher ou limiter l'attaque côté défense |

---

## Catalogue des 48 attaques

### 🔍 Reconnaissance — *L'attaquant cartographie l'environnement*

> Avant d'attaquer, l'attaquant cherche à comprendre la structure du domaine : quels comptes existent, quels services tournent, quelles machines sont accessibles. Ces attaques sont souvent silencieuses car elles n'exploitent aucune vulnérabilité — elles utilisent des fonctionnalités légitimes d'AD.

| # | Attaque | MITRE |
|:-:|---------|-------|
| 01 | [LDAP Enumeration (BloodHound/SharpHound)](01-recon/01-ldap-enumeration.md) | T1087, T1069 |
| 02 | [SPN Scanning](01-recon/02-spn-scanning.md) | T1046 |
| 03 | [Null / Anonymous Sessions](01-recon/03-null-anonymous-sessions.md) | T1087 |
| 04 | [AS-REP Roasting Recon](01-recon/04-asrep-roasting-recon.md) | T1087 |

---

### 🔑 Credential Access — *L'attaquant vole des mots de passe ou des hashs*

> L'objectif ici est d'obtenir des identifiants valides — soit en clair, soit sous forme de hash. Avec un hash, l'attaquant peut souvent s'authentifier directement sans connaître le mot de passe (Pass-the-Hash). Ces attaques sont parmi les plus critiques car elles donnent accès à de nouveaux comptes.

| # | Attaque | MITRE |
|:-:|---------|-------|
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

---

### ↔️ Lateral Movement — *L'attaquant se déplace d'une machine à l'autre*

> Une fois un premier compte compromis, l'attaquant l'utilise pour accéder à d'autres machines du réseau. L'objectif est de progresser vers les systèmes les plus critiques (serveurs, DC).

| # | Attaque | MITRE |
|:-:|---------|-------|
| 13 | [Pass-the-Hash](03-lateral-movement/13-pass-the-hash.md) | T1550.002 |
| 14 | [Pass-the-Ticket](03-lateral-movement/14-pass-the-ticket.md) | T1550.003 |
| 15 | [Overpass-the-Hash](03-lateral-movement/15-overpass-the-hash.md) | T1550.002 |
| 16 | [PsExec / WMI / WinRM](03-lateral-movement/16-psexec-wmi-winrm.md) | T1021 |
| 17 | [NTLM Relay (SMB Relay)](03-lateral-movement/17-ntlm-relay.md) | T1557.001 |

---

### ⬆️ Privilege Escalation — *L'attaquant devient administrateur du domaine*

> L'objectif final de presque toutes les intrusions AD : obtenir les droits Domain Admin ou Enterprise Admin, ce qui donne un contrôle total sur l'ensemble du parc. Ces attaques exploitent des failles dans Kerberos, les services de certificats (ADCS) ou des mauvaises configurations.

| # | Attaque | MITRE |
|:-:|---------|-------|
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

---

### 🔒 Persistence — *L'attaquant s'assure de rester dans le réseau*

> Après avoir pris le contrôle, l'attaquant installe des mécanismes de persistance pour rester présent même si son accès initial est révoqué — parfois pendant des mois ou des années.

| # | Attaque | MITRE |
|:-:|---------|-------|
| 26 | [Skeleton Key](05-persistence/26-skeleton-key.md) | T1556.001 |
| 27 | [DCShadow](05-persistence/27-dcshadow.md) | T1207 |
| 28 | [AdminSDHolder Abuse](05-persistence/28-adminsdholder.md) | T1098 |
| 29 | [GPO Abuse](05-persistence/29-gpo-abuse.md) | T1484.001 |
| 30 | [SID History Injection](05-persistence/30-sid-history-injection.md) | T1134.005 |
| 31 | [Custom SSP](05-persistence/31-custom-ssp.md) | T1547.005 |
| 32 | [Golden Certificate](05-persistence/32-golden-certificate.md) | T1649 |

---

### 🥷 Defense Evasion — *L'attaquant efface ses traces et contourne les défenses*

| # | Attaque | MITRE |
|:-:|---------|-------|
| 33 | [Zerologon (CVE-2020-1472)](06-defense-evasion/33-zerologon.md) | T1068 |
| 34 | [sAMAccountName Spoofing](06-defense-evasion/34-samaccountname-spoofing.md) | T1078 |
| 35 | [Shadow Credentials](06-defense-evasion/35-shadow-credentials.md) | T1556 |
| 36 | [Timeroasting](06-defense-evasion/36-timeroasting.md) | T1558 |

---

### 🌐 Domain Trusts — *L'attaquant pivote d'un domaine à un autre*

> Dans une forêt Active Directory avec plusieurs domaines, un attaquant qui contrôle un domaine enfant peut tenter de compromettre le domaine parent — et ainsi toute la forêt.

| # | Attaque | MITRE |
|:-:|---------|-------|
| 47 | [Domain / Forest Trust Abuse](07-domain-trusts/47-domain-trust-abuse.md) | T1134.005 / T1482 |
| 48 | [Golden gMSA (KDS Root Key Abuse)](07-domain-trusts/48-golden-gmsa.md) | T1552 / T1649 |

---

## Références

- [MITRE ATT&CK](https://attack.mitre.org/) — référentiel mondial des techniques d'attaque
- [The Hacker Recipes](https://www.thehacker.recipes/) — référence technique offensive AD
- [Sigma HQ](https://github.com/SigmaHQ/sigma) — règles de détection portables (format universel)
- [BloodHound](https://github.com/SpecterOps/BloodHound) — cartographie des chemins d'attaque AD
- [Impacket](https://github.com/fortra/impacket) — bibliothèque Python pour les protocoles réseau Windows
