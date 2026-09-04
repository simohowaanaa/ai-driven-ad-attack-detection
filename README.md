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
- [Comprendre les attaques](#-comprendre-les-12-attaques-simulées)

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

## 🎓 Comprendre les 12 attaques simulées

> Cette section explique chaque attaque en langage simple — ce qu'elle exploite, comment elle fonctionne, et ce qu'on a fait concrètement dans ce projet pour la détecter.

---

### 01 — Kerberoasting `T1558.003`

**Le principe :** Kerberos permet à n'importe quel utilisateur du domaine de demander un ticket d'accès (TGS) pour n'importe quel service. Ce ticket est chiffré avec le hash du mot de passe du compte de service. L'attaquant collecte ces tickets et les craque hors ligne — le DC ne voit rien, aucune tentative de connexion suspecte.

**Ce qu'on a fait :**
- Listé les comptes avec SPN via `GetUserSPNs.py` (impacket)
- Demandé les tickets TGS chiffrés en RC4
- Craqué les hashes avec hashcat

**Détection :** Règle **100011** — Event 4769 avec `EncryptionType = 0x17` (RC4) en rafale → **3 hits** détectés en live.

---

### 02 — AS-REP Roasting `T1558.004`

**Le principe :** Normalement, pour obtenir un ticket Kerberos, l'utilisateur doit d'abord prouver son identité (pré-authentification). Certains comptes ont cette protection désactivée. Sans pré-auth, n'importe qui peut demander un ticket AS-REP chiffré avec le hash du mot de passe du compte — sans même avoir de credentials valides.

**Ce qu'on a fait :**
- Identifié les comptes sans pré-authentification (`preAuthType = 0`)
- Récupéré les tickets AS-REP via `GetNPUsers.py` (impacket)
- Craqué les hashes hors ligne

**Détection :** Règle **100014** — Event 4768 avec `preAuthType = 0` → **1 hit** détecté. Audit Kerberos AS activé via GPO (désactivé par défaut).

---

### 03 — Énumération LDAP / BloodHound `T1087`

**Le principe :** Active Directory est un annuaire lisible par tous les utilisateurs authentifiés. BloodHound exploite ça pour cartographier tous les chemins d'attaque vers les comptes admin — qui est admin de quoi, quelles ACL sont abusables, quels comptes ont des SPN.

**Ce qu'on a fait :**
- Lancé `bloodhound-python` avec un compte lambda (`jon.snow`)
- Visualisé les chemins vers Domain Admin dans l'interface graphique BloodHound
- Utilisé `ldapsearch` pour des requêtes ciblées

**Détection :** 🔴 Angle mort structurel — l'audit `Directory Service Access` (Event 4662) est désactivé par défaut. Sans ce log, Wazuh ne voit rien. La détection comportementale (volume de requêtes LDAP) est la seule approche viable.

---

### 04 — LLMNR Poisoning / Responder `T1557.001`

**Le principe :** Quand Windows cherche une machine inexistante via DNS, il "crie" la question sur tout le réseau (protocole LLMNR). L'attaquant répond immédiatement "c'est moi" — Windows envoie alors une tentative d'authentification NTLM avec le hash du mot de passe de l'utilisateur.

**Ce qu'on a fait :**
- Lancé Responder en écoute sur l'interface réseau du lab
- Intercepté des hashes NTLMv2 des machines GOAD
- Tenté le craquage avec hashcat

**Détection :** 🔴 Angle mort structurel — l'attaque se passe au niveau réseau. Windows ne génère aucun Event Log pour les broadcasts LLMNR. Un IDS réseau (Zeek, Suricata) est nécessaire — hors périmètre Wazuh.

---

### 05 — Password Spraying `T1110.003`

**Le principe :** Le brute force classique verrouille les comptes après quelques tentatives. Le spraying contourne ça en testant **un seul mot de passe** sur des centaines de comptes différents — chaque compte ne reçoit qu'une tentative, pas de verrouillage.

**Ce qu'on a fait :**
- Récupéré la liste des utilisateurs du domaine (depuis l'énumération)
- Testé `iknownothing` sur tous les comptes via `kerbrute`
- Identifié les comptes avec ce mot de passe

**Détection :** ✅ Détecté par défaut — vague d'Events **4625** (échec de connexion) visible dans Wazuh. C'est l'une des 2 attaques détectées sans configuration supplémentaire.

---

### 06 — DCSync `T1003.006`

**Le principe :** Les contrôleurs de domaine se synchronisent entre eux via le protocole MS-DRSR. Un compte avec les droits de réplication peut demander cette synchronisation et recevoir **tous les hashes de mots de passe du domaine** — y compris `krbtgt` et `Administrator`.

**Ce qu'on a fait :**
- Obtenu un compte avec droits de réplication (via abus d'ACL)
- Utilisé `secretsdump.py` (impacket) pour extraire tous les hashes
- Récupéré le hash `krbtgt` utilisé ensuite pour le Golden Ticket

**Détection :** Règle **100010** — Event **4662** avec le GUID de réplication AD sur un compte non-machine → **3 hits**, compte `tywin.lannister` identifié. Audit DS Access activé via GPO.

---

### 07 — Abus d'ACL `T1222`

**Le principe :** Les objets Active Directory (utilisateurs, groupes, OUs) ont des permissions (ACL). Si un attaquant obtient un compte avec `WriteDACL` ou `GenericAll` sur un objet, il peut modifier ses permissions — par exemple s'ajouter dans le groupe Domain Admins.

**Ce qu'on a fait :**
- Cartographié les ACL abusables avec BloodHound
- Utilisé PowerView pour modifier les permissions d'un compte cible
- Ajouté notre compte dans un groupe privilégié

**Détection :** ✅ Détecté par défaut — Event **4728** (ajout dans un groupe de sécurité) visible dans Wazuh sans configuration supplémentaire.

---

### 08 — ADCS ESC1 `T1649`

**Le principe :** Active Directory Certificate Services (ADCS) délivre des certificats utilisés pour l'authentification. Une mauvaise configuration (ESC1) permet de demander un certificat **au nom d'un autre utilisateur** (ex: Administrator) en spécifiant un `SubjectAlternativeName` arbitraire.

**Ce qu'on a fait :**
- Identifié les templates de certificats vulnérables avec `certipy find`
- Demandé un certificat au nom de `Administrator` via `certipy req`
- Utilisé ce certificat pour s'authentifier en tant qu'Administrator et obtenir son hash NTLM

**Détection :** Règle **100012** — Event **4887** avec `SubjectAltName` différent du demandeur → **2 hits**, certificat Administrator capturé. Audit ADCS activé via GPO.

---

### 09 — Pass-the-Hash `T1550.002`

**Le principe :** Windows accepte l'authentification NTLM avec le hash du mot de passe directement — sans avoir besoin de connaître le mot de passe en clair. Un attaquant qui a volé un hash peut s'en servir immédiatement pour se connecter à d'autres machines.

**Ce qu'on a fait :**
- Récupéré le hash NTLM d'un compte admin (via DCSync ou LSASS dump)
- Utilisé `evil-winrm` avec l'option `-H` pour passer le hash directement
- Obtenu un shell sur une autre machine sans connaître le mot de passe

**Détection :** Règle **100017** — Event **4624** de type 3 (réseau) avec package d'auth NTLM → **5 hits**. Les connexions NTLM de type réseau vers un DC sont rares et suspectes.

---

### 10 — MSSQL RCE `T1210 + T1059`

**Le principe :** SQL Server possède une procédure stockée `xp_cmdshell` qui permet d'exécuter des commandes système directement depuis une requête SQL. Si elle est activée et que l'attaquant a accès au serveur SQL (avec un hash ou des credentials), il peut prendre le contrôle complet du serveur.

**Ce qu'on a fait :**
- Accédé au serveur SQL avec des credentials volés
- Activé `xp_cmdshell` via `EXEC sp_configure`
- Exécuté des commandes système (`whoami`, `net user`, création de compte backdoor)

**Détection :** Règle **100013** — Event **4688** (création de processus) avec `cmd.exe` lancé par `sqlservr.exe` → **7 hits**, commande `xp_cmdshell whoami` capturée. Audit Process Creation activé via GPO.

---

### 11 — Golden Ticket `T1558.001`

**Le principe :** Le compte `krbtgt` est le compte maître de Kerberos — il signe tous les tickets du domaine. Si l'attaquant obtient son hash (via DCSync), il peut **forger des tickets Kerberos parfaitement valides** pour n'importe quel compte, avec n'importe quels privilèges, pour une durée illimitée. Le DC ne peut pas distinguer ce ticket d'un ticket légitime.

**Ce qu'on a fait :**
- Récupéré le hash `krbtgt` via DCSync
- Forgé un Golden Ticket avec `ticketer.py` (impacket)
- Utilisé ce ticket pour accéder à toutes les ressources du domaine

**Détection :** 🔴 Indétectable par règle signature — le ticket est cryptographiquement valide. Détecté par l'**agent IA** : `robb.stark@NORTH` présente **610 TGS sans aucun TGT** préalable (`tgs_without_tgt = 610`) — signature comportementale exclusive du Golden Ticket.

---

### 12 — Trust inter-domaine / SID History `T1134.005`

**Le principe :** Les deux domaines du lab (`sevenkingdoms.local` et `north.sevenkingdoms.local`) se font confiance. En exploitant SID History, un attaquant qui a compromis le domaine enfant peut ajouter le SID du groupe Enterprise Admins du domaine parent à son compte — et obtenir des privilèges dans la forêt entière.

**Ce qu'on a fait :**
- Compromis le domaine `north.sevenkingdoms.local`
- Forgé un ticket inter-domaine avec le SID Enterprise Admins du domaine parent
- Accédé aux ressources de `sevenkingdoms.local` avec des privilèges élevés

**Détection :** Règle **100019** — Event **4769** cross-domain avec compte non reconnu → **18 hits**, mouvement NORTH→SEVENKINGDOMS détecté.

---

### Bilan global

| Attaque | Sans config | Après règles custom | Agent IA |
|---------|:-----------:|:-------------------:|:--------:|
| Kerberoasting | 🟡 | ✅ 100011 | — |
| AS-REP Roasting | 🔴 | ✅ 100014 | — |
| Énumération LDAP | 🔴 | 🔴 structurel | — |
| LLMNR Poisoning | 🔴 | 🔴 structurel | — |
| Password Spraying | ✅ | ✅ | — |
| DCSync | 🔴 | ✅ 100010 | — |
| Abus d'ACL | ✅ | ✅ | — |
| ADCS ESC1 | 🔴 | ✅ 100012 | — |
| Pass-the-Hash | 🟡 | ✅ 100017 | — |
| MSSQL RCE | 🔴 | ✅ 100013 | — |
| **Golden Ticket** | 🟡 | 🔴 impossible | **✅ IA** |
| Trust inter-domaine | 🟡 | ✅ 100019 | — |

---

## ⚠️ Cadre éthique

Toutes les attaques sont réalisées **exclusivement** dans un environnement isolé et volontairement vulnérable (GOAD), à des fins de recherche défensive et pédagogique.  
**Aucune de ces techniques ne doit être utilisée sur un système réel sans autorisation écrite explicite.**
