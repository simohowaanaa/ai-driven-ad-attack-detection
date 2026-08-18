# 🧪 Lab & Simulation — Phases 2 à 6

Ce dossier couvre le déploiement du lab Active Directory vulnérable, l'installation du SIEM, la simulation des 12 attaques, les règles de détection sur-mesure, et l'agent IA.

---

## 📂 Fichiers de référence

| Fichier | Phase | Description |
|---------|-------|-------------|
| [`01-deploiement-azure.md`](01-deploiement-azure.md) | **2** | Déploiement GOAD-Light sur VM Azure (VirtualBox + Vagrant) |
| [`02-siem-wazuh.md`](02-siem-wazuh.md) | **3** | Installation Wazuh (indexer + manager + dashboard + 3 agents) |
| [`03-attaques.md`](03-attaques.md) | **4** | Index des 12 attaques simulées + détection Wazuh native |
| [`04-detection-avancee.md`](04-detection-avancee.md) | **5** | 7 règles Wazuh sur-mesure (DCSync, Kerberoasting, ADCS ESC1, MSSQL RCE, AS-REP, PtH, Trust Abuse) |
| [`05-agent-ia.md`](05-agent-ia.md) | **6** | Agent IA Isolation Forest — détection du Golden Ticket, PtH furtif, anomalies comportementales |

**Autres ressources :**

| Fichier | Description |
|---------|-------------|
| [`attaques/`](attaques/) | Une fiche par attaque simulée (commandes + captures Wazuh) |
| [`spectre-detection.md`](spectre-detection.md) | Synthèse des 12 attaques : détectées / angles morts / Phase 6 |
| [`mitre-mapping.md`](mitre-mapping.md) | Mapping MITRE ATT&CK des attaques simulées |
| [`glossaire.md`](glossaire.md) | Glossaire AD, Kerberos, Wazuh |
| [`screenshots/`](screenshots/) | Captures du lab et des attaques |
| [`azure-goad-setup.sh`](azure-goad-setup.sh) | Script d'installation (VirtualBox/Vagrant/Ansible/GOAD) |
| [`start-wazuh.sh`](start-wazuh.sh) | Démarrage des services Wazuh |
| [`archive/`](archive/) | Approche locale Windows abandonnée (conservée comme trace) |

---

## 🏗️ Architecture du lab

```
        VM Azure Linux (Ubuntu 24.04 · Standard_E4s_v3 · 32 Go RAM)
        ┌─────────────────────────────────────────────────────────┐
        │   VirtualBox (virtualisation imbriquée)                  │
        │   ┌────────────┐  ┌────────────┐  ┌──────────────────┐  │
        │   │   DC01     │  │   DC02     │  │      SRV02       │  │
        │   │kingslanding│  │ winterfell │  │  castelblack     │  │
        │   │  .10       │  │  .11       │  │  .22 (MSSQL)     │  │
        │   └─────┬──────┘  └─────┬──────┘  └────────┬─────────┘  │
        │         │ agent         │ agent             │ agent      │
        │         └───────────────┼───────────────────┘           │
        │                  ┌──────▼──────┐                        │
        │                  │ Wazuh  .51  │  ← SIEM (collecte logs)│
        │                  └─────────────┘                        │
        │         Réseau host-only 192.168.56.0/24                │
        └─────────────────────────────────────────────────────────┘
                  ▲ SSH + tunnel (depuis le PC)
```

- **`sevenkingdoms.local`** : DC01 (kingslanding)
- **`north.sevenkingdoms.local`** : DC02 (winterfell) — reliés par un **trust inter-domaine**
- **SRV02** (castelblack) : serveur membre + **MSSQL Server**
- **Wazuh** (192.168.56.51) : collecte les logs des 3 machines, héberge les règles custom

---

## ✅ État des phases

| Phase | Description | Statut |
|:-----:|-------------|:------:|
| **2** | Lab GOAD-Light déployé sur Azure | ✅ Terminé |
| **3** | SIEM Wazuh + 3 agents installés | ✅ Terminé |
| **4** | 12 attaques simulées et analysées | ✅ Terminé |
| **5** | 7 règles de détection custom (Wazuh) | ✅ Terminé |
| **6** | Agent IA Isolation Forest — 4 anomalies/23 comptes | ✅ Terminé |

> ⚠️ **Cadre légal :** ce lab est **isolé et volontairement vulnérable** (GOAD). Les attaques ne se pratiquent QUE dans cet environnement.
