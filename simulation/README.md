# 🧪 Simulation & Lab — Phases 2 & 3 du PFA

Ce dossier contient tout le nécessaire pour **construire le lab Active Directory** (Phase 2), y **brancher un SIEM Wazuh** (Phase 3), et **rejouer les attaques** documentées dans [`../docs/`](../docs/).

**Avancement :** ✅ Phase 2 (lab GOAD-Light sur Azure) · ✅ Phase 3 (SIEM Wazuh + 3 agents) · 🔄 Phase 4 (attaques & détection — en cours).

## 📌 Deux approches testées

| Approche | Guide | Statut |
|----------|-------|--------|
| **Local** (Windows + VirtualBox + WSL2) | [`01-lab-setup.md`](01-lab-setup.md) | ❌ **Abandonnée** — WinRM instable à cause de l'empilement Hyper-V/VirtualBox |
| **Azure** (VM Linux + VirtualBox) ⭐ | [`02-azure-goad.md`](02-azure-goad.md) | ✅ **Fonctionnelle** — GOAD-Light déployé avec succès |

> **Pourquoi ce choix ?** Sur Windows, WSL2 impose Hyper-V, qui rend VirtualBox+WinRM instables (les VM bootent mais Vagrant/Ansible ne les configurent pas de façon fiable). Sur une **VM Linux Azure**, tout tourne en **natif** → déploiement fiable. Le guide local est conservé comme **trace de la démarche** (utile pour le mémoire/soutenance).

## Contenu

| Fichier | Description |
|---------|-------------|
| [`02-azure-goad.md`](02-azure-goad.md) ⭐ | **Guide retenu (Phase 2)** : déployer GOAD sur une VM Linux Azure |
| [`03-wazuh-siem.md`](03-wazuh-siem.md) 🛡️ | **Phase 3** : brancher le SIEM Wazuh (déploiement + accès + dépannage) |
| [`04-attaques-detection.md`](04-attaques-detection.md) ⚔️ | **Phase 4** : simuler les attaques + vérifier la détection Wazuh (fiche par attaque) |
| [`azure-goad-setup.sh`](azure-goad-setup.sh) | Script d'install (VirtualBox/Vagrant/Ansible/GOAD) sur la VM Azure |
| [`01-lab-setup.md`](01-lab-setup.md) | Guide local (abandonné) — VirtualBox + WSL2 |
| [`wsl-setup.sh`](wsl-setup.sh) · [`wsl-fix-python312.sh`](wsl-fix-python312.sh) | Scripts de l'approche locale (abandonnée) |
| [`screenshots/`](screenshots/) | Captures du montage du lab |

## Architecture du lab (retenue — Azure)

```
        VM Azure Linux (Ubuntu 24.04 · Standard_E4s_v3 · 32 Go)
        ┌────────────────────────────────────────────────────┐
        │   VirtualBox (natif)                                │
        │   ┌────────────┐  ┌────────────┐  ┌────────────┐    │
        │   │   DC01     │  │   DC02     │  │  SRV02     │    │
        │   │ sevenking. │  │  north.    │  │ (membre +  │    │
        │   │  (AD/DC)🎯 │  │  (enfant)  │  │  MSSQL)    │    │
        │   └────────────┘  └────────────┘  └────────────┘    │
        │        Réseau host-only 192.168.56.0/24             │
        │   ┌──────────────┐  ✅ Phase 3                      │
        │   │  Wazuh  .51   │  ← SIEM : collecte + détection   │
        │   │ (3 agents AD) │     (indexer+manager+dashboard)  │
        │   └──────────────┘                                  │
        └────────────────────────────────────────────────────┘
```

> 🛡️ **Phase 3 faite :** Wazuh déployé (VM `192.168.56.51`) avec un agent sur chaque DC/serveur. Détails → [`03-wazuh-siem.md`](03-wazuh-siem.md).

## Environnement (déployé le 2026-07-16)

- **Hôte :** VM Azure `goad-host`, Ubuntu 24.04, Standard_E4s_v3 (4 vCPU, 32 Go), nested virt ✅.
- **Base vulnérable :** GOAD-Light (Orange Cyberdefense) — 3 VM Windows Server (DC01, DC02, SRV02).
- **Instance GOAD :** `fba132-goad-light-virtualbox` · réseau 192.168.56.0/24.
- **SIEM (Phase 3, déployé le 2026-07-17) :** Wazuh sur `192.168.56.51` + agents sur les 3 machines.

> ⚠️ **Rappel légal/éthique :** ce lab est **isolé**. Les attaques ne se pratiquent QUE dans cet environnement, jamais sur un réseau réel.
