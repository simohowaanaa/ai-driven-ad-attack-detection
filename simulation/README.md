# 🧪 Simulation & Lab — Phase 2 du PFA

Ce dossier contient tout le nécessaire pour **construire le lab Active Directory** et **rejouer les attaques** documentées dans [`../docs/`](../docs/).

## 📌 Deux approches testées

| Approche | Guide | Statut |
|----------|-------|--------|
| **Local** (Windows + VirtualBox + WSL2) | [`01-lab-setup.md`](01-lab-setup.md) | ❌ **Abandonnée** — WinRM instable à cause de l'empilement Hyper-V/VirtualBox |
| **Azure** (VM Linux + VirtualBox) ⭐ | [`02-azure-goad.md`](02-azure-goad.md) | ✅ **Fonctionnelle** — GOAD-Light déployé avec succès |

> **Pourquoi ce choix ?** Sur Windows, WSL2 impose Hyper-V, qui rend VirtualBox+WinRM instables (les VM bootent mais Vagrant/Ansible ne les configurent pas de façon fiable). Sur une **VM Linux Azure**, tout tourne en **natif** → déploiement fiable. Le guide local est conservé comme **trace de la démarche** (utile pour le mémoire/soutenance).

## Contenu

| Fichier | Description |
|---------|-------------|
| [`02-azure-goad.md`](02-azure-goad.md) ⭐ | **Guide retenu** : déployer GOAD sur une VM Linux Azure |
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
        │   ┌──────────────┐  (Phase 3)                       │
        │   │ Wazuh / ELK  │  ← collecte logs (à venir)       │
        │   └──────────────┘                                  │
        └────────────────────────────────────────────────────┘
```

## Environnement (déployé le 2026-07-16)

- **Hôte :** VM Azure `goad-host`, Ubuntu 24.04, Standard_E4s_v3 (4 vCPU, 32 Go), nested virt ✅.
- **Base vulnérable :** GOAD-Light (Orange Cyberdefense) — 3 VM Windows Server (DC01, DC02, SRV02).
- **Instance GOAD :** `fba132-goad-light-virtualbox` · réseau 192.168.56.0/24.

> ⚠️ **Rappel légal/éthique :** ce lab est **isolé**. Les attaques ne se pratiquent QUE dans cet environnement, jamais sur un réseau réel.
