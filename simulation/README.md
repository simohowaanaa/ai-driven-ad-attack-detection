# 🧪 Simulation & Lab — Phases 2 à 4 du PFA

Ce dossier contient tout le nécessaire pour **construire le lab Active Directory** (Phase 2), y **brancher un SIEM Wazuh** (Phase 3), et **rejouer les attaques** documentées dans [`../docs/`](../docs/) en vérifiant leur détection (Phase 4).

**Avancement :** ✅ Phase 2 (lab GOAD-Light sur Azure) · ✅ Phase 3 (SIEM Wazuh + 3 agents) · 🔄 Phase 4 (simulation des attaques & détection — en cours).

---

## 📂 Contenu du dossier

| Fichier / dossier | Description |
|-------------------|-------------|
| [`01-deploiement-azure.md`](01-deploiement-azure.md) 🏗️ | **Phase 2** — déployer le lab GOAD-Light sur une VM Linux Azure |
| [`02-siem-wazuh.md`](02-siem-wazuh.md) 🛡️ | **Phase 3** — installer le SIEM Wazuh (déploiement + accès + dépannage) |
| [`03-attaques.md`](03-attaques.md) ⚔️ | **Phase 4** — index des attaques simulées + roadmap + détection Wazuh |
| [`attaques/`](attaques/) | 📁 **Une fiche par attaque** (avec captures intégrées) + le [template](attaques/00-TEMPLATE.md) |
| [`azure-goad-setup.sh`](azure-goad-setup.sh) | Script d'install (VirtualBox/Vagrant/Ansible/GOAD) sur la VM Azure |
| [`screenshots/`](screenshots/) | 📸 Captures du lab et des attaques |
| [`archive/`](archive/) | 🗄️ Approche locale **abandonnée** (conservée comme trace de la démarche) |

---

## 🏗️ Architecture du lab (Azure)

```
        VM Azure Linux (Ubuntu 24.04 · Standard_E4s_v3 · 32 Go)
        ┌────────────────────────────────────────────────────┐
        │   VirtualBox (natif)                                │
        │   ┌────────────┐  ┌────────────┐  ┌────────────┐    │
        │   │   DC01     │  │   DC02     │  │  SRV02     │    │
        │   │ kingslding │  │ winterfell │  │ castelblack│    │
        │   │  .10       │  │  .11       │  │  .22 (MSSQL)│   │
        │   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │
        │         │ agent         │ agent         │ agent     │
        │         └───────────────┼───────────────┘           │
        │                  ┌──────▼───────┐  ✅ Phase 3       │
        │                  │  Wazuh  .51   │  ← SIEM           │
        │                  └───────────────┘                  │
        │        Réseau host-only 192.168.56.0/24             │
        └────────────────────────────────────────────────────┘
                  ▲ SSH + tunnel (depuis le PC)
```

- **`sevenkingdoms.local`** : DC01 (kingslanding) · **`north.sevenkingdoms.local`** : DC02 (winterfell) — reliés par un **trust**.
- **SRV02** (castelblack) : serveur membre + **MSSQL**.
- **Wazuh** (192.168.56.51) : collecte les logs des 3 machines et lève les alertes.

---

## ⚙️ Environnement

- **Hôte :** VM Azure `goad-host`, Ubuntu 24.04, Standard_E4s_v3 (4 vCPU, 32 Go), nested virt ✅ *(déployé le 2026-07-16)*.
- **Base vulnérable :** GOAD-Light (Orange Cyberdefense), instance `fba132-goad-light-virtualbox`.
- **SIEM :** Wazuh (indexer + manager + dashboard) + agents sur les 3 machines *(déployé le 2026-07-17)*.
- **Outils d'attaque :** impacket (installés sur l'hôte Azure).

> ⚠️ **Rappel légal/éthique :** ce lab est **isolé**. Les attaques ne se pratiquent QUE dans cet environnement, jamais sur un réseau réel.
