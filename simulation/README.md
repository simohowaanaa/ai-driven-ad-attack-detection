# 🧪 Simulation & Lab — Phase 2 du PFA

Ce dossier contient tout le nécessaire pour **construire le lab Active Directory** et **rejouer les attaques** documentées dans [`../docs/`](../docs/).

## Contenu

| Fichier | Description |
|---------|-------------|
| [`01-lab-setup.md`](01-lab-setup.md) | Guide pas-à-pas pour monter le lab (VirtualBox + WSL2 + GOAD-Light + Kali) |

## Architecture cible du lab

```
        PC hôte (Windows 11 · 32 Go RAM · VirtualBox)
        ┌──────────────────────────────────────────────────┐
        │   ┌────────────┐  ┌────────────┐  ┌────────────┐   │
        │   │   DC01     │  │  SRV02     │  │   KALI     │   │
        │   │ Win Server │  │ Win Server │  │ Attaquant  │   │
        │   │  (AD/DC)🎯 │  │ (victime)  │  │            │   │
        │   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘   │
        │         │ Sysmon +      │ Winlogbeat    │          │
        │         └───────┬───────┴───────────────┘          │
        │                 ▼                                  │
        │          ┌──────────────┐                          │
        │          │ ELASTIC/Kibana│  (Phase 3)               │
        │          └──────────────┘                          │
        └──────────────────────────────────────────────────┘
```

## Environnement (validé le 2026-07-15)

- **Hôte :** Windows 11, Intel i9-14900HX (24C/32T), 31.7 Go RAM, VT-x activé.
- **Disque :** C: 635 Go libres.
- **Base vulnérable :** GOAD-Light (Orange Cyberdefense) — 2 VM Windows Server.
- **Attaquant :** Kali Linux.

> ⚠️ **Rappel légal/éthique :** ce lab est **isolé**. Les attaques ne se pratiquent QUE dans cet environnement, jamais sur un réseau réel.
