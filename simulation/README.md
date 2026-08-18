# Simulation — Lab & Attaques (Phases 2 à 4)

Ce dossier couvre le déploiement du lab Active Directory vulnérable (Phase 2), l'installation du SIEM Wazuh (Phase 3), et la simulation des 12 attaques avec analyse de détection (Phase 4).

> Les règles custom et l'agent IA (Phases 5-6) sont dans [`../detection/`](../detection/).

---

## Fichiers de référence

| Fichier | Phase | Description |
|---------|:-----:|-------------|
| [`01-deploiement-azure.md`](01-deploiement-azure.md) | **2** | Déploiement GOAD-Light sur VM Azure (VirtualBox + Vagrant + Ansible) |
| [`02-siem-wazuh.md`](02-siem-wazuh.md) | **3** | Installation Wazuh (indexer + manager + dashboard + 3 agents Windows) |
| [`03-attaques.md`](03-attaques.md) | **4** | Index des 12 attaques simulées + résultats de détection Wazuh native |

**Ressources transverses :**

| Fichier | Description |
|---------|-------------|
| [`attaques/`](attaques/) | 12 playbooks d'attaques (commandes + captures Wazuh intégrées) |
| [`spectre-detection.md`](spectre-detection.md) | Synthèse : 2 détectés / 4 partiels / 6 angles morts |
| [`mitre-mapping.md`](mitre-mapping.md) | Mapping MITRE ATT&CK des 12 attaques |
| [`glossaire.md`](glossaire.md) | Glossaire AD, Kerberos, Wazuh |
| [`scripts/`](scripts/) | Scripts shell : déploiement Azure et démarrage Wazuh |
| [`screenshots/`](screenshots/) | Captures du lab Azure et des attaques |
| [`archive/`](archive/) | Approche locale Windows abandonnée (conservée comme trace) |

---

## Architecture du lab

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
        │                  │ Wazuh  .51  │  ← SIEM                │
        │                  └─────────────┘                        │
        │         Réseau host-only 192.168.56.0/24                │
        └─────────────────────────────────────────────────────────┘
                  ▲ SSH + tunnel depuis le PC local
```

- **`sevenkingdoms.local`** : DC01 (kingslanding · .10)
- **`north.sevenkingdoms.local`** : DC02 (winterfell · .11) — reliés par un trust inter-domaine
- **SRV02** (castelblack · .22) : serveur membre + MSSQL Server
- **Wazuh** (.51) : collecte les logs des 3 machines, héberge les règles custom

---

## Résultats Phase 4 (détection native Wazuh)

```
12 attaques  →  2 détectées  +  4 partielles  +  6 angles morts
```

Les 6 angles morts sont comblés en Phases 5 et 6 — voir [`../detection/`](../detection/).

> ⚠️ **Cadre éthique :** lab isolé, volontairement vulnérable (GOAD). Toutes les attaques sont réalisées uniquement dans cet environnement, à des fins de recherche défensive.
