# Archive — Première approche abandonnée

> **Ne pas suivre ce guide.** Ce dossier conserve la trace d'une démarche qui n'a pas fonctionné — utile pour comprendre pourquoi on a changé d'approche, et pour la soutenance.

---

## Quelle était cette première approche ?

Au départ, l'idée était de déployer le lab Active Directory (GOAD-Light) **localement sur Windows** :

```
PC Windows local
└── VirtualBox
    ├── Hyper-V (hyperviseur Windows)
    ├── WSL2 (sous-système Linux)
    └── GOAD-Light (3 VM Windows via Vagrant + Ansible)
```

En théorie, cela semblait plus simple — pas besoin d'une VM Azure, tout tourne sur le PC.

---

## Pourquoi ça n'a pas fonctionné

L'empilement `Windows + Hyper-V + WSL2 + VirtualBox + Vagrant` a créé un problème fondamental : **WinRM (le protocole de gestion distante Windows) devenait instable** dans cet environnement.

Concrètement : les VM démarraient, mais Ansible (qui configure automatiquement les domaines AD via WinRM) ne parvenait pas à les configurer de façon fiable. Les commandes semblaient réussir mais n'avaient aucun effet réel sur les machines.

Après plusieurs tentatives de correction (voir les scripts ci-dessous), le problème s'est révélé structurel — pas un bug à corriger, mais une incompatibilité entre les couches de virtualisation.

---

## Décision : migrer vers Azure

La solution retenue : déployer sur une **VM Linux sur Azure**, sans Hyper-V ni WSL2, avec VirtualBox directement sur Linux.

Résultat : GOAD-Light déployé en quelques heures, sans problème.  
→ [Voir la démarche retenue](../01-deploiement-azure.md)

---

## Contenu de ce dossier

| Fichier | Description |
|---------|-------------|
| [`lab-setup-local.md`](lab-setup-local.md) | Guide de la tentative locale (abandonné) |
| [`wsl-setup.sh`](wsl-setup.sh) | Script de provisioning WSL2 |
| [`wsl-fix-python312.sh`](wsl-fix-python312.sh) | Tentative de correction du conflit Python 3.12/WSL |
