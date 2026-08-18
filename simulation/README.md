# Simulation — Phases 2, 3 et 4

> Ce dossier contient tout le travail pratique : construire le lab, y brancher un SIEM, puis rejouer les attaques et observer ce que Wazuh détecte — ou ne détecte pas.

---

## Pourquoi ces trois phases sont regroupées ici

Les Phases 2, 3 et 4 forment une séquence ininterrompue :

```
Phase 2                   Phase 3                     Phase 4
Construire le lab    →    Brancher le SIEM        →    Rejouer les attaques
(01-deploiement)          (02-siem-wazuh)               (03-attaques + attaques/)

Sans lab,                 Sans SIEM,                   Sans les deux,
rien à attaquer           rien à détecter               rien à analyser
```

Les résultats de Phase 4 (ce que Wazuh voit ou ne voit pas) sont exactement ce qui motive les Phases 5 et 6 — documentées dans [`../detection/`](../detection/).

---

## Phase 2 — Déploiement du lab

**Problème résolu :** on ne peut pas tester des attaques sur un vrai réseau d'entreprise. On construit donc un environnement Active Directory volontairement vulnérable, isolé, qui reproduit fidèlement un réseau d'entreprise réel.

**Solution :** [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) (Game Of Active Directory) déployé sur une VM Linux Azure avec virtualisation imbriquée.

| Fichier | Ce qu'il contient |
|---------|------------------|
| [`01-deploiement-azure.md`](01-deploiement-azure.md) | Toutes les étapes : création de la VM Azure, installation de VirtualBox/Vagrant/Ansible, déploiement de GOAD, vérification |
| [`scripts/azure-goad-setup.sh`](scripts/azure-goad-setup.sh) | Le script shell qui automatise l'installation complète sur la VM |

---

## Phase 3 — Installation du SIEM Wazuh

**Problème résolu :** le lab AD tourne, mais on n'a aucun moyen de voir ce qui se passe. Il faut un système qui collecte les logs de toutes les machines et les rende consultables.

**Solution :** Wazuh déployé sur une 4ᵉ VM du lab. Trois agents installés sur les machines Windows pour remonter tous les Event Logs en temps réel.

| Fichier | Ce qu'il contient |
|---------|------------------|
| [`02-siem-wazuh.md`](02-siem-wazuh.md) | Installation de Wazuh (manager, indexer, dashboard), déploiement des agents sur DC01, DC02 et SRV02, accès au dashboard, dépannage |
| [`scripts/start-wazuh.sh`](scripts/start-wazuh.sh) | Script de démarrage des services Wazuh |

---

## Phase 4 — Simulation des attaques

**Problème résolu :** on a un lab et un SIEM — mais est-ce que Wazuh détecte vraiment les attaques ? La réponse honnête est : *ça dépend*. Cette phase donne la réponse attaque par attaque.

**Méthode :** chaque attaque est rejouée en live depuis l'hôte Azure (qui voit le réseau du lab). On note précisément ce que Wazuh voit — ou ne voit pas — et pourquoi.

| Fichier | Ce qu'il contient |
|---------|------------------|
| [`03-attaques.md`](03-attaques.md) | L'index des 12 attaques avec leur statut de détection Wazuh |
| [`attaques/`](attaques/) | Un playbook par attaque : commandes exactes, captures Wazuh, analyse |
| [`spectre-detection.md`](spectre-detection.md) | La synthèse : 2 bien détectées, 4 partielles, 6 angles morts — et pourquoi |
| [`mitre-mapping.md`](mitre-mapping.md) | Les 12 attaques positionnées sur la matrice MITRE ATT&CK |

### Résumé des 12 attaques simulées

| # | Attaque | Résultat Phase 4 | Suite |
|:-:|---------|:----------------:|-------|
| 01 | [Kerberoasting](attaques/01-kerberoasting.md) | 🟡 Partiel | Règle 100011 (Phase 5) |
| 02 | [AS-REP Roasting](attaques/02-asrep-roasting.md) | 🔴 Invisible | Règle 100014 (Phase 5) |
| 03 | [Énumération LDAP](attaques/03-enumeration.md) | 🔴 Invisible | Agent IA (Phase 6) |
| 04 | [LLMNR Poisoning](attaques/04-llmnr-poisoning.md) | 🔴 Invisible | Non couvrable (attaque réseau) |
| 05 | [Password Spraying](attaques/05-password-spraying.md) | ✅ Détecté | — |
| 06 | [DCSync](attaques/06-dcsync.md) | 🔴 Invisible | Règle 100010 (Phase 5) |
| 07 | [Abus d'ACL](attaques/07-acl-abuse.md) | ✅ Détecté | — |
| 08 | [ADCS ESC1](attaques/08-adcs-esc1.md) | 🔴 Invisible | Règle 100012 (Phase 5) |
| 09 | [Pass-the-Hash](attaques/09-pass-the-hash.md) | 🟡 Partiel | Règle 100017 + Agent IA (Phase 6) |
| 10 | [MSSQL RCE](attaques/10-mssql-rce.md) | 🔴 Invisible | Règle 100013 (Phase 5) |
| 11 | [Golden Ticket](attaques/11-golden-ticket.md) | 🟡 Partiel | Agent IA (Phase 6) |
| 12 | [Trust inter-domaine](attaques/12-trust-inter-domaine.md) | 🟡 Partiel | Règle 100019 (Phase 5) |

**Conclusion :** sur 12 attaques, seulement 2 sont clairement détectées par Wazuh par défaut. C'est le constat qui justifie les Phases 5 et 6.

→ [Voir les règles custom et l'agent IA](../detection/)

---

## Ressources complémentaires

| Fichier | Description |
|---------|-------------|
| [`glossaire.md`](glossaire.md) | Définitions des termes techniques utilisés dans les fiches (AD, TGT, DCSync, SIEM…) |
| [`screenshots/`](screenshots/) | Toutes les captures d'écran du lab et des attaques |
| [`archive/`](archive/) | Trace de la première approche (lab local Windows) — abandonnée, conservée pour la démarche |

---

> ⚠️ **Rappel éthique :** ce lab est **isolé**. Les attaques ne se pratiquent QUE dans cet environnement, jamais sur un réseau réel.
