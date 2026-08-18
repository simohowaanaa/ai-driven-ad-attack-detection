# ⚔️ Attaque 03 — Énumération LDAP (BloodHound / SharpHound)

| | |
|---|---|
| **Catégorie** | Reconnaissance |
| **MITRE ATT&CK** | [T1087](https://attack.mitre.org/techniques/T1087/) · [T1069](https://attack.mitre.org/techniques/T1069/) |
| **Fiche théorique** | [`../../docs/01-recon/01-ldap-enumeration.md`](../../docs/01-recon/01-ldap-enumeration.md) |
| **Cible** | `north.sevenkingdoms.local` + `sevenkingdoms.local` |
| **Compte attaquant** | `jon.snow` (compte de domaine lambda) |
| **Outil** | BloodHound · SharpHound · `ldapsearch` |
| **Statut détection Wazuh** | 🔴 Invisible — angle mort total |

---

## 1. 🧠 Description

> **Le concept en une phrase :** avant d'attaquer, l'attaquant cartographie l'environnement — qui a accès à quoi, quels chemins mènent aux comptes admin — en utilisant uniquement des fonctionnalités légitimes d'Active Directory.

Active Directory est, par conception, un **annuaire** : tous les utilisateurs authentifiés peuvent y lire des informations sur la structure du domaine (groupes, comptes, machines, relations de confiance). C'est ce qui permet à un ordinateur de savoir où se trouve son contrôleur de domaine, ou à une imprimante de valider qui peut y accéder.

**BloodHound** exploite cette fonctionnalité pour construire une **carte des chemins d'attaque** : il interroge LDAP et collecte toutes les relations (qui est admin de quoi, qui peut modifier quels comptes, quels groupes ont accès à quels serveurs), puis les visualise sous forme de graphe.

**Ce que voit l'attaquant après l'énumération :**
- La liste complète des utilisateurs, groupes, ordinateurs
- Les chemins les plus courts vers `Domain Admin` ou `Enterprise Admin`
- Les comptes à SPN (cibles du Kerberoasting)
- Les ACL abusables (cibles de l'attaque 07)

C'est souvent la **première étape** d'une intrusion — sans elle, l'attaquant navigue à l'aveugle.

## 2. 🎯 Prérequis

- Un **compte de domaine quelconque** (même sans aucun privilège)
- Un accès réseau au DC (ports LDAP 389/636)

## 3. 💻 Exécution

### Option A — BloodHound / SharpHound (cartographie graphique)

```bash
bloodhound-python -u jon.snow -p iknownothing -d north.sevenkingdoms.local \
  -dc 192.168.56.11 --zip -c All
```

→ Génère une archive ZIP avec tous les objets du domaine, importable dans BloodHound pour visualiser les chemins d'attaque.

![Cartographie BloodHound du domaine north](../screenshots/attacks/attack-03-enum-bloodhound.png)

### Option B — LDAP brut (ciblé)

```bash
ldapsearch -x -H ldap://192.168.56.11 \
  -D "jon.snow@north.sevenkingdoms.local" -w iknownothing \
  -b "DC=north,DC=sevenkingdoms,DC=local" "(objectClass=user)" sAMAccountName
```

→ Liste tous les comptes utilisateurs du domaine.

![Résultat LDAP — liste des comptes](../screenshots/attacks/attack-03-enum-ldap.png)

## 4. 📤 Résultat

Une **cartographie complète** du domaine : utilisateurs, groupes, ordinateurs, relations de confiance, ACL. L'attaquant sait maintenant précisément quelles sont les cibles prioritaires et quels chemins mènent aux privilèges les plus élevés.

## 5. 🛡️ Détection dans Wazuh — 🔴 angle mort total

**Recherches testées :**

| Recherche (DQL) | Résultat | Lecture |
|---|---|---|
| `data.win.system.eventID:4662` | **0 hit** | audit DS Access non activé → énumération LDAP invisible |
| `data.win.eventdata.subjectUserName:jon.snow` | quelques hits | logons normaux, rien sur l'énumération |

**Event Windows concerné :** `4662` (*An operation was performed on an object*) — mais l'audit **Directory Service Access** n'est pas activé par défaut, donc SharpHound interroge LDAP en silence.

![Aucune trace de l'énumération BloodHound dans Wazuh](../screenshots/attacks/attack-03-enum-wazuh.png)

**Pourquoi c'est difficile à détecter :** l'énumération LDAP utilise des requêtes parfaitement légitimes. Des outils d'administration comme RSAT ou des scripts de supervision font exactement la même chose. Il n'y a pas de "signature" — seul le volume et la vitesse peuvent trahir l'attaque.

## 6. 🎓 Analyse & leçon

> **L'étape invisible mais fondamentale.** L'énumération ne laisse aucune trace exploitable dans le SIEM par défaut — et pourtant, c'est ce qui permet à l'attaquant de planifier toute la suite. Sans cartographie, les attaques suivantes auraient été beaucoup plus lentes.

**Ce qu'il faut retenir :**
- Active Directory est conçu pour être lisible par tous les utilisateurs authentifiés — c'est une fonctionnalité, pas un bug.
- La détection comportementale (volume de requêtes LDAP inhabituel) est plus efficace que les règles de signature ici — c'est le domaine de l'agent IA (Phase 6).
- BloodHound est aussi utilisé par les équipes de défense pour cartographier leur propre exposition.

## 7. 🔧 Remédiation

- **Activer l'audit `Directory Service Access`** (4662) pour rendre les requêtes LDAP visibles.
- Mettre en place le **LDAP signing** pour empêcher les requêtes anonymes.
- Déployer des **honey accounts** (comptes leurres) dans BloodHound : si quelqu'un les vise, c'est un attaquant.
- Surveiller les volumes de requêtes LDAP inhabituels (détection comportementale, Phase 6).

---

⬅️ Retour à l'[index des attaques](../03-attaques.md)
