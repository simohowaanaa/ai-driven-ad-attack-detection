# ⚔️ Attaque 06 — DCSync

| | |
|---|---|
| **Catégorie** | Credential Access |
| **MITRE ATT&CK** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| **Fiche théorique** | [`../../docs/02-credential-access/08-dcsync.md`](../../docs/02-credential-access/08-dcsync.md) |
| **Cible** | `north.sevenkingdoms.local` (DC02 / winterfell · 192.168.56.11) |
| **Compte attaquant** | `eddard.stark` (**Domain Admin**) |
| **Outil** | impacket — `secretsdump.py` |
| **Statut détection Wazuh** | ⚠️ **Angle mort critique** — non détecté par défaut |

---

## 1. 🧠 Description
Les contrôleurs de domaine se **synchronisent** en permanence via un mécanisme de **réplication** (ils s'échangent les données de l'AD). **DCSync** consiste, pour un attaquant privilégié, à **se faire passer pour un contrôleur de domaine** et à demander à un vrai DC de lui **répliquer les secrets** — c'est-à-dire les **hashs de mots de passe de TOUS les comptes**. Le DC obéit car la demande semble légitime.

> C'est **furtif** : aucun code exécuté sur le DC, aucun fichier touché — juste une requête réseau qui ressemble à de la réplication normale.

## 2. 🎯 Prérequis
- Un compte disposant du droit **"Replicating Directory Changes"** (+ *…-All*) — les **Domain Admins** l'ont par défaut. Ici : `eddard.stark`.
- Accès réseau au contrôleur de domaine.

## 3. 💻 Exécution
```bash
secretsdump.py north.sevenkingdoms.local/eddard.stark:'FightP3aceAndHonor!'@192.168.56.11 -just-dc
```
| Élément | Rôle |
|---------|------|
| `secretsdump.py` | outil impacket |
| `eddard.stark:'FightP3aceAndHonor!'` | compte **Domain Admin** (droit de réplication) |
| `@192.168.56.11` | le DC ciblé (winterfell / DC02) |
| `-just-dc` | active le mode **DCSync** (dump via réplication) |

![Exécution de DCSync — dump de tous les hashs du domaine](../screenshots/attacks/attack-06-dcsync-command.png)

## 4. 📤 Résultat
**Compromission totale du domaine** : tous les hashs NTLM + clés Kerberos extraits, dont :

| Compte | Importance |
|--------|-----------|
| `krbtgt:502:...` | 👑 **le trophée** — permet de forger des **Golden Tickets** (contrôle total et permanent) |
| `Administrator:500:...` | admin local du DC |
| tous les utilisateurs + comptes machine (`WINTERFELL$`, `CASTELBLACK$`…) | l'intégralité du domaine |

## 5. 🛡️ Détection dans Wazuh — ⚠️ ANGLE MORT CRITIQUE
**Recherche (Threat Hunting → Events) :**
```
data.win.system.eventID:4662
```
**Event Windows concerné :** `4662` (*An operation was performed on an object*) avec les **GUID de réplication** (`DS-Replication-Get-Changes`) = la signature du DCSync.

**Résultat : `No results` !** L'audit *"Directory Service Access"* n'est **pas activé** → **DCSync est totalement invisible**. La seule trace (`eddard.stark` qui se connecte) est **noyée dans le bruit** : `eddard.stark` est un **bot GOAD** qui s'authentifie toutes les 5 min (43 événements `4634`/logon sans rapport avec l'attaque).

![Aucun event 4662 dans Wazuh — DCSync invisible](../screenshots/attacks/attack-06-dcsync-wazuh.png)

## 6. 🎓 Analyse & leçon
> **L'une des attaques les plus dévastatrices (compromission totale) est totalement invisible** avec la configuration par défaut. C'est la **justification n°1 de la Phase 5** : sans audit `4662` ni règle dédiée, un SIEM ne voit pas le vol de tous les mots de passe du domaine.

C'est le point le plus marquant de la démonstration : **détecter DCSync est possible, mais uniquement si on prépare le terrain** (audit + règle) — ce que le déploiement standard ne fait pas.

## 7. 🔧 Remédiation
- **Restreindre** le droit "Replicating Directory Changes" aux seuls DC (auditer qui le possède).
- **Phase 5 :** activer l'audit *Directory Service Access* (`auditpol /set /subcategory:"Directory Service Access" /success:enable`) puis écrire une règle Wazuh qui alerte sur un `4662` avec les GUID de réplication demandé par un compte **non-DC**.
- Solutions avancées : détection comportementale (un compte non-DC qui réplique = anomalie forte).

---

⬅️ Retour à l'[index des attaques](../03-attaques.md)
