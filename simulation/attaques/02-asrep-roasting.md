# ⚔️ Attaque 02 — AS-REP Roasting

| | |
|---|---|
| **Catégorie** | Credential Access |
| **MITRE ATT&CK** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| **Fiche théorique** | [`../../docs/02-credential-access/06-asrep-roasting.md`](../../docs/02-credential-access/06-asrep-roasting.md) |
| **Cible** | `north.sevenkingdoms.local` (DC02 / winterfell · 192.168.56.11) |
| **Compte attaquant** | `arya.stark` (pour l'énumération) — compte vulnérable : `brandon.stark` |
| **Outil** | impacket — `GetNPUsers.py` |
| **Statut détection Wazuh** | ⚠️ **Angle mort** — non détecté par défaut |

---

## 1. 🧠 Description
Normalement, pour obtenir son ticket d'entrée Kerberos (TGT), un compte doit d'abord **prouver qu'il connaît son mot de passe** : c'est la **pré-authentification** (le "cadenas"). Certains comptes ont l'option **`DONT_REQ_PREAUTH`** activée → le cadenas saute. **N'importe qui, sans mot de passe**, peut alors demander leur TGT, et le contrôleur renvoie un message (**AS-REP**) contenant un bloc **chiffré avec le mot de passe du compte** → l'attaquant le **crack hors-ligne**.

> Différence avec le Kerberoasting : ici on cible des comptes ayant **oublié le cadenas** (pas des comptes de service), et l'attaque peut se faire **sans aucun identifiant**.

## 2. 🎯 Prérequis
- **Aucun identifiant nécessaire** en théorie (une simple liste de noms suffit). Ici on utilise `arya.stark` pour énumérer automatiquement les comptes vulnérables.
- Accès réseau au contrôleur de domaine (port Kerberos 88).

## 3. 💻 Exécution
```bash
GetNPUsers.py north.sevenkingdoms.local/arya.stark:Needle -dc-ip 192.168.56.11 -request
```
| Élément | Rôle |
|---------|------|
| `GetNPUsers.py` | outil impacket (« NP » = *No Preauth*) |
| `arya.stark:Needle` | compte pour énumérer les comptes sans pré-auth |
| `-dc-ip 192.168.56.11` | le contrôleur de domaine ciblé (winterfell / DC02) |
| `-request` | demande les AS-REP des comptes vulnérables |

![Exécution de l'AS-REP Roasting — brandon.stark et hash $krb5asrep$](../screenshots/attacks/attack-02-asrep-command.png)

## 4. 📤 Résultat
Un compte vulnérable trouvé, hash extrait (format `$krb5asrep$23$...`, **RC4**, crackable via `hashcat -m 18200`) :

| Compte | UAC | Indice |
|--------|-----|--------|
| `brandon.stark` | `0x410200` | le flag `0x400000` = **`DONT_REQ_PREAUTH`** (pré-auth désactivée) |

## 5. 🛡️ Détection dans Wazuh — ⚠️ ANGLE MORT
**Recherche (Threat Hunting → Events) :**
```
data.win.system.eventID:4768
```
**Event(s) Windows concerné(s) :** `4768` (demande de TGT) avec **`preAuthType = 0`** = la signature de l'AS-REP.

**Résultat : `No results` !** Le DC **ne remonte AUCUN `4768`** à Wazuh (à comparer aux `4769` qui, eux, remontent). L'audit *"Kerberos Authentication Service"* n'est pas activé → **l'attaque est invisible**. La seule trace (`rule 92652` sur `arya.stark`) n'est **pas spécifique** et disparaîtrait si l'attaque était faite **sans identifiants**.

> 📸 *Capture à ajouter (`../screenshots/attacks/attack-02-asrep-wazuh.png`) : la recherche `data.win.system.eventID:4768` renvoyant « No results » — preuve visuelle de l'angle mort.*

## 6. 🎓 Analyse & leçon
> **On ne peut pas détecter ce qu'on ne journalise pas.** La détection dépend d'abord d'une **politique d'audit correcte**, *avant même* d'écrire des règles. Un SIEM est aveugle si les bons Event Logs ne sont pas générés et collectés.

## 7. 🔧 Remédiation
- **Ne jamais** activer `DONT_REQ_PREAUTH` (auditer les comptes qui l'ont).
- Mots de passe forts sur ces comptes + désactiver RC4.
- **Phase 5 :** activer l'audit `4768` (`auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable`) puis écrire une règle sur `preAuthType = 0`.

---

⬅️ Retour à l'[index des attaques](../03-attaques.md)
