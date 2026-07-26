# ⚔️ Attaque 01 — Kerberoasting

| | |
|---|---|
| **Catégorie** | Credential Access |
| **MITRE ATT&CK** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| **Fiche théorique** | [`../../docs/02-credential-access/05-kerberoasting.md`](../../docs/02-credential-access/05-kerberoasting.md) |
| **Cible** | `north.sevenkingdoms.local` (DC02 / winterfell · 192.168.56.11) |
| **Compte attaquant** | `arya.stark` (utilisateur basique) |
| **Outil** | impacket — `GetUserSPNs.py` |
| **Statut détection Wazuh** | ✅ Détecté (connexion attaquant, rule 92652 niveau 6) |

---

## 1. 🧠 Description
Un **compte de service** (ex. celui qui fait tourner MSSQL) est identifié dans l'AD par un **SPN** (*Service Principal Name*). La faille : **n'importe quel utilisateur authentifié** peut demander un **ticket Kerberos (TGS)** pour ce SPN, et ce ticket est **chiffré avec le mot de passe du compte de service**. L'attaquant récupère donc un blob chiffré avec le mot de passe de la cible, puis le **crack hors-ligne** (sans alerter le domaine). Comme ces comptes ont souvent des mots de passe faibles et des privilèges élevés, l'attaque est très rentable.

## 2. 🎯 Prérequis
- **Un compte de domaine valide** (même sans privilège), ici `arya.stark`.
- Accès réseau au contrôleur de domaine (port Kerberos 88).

## 3. 💻 Exécution
```bash
GetUserSPNs.py north.sevenkingdoms.local/arya.stark:Needle -dc-ip 192.168.56.11 -request
```
| Élément | Rôle |
|---------|------|
| `GetUserSPNs.py` | outil impacket qui liste les SPN et demande les tickets |
| `arya.stark:Needle` | le compte utilisateur (l'attaquant authentifié) |
| `-dc-ip 192.168.56.11` | le contrôleur de domaine ciblé (winterfell / DC02) |
| `-request` | demande réellement les tickets TGS |

![Exécution du Kerberoasting et hashs $krb5tgs$ extraits](../screenshots/attacks/attack-01-kerberoasting-command.png)

## 4. 📤 Résultat
3 comptes kerberoastables trouvés et leurs tickets extraits (format `$krb5tgs$23$...`, le **`23`** = **RC4** = crackable via `hashcat -m 13100`) :

| Compte | SPN | Délégation |
|--------|-----|------------|
| `sql_svc` | `MSSQLSvc/castelblack.north.sevenkingdoms.local:1433` | — |
| `sansa.stark` | `HTTP/eyrie.north.sevenkingdoms.local` | — |
| `jon.snow` | `HTTP/thewall.north.sevenkingdoms.local` | constrained |

## 5. 🛡️ Détection dans Wazuh
**Recherche (Threat Hunting → Events) :**
```
data.win.eventdata.targetUserName:arya*
```
**Event(s) Windows concerné(s) :** `4769` (demande de ticket TGS), `4624` (connexion). Le marqueur du Kerberoasting est un `4769` avec **TicketEncryptionType = `0x17`** (RC4).

**Résultat :** 3 alertes de **niveau 6** (rule **92652** — *NTLM remote logon, possible pass-the-hash*) correspondant aux 3 lancements, sur l'agent **winterfell**. Wazuh a repéré la **connexion réseau anormale** de l'outil d'attaque.

![Détection dans Wazuh — alertes niveau 6 liées à arya.stark](../screenshots/attacks/attack-01-kerberoasting-wazuh.png)

## 6. 🎓 Analyse & leçon
| Ce que Wazuh voit | Règle | Niveau | Statut |
|-------------------|-------|--------|--------|
| Connexion NTLM anormale de l'attaquant | 92652 | 6 🚨 | ✅ Détecté par défaut |
| Le motif Kerberoasting *précis* (rafale de TGS RC4) | 60106 | 3 | ⚠️ Noyé dans le trafic normal |

👉 Le ruleset par défaut alerte sur la connexion suspecte, mais **ne nomme pas explicitement "Kerberoasting"**. Créer une règle personnalisée qui élève les `4769` RC4 en alerte dédiée sera l'objet de la **Phase 5**.

## 7. 🔧 Remédiation
- Utiliser des **gMSA** (mots de passe gérés, longs, tournants) pour les comptes de service.
- Désactiver **RC4** au profit d'**AES** (tickets non triviaux à cracker).
- Surveiller les **rafales de 4769 en RC4** demandées par un compte utilisateur (règle Phase 5).

---

⬅️ Retour à l'[index des attaques](../03-attaques.md)
