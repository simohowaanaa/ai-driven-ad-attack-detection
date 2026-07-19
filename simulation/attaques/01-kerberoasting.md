# ⚔️ Attaque 01 — Kerberoasting

| | |
|---|---|
| **Catégorie** | Credential Access |
| **MITRE ATT&CK** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| **Fiche théorique** | [`../../docs/02-credential-access/`](../../docs/02-credential-access/) |
| **Cible** | `north.sevenkingdoms.local` (DC02 / winterfell · 192.168.56.11) |
| **Compte attaquant** | `arya.stark` (utilisateur basique) |
| **Statut détection Wazuh** | ✅ Détecté (rule 92652, niveau 6) |

---

## 1. 🧠 Description (en clair)

Un **compte de service** (ex. celui qui fait tourner MSSQL) est identifié dans l'AD par un **SPN** (*Service Principal Name*). La faille : **n'importe quel utilisateur authentifié** peut demander un **ticket Kerberos (TGS)** pour ce SPN, et ce ticket est **chiffré avec le mot de passe du compte de service**.

L'attaquant récupère donc un blob chiffré avec le mot de passe de la cible, puis le **crack hors-ligne** (sans alerter le domaine). Comme les comptes de service ont souvent des mots de passe faibles et des privilèges élevés, l'attaque est très rentable.

---

## 2. 💻 Exécution de l'attaque

Depuis l'hôte Azure (outil **impacket**), avec le compte basique `arya.stark` :

```bash
GetUserSPNs.py north.sevenkingdoms.local/arya.stark:Needle -dc-ip 192.168.56.11 -request
```

| Élément | Rôle |
|---------|------|
| `GetUserSPNs.py` | outil impacket qui liste les SPN et demande les tickets |
| `arya.stark:Needle` | le compte utilisateur (l'attaquant authentifié) |
| `-dc-ip 192.168.56.11` | le contrôleur de domaine ciblé (winterfell / DC02) |
| `-request` | demande réellement les tickets TGS |

### Résultat

3 comptes kerberoastables trouvés, tickets extraits au format `$krb5tgs$23$...` (le **`23`** = chiffrement **RC4** = crackable hors-ligne via `hashcat -m 13100`) :

| Compte | SPN | Délégation |
|--------|-----|------------|
| `sql_svc` | `MSSQLSvc/castelblack.north.sevenkingdoms.local:1433` | — |
| `sansa.stark` | `HTTP/eyrie.north.sevenkingdoms.local` | — |
| `jon.snow` | `HTTP/thewall.north.sevenkingdoms.local` | constrained |

![Exécution du Kerberoasting et hashs $krb5tgs$ extraits](../screenshots/attacks/attack-01-kerberoasting-command.png)

---

## 3. 🛡️ Détection dans Wazuh

Module **Threat Hunting → Events**, recherche par le compte attaquant :

```
data.win.eventdata.targetUserName:arya*
```

**Résultat :** 3 alertes de **niveau 6** correspondant aux 3 lancements de l'attaque, sur l'agent **winterfell** :

| Heure | Règle | Niveau | Description |
|-------|-------|--------|-------------|
| 16:49 / 17:01 / 17:20 | **92652** | **6** 🚨 | *Successful Remote Logon Detected - User: arya.stark - NTLM authentication, possible pass-the-hash attack* |

Wazuh a repéré la **connexion réseau anormale** de l'outil d'attaque (impacket se connecte au DC en NTLM pour énumérer les SPN) et a levé une alerte de sécurité.

![Détection dans Wazuh — alertes niveau 6 liées à arya.stark](../screenshots/attacks/attack-01-kerberoasting-wazuh.png)

**Events Windows concernés :** `4769` (demande de ticket TGS Kerberos) · `4624` (connexion). Le marqueur du Kerberoasting est un `4769` avec **TicketEncryptionType = `0x17`** (RC4).

---

## 4. 🎓 Analyse & leçon

Deux niveaux de visibilité observés :

| Ce que Wazuh voit | Règle | Niveau | Statut |
|-------------------|-------|--------|--------|
| Connexion NTLM anormale de l'attaquant | 92652 | 6 🚨 | ✅ Détecté par défaut |
| Le motif Kerberoasting *précis* (rafale de TGS RC4 sur comptes de service) | 60106 | 3 | ⚠️ Noyé dans le trafic normal |

👉 **Le ruleset par défaut alerte sur la connexion suspecte, mais ne nomme pas explicitement "Kerberoasting".** Créer une **règle Wazuh personnalisée** qui élève les `4769` RC4 sur comptes de service en **alerte dédiée de haute sévérité** sera l'objet de la **Phase 5**. Cette attaque démontre concrètement *pourquoi* le tuning de règles est indispensable dans un SOC.

---

## 5. 🔧 Remédiation (côté défense)
- Utiliser des **gMSA** (mots de passe gérés, longs et tournants) pour les comptes de service.
- Désactiver **RC4** au profit d'**AES** (les tickets ne seraient plus facilement crackables).
- Surveiller les **rafales de 4769 en RC4** demandées par un compte utilisateur → règle de détection (Phase 5).

---

⬅️ Retour à l'[index des attaques](../04-attaques-detection.md)
