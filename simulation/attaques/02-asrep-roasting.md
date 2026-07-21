# ⚔️ Attaque 02 — AS-REP Roasting

| | |
|---|---|
| **Catégorie** | Credential Access |
| **MITRE ATT&CK** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| **Fiche théorique** | [`../../docs/02-credential-access/`](../../docs/02-credential-access/) |
| **Cible** | `north.sevenkingdoms.local` (DC02 / winterfell · 192.168.56.11) |
| **Compte attaquant** | `arya.stark` (pour l'énumération) |
| **Compte vulnérable** | `brandon.stark` (pré-authentification désactivée) |
| **Statut détection Wazuh** | ⚠️ **ANGLE MORT** — non détecté par défaut |

---

## 1. 🧠 Description (en clair)

Normalement, pour obtenir son ticket d'entrée Kerberos (TGT), un compte doit d'abord **prouver qu'il connaît son mot de passe** : c'est la **pré-authentification** (il chiffre l'heure courante avec son mot de passe). Ce mécanisme est le "cadenas" qui empêche de demander des infos sur un compte sans le connaître.

Certains comptes ont l'option **`DONT_REQ_PREAUTH`** activée → le cadenas saute. **N'importe qui, sans mot de passe**, peut alors demander leur TGT, et le contrôleur renvoie un message (**AS-REP**) contenant un bloc **chiffré avec le mot de passe du compte**. L'attaquant le récupère et le **crack hors-ligne**.

> Différence avec le Kerberoasting : ici on ne cible pas des comptes de service (SPN), mais des comptes ayant **oublié le cadenas** — et l'attaque peut se faire **sans aucun identifiant**.

---

## 2. 💻 Exécution de l'attaque

Outil impacket **`GetNPUsers.py`** (« NP » = *No Preauth*) :

```bash
GetNPUsers.py north.sevenkingdoms.local/arya.stark:Needle -dc-ip 192.168.56.11 -request
```

### Résultat
Un compte vulnérable trouvé, hash extrait :

| Compte | UAC | Indice |
|--------|-----|--------|
| `brandon.stark` | `0x410200` | le flag `0x400000` = **`DONT_REQ_PREAUTH`** (pré-auth désactivée) |

Hash obtenu au format `$krb5asrep$23$...` → le **`23`** = **RC4** = crackable hors-ligne (`hashcat -m 18200`).

![Exécution de l'AS-REP Roasting — compte brandon.stark et hash $krb5asrep$](../screenshots/attacks/attack-02-asrep-command.png)

---

## 3. 🛡️ Détection dans Wazuh — ⚠️ ANGLE MORT

La signature propre de l'AS-REP Roasting est un **Event `4768`** (demande de TGT) avec **`preAuthType = 0`** (pas de cadenas). Recherche dans Wazuh :

```
data.win.system.eventID:4768
```

**Résultat : `No results match your search criteria`.** 

→ Le DC **ne remonte AUCUN event `4768`** à Wazuh (à comparer aux `4769` qui, eux, remontent — 108 résultats). L'audit *"Kerberos Authentication Service"* n'est pas activé / non indexé.

> 📸 *Capture à ajouter (`screenshots/attacks/attack-02-asrep-wazuh.png`) : la recherche `data.win.system.eventID:4768` renvoyant « No results match your search criteria » — preuve visuelle de l'angle mort. À prendre au prochain démarrage du lab.*

### Et la connexion de l'attaquant ?
On voit bien une alerte `rule 92652` (niveau 6, "possible pass-the-hash") pour `arya.stark`, **mais** :
- elle n'est **pas spécifique** à l'AS-REP (c'est la même que pour le Kerberoasting) ;
- elle n'apparaît **que parce qu'on a utilisé des identifiants** pour énumérer. Une AS-REP faite **sans identifiants** (juste une liste de noms) **ne laisserait aucune trace** ici.

**Conclusion : avec la configuration actuelle, l'AS-REP Roasting est un angle mort de détection.**

---

## 4. 🎓 Analyse & leçon (point fort du mémoire)

> **On ne peut pas détecter ce qu'on ne journalise pas.** La détection dépend d'abord d'une **politique d'audit correcte**, *avant même* d'écrire des règles.

Cette attaque illustre une réalité SOC essentielle : un outil comme Wazuh est aveugle si les bons Event Logs Windows ne sont pas générés et collectés.

---

## 5. 🔧 Correction prévue (Phase 5)
1. **Activer l'audit TGT** sur les DC :
   ```
   auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
   ```
2. **Écrire une règle Wazuh** qui alerte sur un `4768` avec `preAuthType = 0` (haute sévérité).
3. Rejouer l'attaque → obtenir une **vraie alerte "AS-REP Roasting détecté"**.

## 6. 🛡️ Remédiation (côté défense de l'AD)
- **Ne jamais** activer `DONT_REQ_PREAUTH` (auditer régulièrement les comptes qui l'ont).
- Mots de passe forts sur ces comptes + désactiver RC4.

---

⬅️ Retour à l'[index des attaques](../04-attaques-detection.md)
