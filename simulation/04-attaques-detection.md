# ⚔️ Phase 4 — Simulation des attaques & détection Wazuh

> **But :** rejouer les attaques documentées dans [`../docs/`](../docs/) sur le lab GOAD, puis **vérifier dans Wazuh** (Phase 3) qu'elles laissent une trace détectable. C'est la démonstration centrale du PFA : **attaque → trace → détection.**

> **Méthode d'attaque :** les outils (impacket, netexec) sont installés **directement sur l'hôte Azure** (qui voit le réseau du lab `192.168.56.0/24`), pas besoin d'une VM Kali séparée.

**Comptes GOAD utilisés (lab isolé) :**
| Domaine | Compte | Mot de passe |
|---------|--------|--------------|
| `sevenkingdoms.local` (DC01 · .10) | `tywin.lannister` | `powerkingftw135` |
| `north.sevenkingdoms.local` (DC02 · .11) | `arya.stark` | `Needle` |

> ⚠️ Ces identifiants ne valent **que** pour ce lab d'entraînement isolé.

---

## 📋 Comment lire chaque fiche d'attaque
Pour chaque attaque : **1) description → 2) commande → 3) résultat → 4) détection Wazuh → 5) leçon.**
Chaque attaque a 2 captures dans [`screenshots/attacks/`](screenshots/attacks/) :
`attack-NN-<nom>-command.png` (l'attaque) et `attack-NN-<nom>-wazuh.png` (la détection).

---

# Attaque 01 — Kerberoasting

📄 Fiche théorique : [`../docs/02-credential-access/`](../docs/02-credential-access/) · **MITRE ATT&CK : T1558.003**

## 1. Description (en clair)
Un compte de service (ex. le compte qui fait tourner MSSQL) est identifié dans l'AD par un **SPN**. **N'importe quel utilisateur authentifié** peut demander un **ticket Kerberos (TGS)** pour ce SPN. Ce ticket est **chiffré avec le mot de passe du compte de service** → l'attaquant le récupère et le **crack hors-ligne** pour obtenir le mot de passe. Les comptes de service ayant souvent des mots de passe faibles et des privilèges élevés, c'est une attaque très rentable.

## 2. Commande utilisée
Depuis l'hôte Azure (compte lambda `arya.stark`) :
```bash
GetUserSPNs.py north.sevenkingdoms.local/arya.stark:Needle -dc-ip 192.168.56.11 -request
```
| Élément | Rôle |
|---------|------|
| `GetUserSPNs.py` | outil impacket |
| `arya.stark:Needle` | compte utilisateur basique (l'attaquant) |
| `-dc-ip 192.168.56.11` | le contrôleur de domaine visé (winterfell / DC02) |
| `-request` | demande réellement les tickets TGS |

## 3. Résultat
3 comptes kerberoastables trouvés et leurs tickets extraits :
| Compte | SPN | Délégation |
|--------|-----|------------|
| `sql_svc` | `MSSQLSvc/castelblack.north.sevenkingdoms.local:1433` | — |
| `sansa.stark` | `HTTP/eyrie.north.sevenkingdoms.local` | — |
| `jon.snow` | `HTTP/thewall.north.sevenkingdoms.local` | constrained |

Hashs obtenus au format `$krb5tgs$23$...` → le **`23`** = chiffrement **RC4** = crackable hors-ligne (ex. `hashcat -m 13100`).

📸 `screenshots/attacks/attack-01-kerberoasting-command.png`

## 4. Détection dans Wazuh
Recherche (module **Threat Hunting → Events**) par le compte attaquant :
```
data.win.eventdata.targetUserName:arya*
```

**Résultat :** 3 alertes de **niveau 6** correspondant aux 3 lancements de l'attaque :
| Heure | Agent | Règle | Niveau | Description |
|-------|-------|-------|--------|-------------|
| 16:49 / 17:01 / 17:20 | winterfell (DC02) | **92652** | **6** | *Successful Remote Logon Detected - User: arya.stark - NTLM authentication, possible pass-the-hash attack* |

→ Wazuh a repéré la **connexion réseau anormale** de l'outil d'attaque (impacket se connecte au DC en NTLM) et a levé une alerte de sécurité.

📸 `screenshots/attacks/attack-01-kerberoasting-wazuh.png`

**Event Windows concernés :** `4769` (demande de ticket TGS Kerberos), `4624` (connexion). Le marqueur clé du Kerberoasting est un `4769` avec **TicketEncryptionType = `0x17`** (RC4).

## 5. Leçon (important pour le mémoire)
Deux niveaux de visibilité observés :

| Ce que Wazuh voit | Règle | Niveau | Statut |
|-------------------|-------|--------|--------|
| Connexion NTLM anormale de l'attaquant | 92652 | 6 🚨 | ✅ Détecté par défaut |
| Le motif Kerberoasting *précis* (rafale de TGS RC4 sur des comptes de service) | 60106 | 3 | ⚠️ Noyé dans le trafic normal |

👉 **Le ruleset par défaut alerte sur la connexion suspecte, mais ne nomme pas explicitement "Kerberoasting".** C'est justement l'objet de la **Phase 5** : écrire une **règle Wazuh personnalisée** qui élève ces `4769 RC4` en **alerte dédiée de haute sévérité**. Cette attaque démontre *pourquoi* le tuning de règles est indispensable dans un vrai SOC.

---

## 🗺️ Suivi des attaques

| # | Attaque | MITRE | Simulée | Détectée Wazuh | Captures |
|---|---------|-------|:-------:|:--------------:|----------|
| 01 | Kerberoasting | T1558.003 | ✅ | ✅ (rule 92652) | ✅ |
| 02 | AS-REP Roasting | T1558.004 | ⬜ | ⬜ | ⬜ |
| 03 | DCSync | T1003.006 | ⬜ | ⬜ | ⬜ |
| 04 | Password Spray | T1110.003 | ⬜ | ⬜ | ⬜ |

*(à compléter au fur et à mesure)*
