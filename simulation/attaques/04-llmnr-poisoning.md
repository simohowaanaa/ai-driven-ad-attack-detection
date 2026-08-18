# ⚔️ Attaque 04 — LLMNR / NBT-NS Poisoning (Responder)

| | |
|---|---|
| **Catégorie** | Credential Access / Network Interception |
| **MITRE ATT&CK** | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| **Fiche théorique** | [`../../docs/02-credential-access/07-llmnr-nbtns-poisoning.md`](../../docs/02-credential-access/07-llmnr-nbtns-poisoning.md) |
| **Cible** | Tout utilisateur du réseau qui tape un nom de machine inexistant |
| **Compte attaquant** | aucun — juste un accès réseau local |
| **Outil** | `Responder` |
| **Statut détection Wazuh** | 🔴 Angle mort structurel — attaque réseau, hors périmètre des logs Windows |

---

## 1. 🧠 Description

> **Le concept en une phrase :** quand un utilisateur tape un nom de machine qui n'existe pas dans le DNS, Windows crie la question sur le réseau — l'attaquant répond "c'est moi !" et récupère le hash du mot de passe de cet utilisateur.

**LLMNR** (Link-Local Multicast Name Resolution) et **NBT-NS** sont des protocoles de secours que Windows utilise quand le DNS ne trouve pas un nom. Concrètement : si un utilisateur tape `\\serveur-partage` dans l'explorateur Windows et que `serveur-partage` n'existe pas dans le DNS, Windows envoie un message broadcast à tout le réseau : *"Est-ce que quelqu'un connaît `serveur-partage` ?"*

**Responder** répond immédiatement : *"Oui c'est moi, connecte-toi ici."* Windows envoie alors une tentative d'authentification NTLM — avec le **hash du mot de passe** de l'utilisateur.

**Ce n'est pas un exploit** — c'est juste Windows qui fonctionne normalement, et un attaquant qui intercepte une mauvaise adresse.

**Les cas qui déclenchent ça en vrai :**
- Un utilisateur tape mal un nom de partage réseau
- Un script qui pointe vers un serveur qui n'existe plus
- Une application mal configurée

## 2. 🎯 Prérequis

- Un **accès au réseau local** (même réseau que les victimes)
- Aucun compte de domaine nécessaire

## 3. 💻 Exécution

### Lancer Responder et attendre les victimes

```bash
responder -I eth0 -wrf
```

| Élément | Rôle |
|---------|------|
| `-I eth0` | interface réseau à écouter |
| `-w` | activer le proxy WPAD (autre vecteur d'interception) |
| `-r` | activer le mode NBT-NS |
| `-f` | fingerprinting des cibles |

Responder écoute en silence. Dès qu'un utilisateur tape un nom inexistant → son hash NTLMv2 apparaît dans la console.

![Responder intercepte un hash NTLMv2 en live](../screenshots/attacks/attack-04-llmnr-responder.png)

### Cracker le hash intercepté

```bash
hashcat -m 5600 hashes_ntlmv2.txt wordlist.txt
```

Si le mot de passe est dans la wordlist → compte compromis.

## 4. 📤 Résultat

Le hash NTLMv2 d'un utilisateur du réseau est intercepté. Deux options pour l'attaquant :
- **Cracker le hash** hors ligne (si mot de passe faible)
- **Relay attack** : retransmettre le hash en temps réel vers un autre service pour s'y authentifier sans même craquer

## 5. 🛡️ Détection dans Wazuh — 🔴 angle mort structurel

**Résultat : 0 hit** sur toutes les recherches.

**Pourquoi c'est un angle mort structurel :**

| Couche | Problème |
|--------|---------|
| Windows Event Logs | L'attaque se passe au niveau réseau — Windows ne loggue pas les broadcasts LLMNR/NBT-NS |
| Wazuh (agent-based) | Wazuh lit les logs Windows — s'il n'y a rien à lire, il ne peut rien détecter |
| Réseau | Il faudrait un IDS réseau (Zeek, Suricata) pour détecter les réponses Responder |

**Ce n'est pas un problème de configuration** : même avec tous les audits activés, cette attaque reste invisible pour un SIEM basé sur les logs Windows. La détection requiert une **solution réseau** (NDR — Network Detection & Response), hors périmètre de ce projet.

![Aucun log lié à l'attaque LLMNR dans Wazuh](../screenshots/attacks/attack-04-llmnr-wazuh.png)

## 6. 🎓 Analyse & leçon

> **L'attaque d'opportunité par excellence.** Pas besoin de compte, pas besoin de préparer quoi que ce soit — juste écouter. C'est souvent la première chose qu'un pentesteur fait en arrivant sur un réseau interne. Et c'est totalement invisible pour un SIEM qui ne lit que des logs Windows.

**Ce qu'il faut retenir :**
- Un SIEM est puissant, mais il a un **angle mort structurel** sur les attaques purement réseau.
- La vraie protection est de **désactiver LLMNR et NBT-NS** (ce qui n'a aucun impact négatif sur les environnements modernes avec un DNS bien configuré).
- Ce cas illustre pourquoi une défense en profondeur combine SIEM *et* NDR.

## 7. 🔧 Remédiation

- **Désactiver LLMNR** via GPO : `Computer Configuration > Administrative Templates > Network > DNS Client > Turn off Multicast Name Resolution → Enabled`
- **Désactiver NBT-NS** sur toutes les interfaces réseau (propriétés TCP/IP avancées → WINS → Disable NetBIOS over TCP/IP)
- Déployer un **IDS réseau** (Zeek, Suricata) pour détecter les broadcast Responder
- Activer **SMB Signing** pour bloquer le relay attack même si le hash est intercepté

---

⬅️ Retour à l'[index des attaques](../03-attaques.md)
