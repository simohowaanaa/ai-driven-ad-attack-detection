<!--
  TEMPLATE de fiche d'attaque — copier ce fichier en `NN-nom-attaque.md`
  et remplir chaque section. Garder le même ordre pour toutes les fiches.
-->

# ⚔️ Attaque NN — <Nom de l'attaque>

| | |
|---|---|
| **Catégorie** | <Recon / Credential Access / Lateral Movement / Priv Esc / Persistence / Domain Trusts> |
| **MITRE ATT&CK** | [Txxxx.xxx](https://attack.mitre.org/techniques/Txxxx/) |
| **Fiche théorique** | [`../../docs/<categorie>/`](../../docs/) |
| **Cible** | <machine + IP> |
| **Compte attaquant** | <compte utilisé> |
| **Outil** | <impacket / netexec / …> |
| **Statut détection Wazuh** | <✅ Détecté / ⚠️ Angle mort / 🔄 À tester> |

---

## 1. 🧠 Description
> L'attaque en clair (une analogie simple si utile). Quel est le principe ? Pourquoi ça marche ?

## 2. 🎯 Prérequis
- Compte / droits nécessaires
- Accès réseau requis

## 3. 💻 Exécution
```bash
<commande>
```
| Élément | Rôle |
|---------|------|
| … | … |

![Exécution de l'attaque](../screenshots/attacks/attack-NN-<nom>-command.png)

## 4. 📤 Résultat
> Ce qu'on obtient (hash, accès, tickets…) et à quoi ça sert ensuite.

## 5. 🛡️ Détection dans Wazuh
**Recherche (Threat Hunting → Events) :**
```
<requête DQL>
```
**Event(s) Windows concerné(s) :** `<4xxx>` — <description>.

**Résultat :** <ce que Wazuh affiche / ne montre pas>.

![Détection dans Wazuh](../screenshots/attacks/attack-NN-<nom>-wazuh.png)

## 6. 🎓 Analyse & leçon
> Ce que le SIEM voit (ou pas), le niveau de l'alerte, et ce que ça implique pour la détection.

## 7. 🔧 Remédiation
- Comment se protéger de cette attaque côté AD / audit.

---

⬅️ Retour à l'[index des attaques](../03-attaques.md)
