# ⚔️ Attaque 07 — Abus d'ACL (GenericWrite → Group Membership)

| | |
|---|---|
| **Catégorie** | Privilege Escalation |
| **MITRE ATT&CK** | [T1222](https://attack.mitre.org/techniques/T1222/) · [T1098](https://attack.mitre.org/techniques/T1098/) |
| **Fiche théorique** | [`../../docs/04-privilege-escalation/41-acl-dacl-abuse.md`](../../docs/04-privilege-escalation/41-acl-dacl-abuse.md) |
| **Cible** | `north.sevenkingdoms.local` — groupe `domain admins` |
| **Compte attaquant** | `jon.snow` → `Domain Admin` via `GenericWrite` sur `night.king` |
| **Outil** | `net` (Windows) · impacket · BloodHound |
| **Statut détection Wazuh** | ✅ Bien détecté — Event 4728 (ajout de membre) visible |

---

## 1. 🧠 Description

> **Le concept en une phrase :** dans AD, chaque objet (compte, groupe, machine) a une liste de droits définissant qui peut le modifier — un droit `GenericWrite` sur un compte signifie qu'on peut changer son mot de passe, et donc l'usurper.

Les **ACL** (Access Control Lists) dans Active Directory définissent qui peut faire quoi sur chaque objet. Ces permissions sont souvent configurées sans en mesurer les conséquences : un helpdesk qui peut réinitialiser des mots de passe, un compte de service qui peut modifier des groupes…

**Les droits dangereux :**
- `GenericWrite` / `GenericAll` — modifier l'objet (changer le mot de passe, modifier les membres…)
- `WriteDACL` — modifier les droits de l'objet lui-même
- `ForceChangePassword` — réinitialiser le mot de passe sans connaître l'ancien

**La chaîne dans ce lab :**
1. `jon.snow` a `GenericWrite` sur `night.king` (découvert via BloodHound)
2. L'attaquant change le mot de passe de `night.king`
3. `night.king` a `GenericWrite` sur le groupe `domain admins`
4. L'attaquant ajoute `jon.snow` aux Domain Admins
5. `jon.snow` est maintenant Domain Admin

→ Escalade de privilèges complète en abusant de droits AD mal configurés.

## 2. 🎯 Prérequis

- Un **compte de domaine** avec un droit ACL abusable (trouvé via BloodHound)
- Ici : `jon.snow` → `GenericWrite` sur `night.king` → `GenericWrite` sur `domain admins`

## 3. 💻 Exécution

### Étape 1 — Identifier la chaîne d'ACL abusables avec BloodHound

BloodHound révèle le chemin `jon.snow → [GenericWrite] → night.king → [GenericWrite] → domain admins`.

![Chemin d'attaque ACL dans BloodHound](../screenshots/attacks/attack-07-acl-bloodhound.png)

### Étape 2 — Changer le mot de passe de `night.king`

```bash
net rpc password night.king 'NewPassword123!' -U 'north.sevenkingdoms.local/jon.snow%iknownothing' -S 192.168.56.11
```

`jon.snow` a `GenericWrite` sur `night.king` → il peut forcer un changement de mot de passe.

### Étape 3 — Ajouter `jon.snow` aux Domain Admins

Maintenant connecté en `night.king` :
```bash
net rpc group addmem "Domain Admins" jon.snow -U 'north.sevenkingdoms.local/night.king%NewPassword123!' -S 192.168.56.11
```

![jon.snow ajouté aux Domain Admins](../screenshots/attacks/attack-07-acl-command.png)

### Étape 4 — Vérification

```bash
net rpc group members "Domain Admins" -U 'north.sevenkingdoms.local/jon.snow%iknownothing' -S 192.168.56.11
```

→ `NORTH\jon.snow` apparaît dans la liste des Domain Admins.

## 4. 📤 Résultat

`jon.snow`, simple utilisateur du domaine au départ, est maintenant **Domain Admin** — sans exploiter aucune vulnérabilité logicielle, uniquement en abusant de droits AD mal configurés.

## 5. 🛡️ Détection dans Wazuh — ✅ bien détecté

**Recherche (Threat Hunting → Events) :**
```
data.win.system.eventID:4728 and data.win.eventdata.groupName:*Domain Admins*
```

**Event Windows concerné :** `4728` (*A member was added to a security-enabled global group*) — généré quand un utilisateur est ajouté à un groupe.

**Résultat : détecté** — l'ajout de `jon.snow` aux Domain Admins génère un événement `4728` clairement visible dans Wazuh.

![Event 4728 — jon.snow ajouté aux Domain Admins](../screenshots/attacks/attack-07-acl-wazuh.png)

**Pourquoi c'est détectable ici :** modifier l'appartenance à un groupe génère toujours un event Windows — c'est une action visible contrairement aux attaques purement réseau ou Kerberos.

**Limite :** si l'attaquant ajoute le compte, l'utilise rapidement, puis le supprime du groupe, la fenêtre de détection est courte.

## 6. 🎓 Analyse & leçon

> **Les mauvaises configurations AD sont aussi dangereuses que les failles logicielles.** Un droit `GenericWrite` accordé par inadvertance il y a 5 ans peut suffire à compromettre le domaine entier aujourd'hui. BloodHound est l'outil qui révèle ces chemins cachés.

**Ce qu'il faut retenir :**
- La détection fonctionne ici parce que l'action finale (ajout de membre) laisse une trace — mais les étapes intermédiaires (changement de mot de passe via `GenericWrite`) sont moins visibles.
- BloodHound est aussi un outil de **défense** : les équipes bleues l'utilisent pour cartographier leurs propres expositions.
- Les ACL AD sont souvent héritées et jamais réauditées — c'est un risque majeur silencieux.

## 7. 🔧 Remédiation

- **Auditer les ACL AD** régulièrement (BloodHound en mode défensif, ou `Get-DomainObjectAcl` via PowerView).
- Appliquer le **principe du moindre privilège** : supprimer tout `GenericWrite`/`GenericAll` inutile sur des objets sensibles.
- Surveiller les **ajouts aux groupes privilégiés** (4728, 4732) et alerter en temps réel.
- Activer la **protection AdminSDHolder** pour les comptes sensibles.

---

⬅️ Retour à l'[index des attaques](../03-attaques.md)
