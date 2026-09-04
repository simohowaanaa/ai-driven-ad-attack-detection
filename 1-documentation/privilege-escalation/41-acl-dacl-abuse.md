# 41 — ACL / DACL Abuse (GenericAll, WriteDACL, WriteOwner…)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation / Persistence |
| **Technique MITRE** | T1222 / T1098 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | — |
| **Privilèges requis** | Un droit d'écriture mal placé sur un objet AD |
| **Impact** | Élevé à Critique (chaînes d'ACL menant à Domain Admin) |

---

## 1. Description

Chaque objet AD (utilisateur, groupe, GPO, ordinateur…) a une **liste de contrôle d'accès (DACL)** définissant qui peut faire quoi. Des **droits mal attribués** créent des **chemins d'attaque**. C'est le cœur de ce que **BloodHound** révèle. Les droits abusables les plus courants :

| Droit (arête BloodHound) | Ce que l'attaquant peut faire |
|--------------------------|-------------------------------|
| **GenericAll** | Contrôle total de l'objet (tout faire) |
| **GenericWrite** | Écrire des attributs (SPN → Kerberoast ciblé, KeyCredentialLink → Shadow Creds) |
| **WriteDACL** | Modifier la DACL → s'octroyer plus de droits |
| **WriteOwner** | Devenir propriétaire de l'objet → puis WriteDACL |
| **ForceChangePassword** | Réinitialiser le mot de passe de la cible |
| **AddMember** | S'ajouter à un groupe (ex. Domain Admins) |
| **AddSelf** | S'ajouter soi-même à un groupe |

En **enchaînant** ces droits (`othmane` → WriteDACL sur un groupe → AddMember → Domain Admins), on remonte jusqu'à DA.

## 2. Prérequis
- Au moins un droit d'écriture exploitable sur un objet (souvent découvert via BloodHound).

## 3. Procédure de simulation (lab)

```bash
# Exemple : ForceChangePassword sur un compte cible
net rpc password "cible" "NouveauPass1!" -U datacorp.local/othmane%Marketing2025 -S dc01

# Exemple : s'ajouter à un groupe (AddMember) via bloodyAD
bloodyAD -u othmane -p Marketing2025 -d datacorp.local --host dc01 add groupMember "Domain Admins" othmane

# Exemple : GenericWrite → poser un SPN puis Kerberoast ciblé (targeted Kerberoasting)
targetedKerberoast.py -u othmane -p Marketing2025 -d datacorp.local
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **5136** | Modification d'objet AD (DACL, appartenance, attribut) |
| Security (DC) | **4728 / 4732 / 4756** | Ajout d'un membre à un groupe (global/local/universel) |
| Security (DC) | **4724** | Réinitialisation de mot de passe (ForceChangePassword) |
| Security (DC) | 4738 | Modification d'un compte utilisateur |

**Anomalie :** ajout d'un compte à un **groupe privilégié**, modification de DACL, reset de mot de passe par un compte non-admin.

## 5. Détection

### Règle Sigma
```yaml
title: ACL Abuse - Privileged Group Change / DACL Modification
status: experimental
logsource:
    product: windows
    service: security
detection:
    group_add:
        EventID:
            - 4728
            - 4732
            - 4756
        TargetUserName|contains:
            - 'Domain Admins'
            - 'Enterprise Admins'
            - 'Administrators'
    dacl_mod:
        EventID: 5136
        AttributeLDAPDisplayName: 'nTSecurityDescriptor'
    condition: group_add or dacl_mod
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:(4728 or 4732 or 4756) and winlog.event_data.TargetUserName:("Domain Admins" or "Enterprise Admins")`
- **QRadar :** alerter sur tout ajout à un groupe privilégié + modification de DACL par un compte non administrateur.

## 6. Contre-mesures / Hardening
- **Auditer les ACL** régulièrement (BloodHound côté défense, PingCastle).
- Retirer les droits excessifs (moindre privilège).
- Surveiller les changements d'appartenance aux groupes privilégiés (Tier 0).

## 7. Features pour l'agent IA
- Ajout à un groupe privilégié par un compte non-admin (feature booléenne forte).
- Modification de DACL / propriétaire sur des objets sensibles.
- Reset de mot de passe (4724) hors help-desk habituel.
- Séquence : WriteOwner → WriteDACL → AddMember (chaîne d'escalade).

## 8. Références
- https://bloodhound.specterops.io/resources/edges/overview
- https://www.thehacker.recipes/ad/movement/dacl
