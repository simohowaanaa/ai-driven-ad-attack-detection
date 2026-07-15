# 34 — sAMAccountName Spoofing (CVE-2021-42278)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation |
| **Technique MITRE** | T1078 / T1068 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | **CVE-2021-42278** |
| **Privilèges requis** | Compte de domaine standard + MachineAccountQuota > 0 |
| **Impact** | Critique (composant de la chaîne noPac) |

---

## 1. Description

Cette fiche isole la **primitive** exploitée par noPac (voir fiche 23) : avant le correctif, AD **ne validait pas** que le `sAMAccountName` d'un compte machine se terminait par `$`. Un attaquant peut donc renommer un compte machine qu'il contrôle pour qu'il **usurpe l'identité d'un compte machine privilégié** (typiquement un DC). Couplée à **CVE-2021-42287** (recherche de compte par nom sans `$`), elle permet l'élévation vers DA. On la documente séparément car la **détection porte spécifiquement sur le renommage/format du sAMAccountName**.

## 2. Prérequis
- Compte de domaine standard, `ms-DS-MachineAccountQuota > 0`.
- DC non patché (KB de novembre 2021).

## 3. Procédure de simulation (lab)

```bash
# Créer un compte machine puis le renommer sans le "$"
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Pass123' domaine.local/user:pass
renameMachine.py -current-name 'EVIL$' -new-name 'DC01' domaine.local/user:pass
# → puis chaîne S4U (cf. fiche 23 noPac)
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4781** | **The name of an account was changed** (sAMAccountName) |
| Security (DC) | 5136 | Modification de l'attribut `sAMAccountName` |
| Security (DC) | 4741 | Création du compte machine |

**Anomalie clé :** compte machine dont le nouveau `sAMAccountName` **ne finit pas par `$`** et/ou **coïncide avec un nom de DC**.

## 5. Détection

### Règle Sigma
```yaml
title: sAMAccountName Spoofing - Machine Account Renamed Without Trailing $
status: experimental
logsource:
    product: windows
    service: security
detection:
    rename:
        EventID: 4781
    attr:
        EventID: 5136
        AttributeLDAPDisplayName: 'sAMAccountName'
        AttributeValue|endswith: '$'
    # cible : nouvelle valeur SANS $ alors que c'est un compte machine
    condition: rename or (attr and not attr)
level: high
```
> Implémentation pratique : alerter sur tout 4781 où l'`OldTargetUserName` finit par `$` mais le `NewTargetUserName` **ne finit pas** par `$`.

### Traduction SIEM
- **Elastic :** `event.code:4781` avec `OldTargetUserName` en `*$` et `NewTargetUserName` non `*$`.
- **QRadar :** règle custom sur le format du sAMAccountName lors du renommage.

## 6. Contre-mesures / Hardening
- **Patcher** CVE-2021-42278/42287.
- **MachineAccountQuota = 0**.
- Alerter sur 4781 concernant des comptes machine.

## 7. Features pour l'agent IA
- Renommage (4781) d'un compte machine vers un nom sans `$` (feature booléenne).
- Similarité du nouveau nom avec un nom de DC (distance de chaîne).
- Séquence create(4741) → rename(4781) → S4U par un utilisateur standard.

## 8. Références
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278
- Voir fiche **23 — noPac**
