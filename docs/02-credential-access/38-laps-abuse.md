# 38 — LAPS Password Abuse

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1552 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Droit de lecture sur l'attribut `ms-Mcs-AdmPwd` (délégation mal configurée) |
| **Impact** | Élevé (mot de passe admin local d'une machine) |

---

## 1. Description

**LAPS** (Local Administrator Password Solution) est une **bonne pratique** : il génère un mot de passe **unique et aléatoire** pour l'admin local de chaque machine, stocké dans un attribut AD (`ms-Mcs-AdmPwd`). Le problème : cet attribut est **lisible en clair** par ceux qui en ont le droit. Si la **délégation est trop large** (trop de comptes peuvent le lire), un attaquant récupère le mot de passe admin local d'une machine cible. Ironie : un outil de sécurité devient une source de credentials si mal délégué.

## 2. Prérequis
- Droit de lecture sur `ms-Mcs-AdmPwd` (souvent découvert via BloodHound).

## 3. Procédure de simulation (lab)

```bash
# Lire le mot de passe LAPS d'une machine
nxc ldap 10.0.0.10 -u othmane -p Marketing2025 -M laps
# ou
pyLAPS.py --action get -d datacorp.local -u othmane -p Marketing2025
```

**Résultat :** `PC-DESIGN-07 → LAPS password: X9$kL2!mQ...`

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4662 | Lecture de l'attribut `ms-Mcs-AdmPwd` |
| Security (DC) | 4104 | (si via PowerShell) |

**Anomalie :** lecture de `ms-Mcs-AdmPwd` par un compte hors de la délégation légitime, ou **lecture en masse** (plusieurs machines).

## 5. Détection

### Règle Sigma
```yaml
title: LAPS Password Read (ms-Mcs-AdmPwd)
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains: 'ms-Mcs-AdmPwd'
    condition: selection
level: medium
```

### Traduction SIEM
- **Elastic :** `event.code:4662 and winlog.event_data.Properties:*ms-Mcs-AdmPwd*`
- **QRadar :** alerter si un même compte lit le LAPS de **plusieurs** machines en peu de temps.

## 6. Contre-mesures / Hardening
- **Auditer la délégation** de lecture de `ms-Mcs-AdmPwd` (principe du moindre privilège).
- Utiliser **Windows LAPS** (moderne, chiffrement du mot de passe dans AD).
- Activer l'audit de lecture de l'attribut.

## 7. Features pour l'agent IA
- Nombre de machines dont le LAPS est lu par un même compte / fenêtre (lecture en masse = 🚨).
- Compte lecteur hors du groupe de délégation attendu.
- Corrélation : lecture LAPS → logon admin sur la machine correspondante.

## 8. Références
- https://attack.mitre.org/techniques/T1552/
- https://www.thehacker.recipes/ad/movement/credentials/dumping/laps
