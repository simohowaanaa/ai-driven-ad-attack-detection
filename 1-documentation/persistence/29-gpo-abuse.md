# 29 — GPO Abuse

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence / Privilege Escalation |
| **Technique MITRE** | T1484.001 (Group Policy Modification) |
| **Phase kill chain** | Persistence / Lateral Movement |
| **CVE** | — |
| **Privilèges requis** | Droit d'édition sur une GPO (délégation ou DA) |
| **Impact** | Élevé (exécution de code sur tous les objets liés à la GPO) |

---

## 1. Description

Une **GPO** s'applique à toutes les machines/utilisateurs de l'OU (ou du domaine) à laquelle elle est liée. Qui peut **modifier une GPO** peut pousser : une **tâche planifiée**, un script de démarrage, un membre de groupe local (`Restricted Groups` → ajouter son compte aux admins locaux), etc. → **exécution de code à grande échelle** ou persistance. Souvent découvert via BloodHound (`GenericWrite`/`WriteDacl` sur un objet GPO).

## 2. Prérequis
- Droit d'écriture sur une GPO (`gPCFileSysPath` dans SYSVOL + objet GPC).

## 3. Procédure de simulation (lab)

```bash
# SharpGPOAbuse / pyGPOAbuse — ajouter une tâche planifiée immédiate
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author admin `
  --Command "cmd.exe" --Arguments "/c net localgroup administrators attacker /add" --GPOName "Default Domain Policy"
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **5136 / 5137** | Modification de l'objet GPO (gPCMachineExtensionNames…) |
| File (SYSVOL) | 4663 | Écriture de fichiers dans `\SYSVOL\...\Policies\{GUID}` |
| Security (DC) | 4739 | Changement de politique de domaine |
| Endpoint | 4698 | **Tâche planifiée créée** (via GPO) |

**Anomalie clé :** modification de fichiers GPO dans SYSVOL par un compte non-admin ; apparition d'une tâche planifiée poussée par GPO.

## 5. Détection

### Règle Sigma
```yaml
title: GPO Modification / Abuse
status: experimental
logsource:
    product: windows
    service: security
detection:
    gpo_obj:
        EventID: 5136
        ObjectClass: 'groupPolicyContainer'
    sysvol_write:
        EventID: 4663
        ObjectName|contains: '\SYSVOL\'
        ObjectName|contains: '\Policies\'
    condition: gpo_obj or sysvol_write
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:5136 and winlog.event_data.ObjectClass:"groupPolicyContainer"` ; écriture SYSVOL par compte inattendu.
- **QRadar :** corréler modification GPO + 4698 (tâche planifiée) sur les endpoints liés.

## 6. Contre-mesures / Hardening
- Restreindre les droits d'édition des GPO (délégation minimale, revue régulière).
- Surveiller SYSVOL et les objets GPC.
- Change control sur les GPO critiques (Default Domain/DC Policy).

## 7. Features pour l'agent IA
- Modification de GPO par un principal hors liste d'administrateurs GPO habituels.
- Écriture SYSVOL suivie de déploiement de tâches/scripts sur plusieurs endpoints (fan-out).
- Ajout via GPO de comptes à des groupes admins locaux.

## 8. Références
- https://attack.mitre.org/techniques/T1484/001/
- https://github.com/FSecureLABS/SharpGPOAbuse
