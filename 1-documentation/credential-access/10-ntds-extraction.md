# 10 — NTDS.dit Extraction

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1003.003 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Administrateur / SYSTEM sur un DC |
| **Impact** | Critique (tous les hashes du domaine) |

---

## 1. Description

**`NTDS.dit`** est la base de données AD stockée sur chaque DC ; elle contient **les hashes de tous les comptes du domaine** (chiffrés avec la clé BootKey/SYSTEM). Un attaquant admin d'un DC peut copier ce fichier (via **Volume Shadow Copy** pour contourner le verrou), extraire SYSTEM, et déchiffrer offline tous les hashes — dont **krbtgt** (→ Golden Ticket).

## 2. Prérequis
- Accès admin/SYSTEM sur un contrôleur de domaine.

## 3. Procédure de simulation (lab)

```powershell
# Copie via Volume Shadow Copy (fichier normalement verrouillé)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\
reg save HKLM\SYSTEM C:\temp\SYSTEM

# ntdsutil (méthode native)
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ifm" q q
```
```bash
# Extraction offline des hashes
secretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security | 4688 / Sysmon 1 | Exécution de `vssadmin`, `ntdsutil`, `esentutl` |
| Security | 8222 / System 4098 | Création d'un Volume Shadow Copy |
| Security | 4663 | Accès au fichier `NTDS.dit` |
| Security | 4104 | PowerShell Script Block (si scripté) |

**Anomalie clé :** création de VSS + accès à `NTDS.dit` ou exécution de `ntdsutil ... ifm` sur un DC.

## 5. Détection

### Règle Sigma
```yaml
title: NTDS.dit Extraction via VSS / ntdsutil
status: stable
logsource:
    product: windows
    category: process_creation
detection:
    vss:
        CommandLine|contains|all:
            - 'vssadmin'
            - 'create'
            - 'shadow'
    ntdsutil:
        CommandLine|contains|all:
            - 'ntdsutil'
            - 'ifm'
    esentutl:
        CommandLine|contains: 'ntds.dit'
    condition: vss or ntdsutil or esentutl
level: critical
```

### Traduction SIEM
- **Elastic :** `process.command_line:(*vssadmin*create*shadow* or *ntdsutil*ifm* or *ntds.dit*)`
- **QRadar :** corréler exécution sur un hôte de la table des DC.

## 6. Contre-mesures / Hardening
- Restreindre/superviser l'accès physique et admin aux DC (Tiering, PAW).
- Alerter sur toute création de VSS et usage de `ntdsutil ifm` sur DC.
- Chiffrement des sauvegardes contenant NTDS.dit.

## 7. Features pour l'agent IA
- Exécution de `vssadmin`/`ntdsutil`/`esentutl` sur un DC (rare = fort signal).
- Accès au fichier NTDS.dit par un process non-AD.
- Corrélation avec exfiltration / mouvement ultérieur.

## 8. Références
- https://attack.mitre.org/techniques/T1003/003/
- https://www.thehacker.recipes/ad/movement/credentials/dumping/ntds
