# 16 — PsExec / WMI / WinRM Lateral Movement

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Lateral Movement / Execution |
| **Technique MITRE** | T1021.002 (SMB), T1021.006 (WinRM), T1047 (WMI) |
| **Phase kill chain** | Lateral Movement |
| **CVE** | — |
| **Privilèges requis** | Droits admin sur la machine cible |
| **Impact** | Élevé (exécution de code à distance) |

---

## 1. Description

Après avoir obtenu des credentials, l'attaquant exécute des commandes à distance via des mécanismes **légitimes** d'administration :
- **PsExec / SMB** : crée un service distant (`\\host\ADMIN$`, service `PSEXESVC`).
- **WMI** : `Win32_Process.Create` via RPC/DCOM.
- **WinRM** : PowerShell Remoting (5985/5986).

Ces techniques sont difficiles à distinguer de l'administration normale → détection par **contexte** (source, compte, fréquence).

## 2. Prérequis
- Credentials valides avec droits admin sur la cible.
- Services correspondants ouverts (445 / 135 / 5985).

## 3. Procédure de simulation (lab)

```bash
psexec.py domaine.local/admin:pass@10.0.0.20
wmiexec.py domaine.local/admin:pass@10.0.0.20
evil-winrm -i 10.0.0.20 -u admin -p pass
```
```powershell
Invoke-Command -ComputerName SRV01 -ScriptBlock { whoami }   # WinRM natif
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (cible) | 4624 | Logon Type 3 |
| Security (cible) | **7045** | **Service installé** (PsExec → PSEXESVC) |
| Security (cible) | 4697 | Service installé (audit) |
| Sysmon | 1 | `services.exe` → `cmd.exe`/`powershell.exe` (PsExec), `WmiPrvSE.exe` → child (WMI), `wsmprovhost.exe` (WinRM) |
| WinRM | 4103/4104 | PowerShell remoting |

**Anomalies :** parent-child inhabituel (`WmiPrvSE.exe` → `cmd.exe`), service au nom aléatoire, `wsmprovhost.exe` lançant des commandes.

## 5. Détection

### Règle Sigma (PsExec)
```yaml
title: PsExec Service Installation
status: stable
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains: 'PSEXESVC'
    generic:
        EventID: 7045
        ServiceFileName|contains: '\\\\'   # binaire lancé depuis un partage
    condition: selection or generic
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:7045 and winlog.event_data.ServiceName:*PSEXESVC*` ; process ancestry `WmiPrvSE.exe`→shell.
- **QRadar :** corréler 4624 Type 3 + 7045 + création de process shell.

## 6. Contre-mesures / Hardening
- Restreindre les admins locaux (Tiering, LAPS).
- Journaliser/limiter WinRM et WMI aux hôtes d'admin (JEA).
- Segmentation, pare-feu hôte.

## 7. Features pour l'agent IA
- Relations parent-child rares (`WmiPrvSE`/`services.exe`→shell).
- Fan-out : un compte exécutant à distance sur N hôtes.
- Nom de service aléatoire / binaire en partage réseau.
- Nouveauté de la paire (compte admin, hôte cible).

## 8. Références
- https://attack.mitre.org/techniques/T1021/
- https://www.thehacker.recipes/ad/movement/
