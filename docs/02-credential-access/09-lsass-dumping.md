# 09 — LSASS Dumping (Mimikatz)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1003.001 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Administrateur local / SYSTEM sur la machine |
| **Impact** | Élevé (hashes, tickets, mots de passe en clair en mémoire) |

---

## 1. Description

Le processus **LSASS** (`lsass.exe`) conserve en mémoire les secrets des utilisateurs connectés : **hashes NTLM, tickets Kerberos (TGT), et parfois mots de passe en clair** (WDigest). Dumper sa mémoire donne accès à ces secrets, réutilisables en Pass-the-Hash / Pass-the-Ticket. C'est l'étape pivot du mouvement latéral après compromission d'une machine.

## 2. Prérequis
- Droits admin local / SYSTEM sur la machine.
- Contourner LSA Protection / EDR le cas échéant.

## 3. Procédure de simulation (lab)

```powershell
# Mimikatz
privilege::debug
sekurlsa::logonpasswords

# Dump du process (comobjet natif) puis parsing offline
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <PID_lsass> C:\temp\lsass.dmp full

# Task Manager / procdump également possibles
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| **Sysmon** | **10** | **ProcessAccess sur lsass.exe** (GrantedAccess 0x1010/0x1410/0x143a) |
| Sysmon | 1 | Création de process suspect (procdump, rundll32 comsvcs) |
| Security | 4656 / 4663 | Handle demandé sur l'objet lsass |
| EDR (AXAT) | — | Détection comportementale d'accès mémoire LSASS |

**Anomalie clé :** `Sysmon EID 10` avec `TargetImage = lsass.exe` et masques d'accès de lecture mémoire, depuis un process non-système.

## 5. Détection

### Règle Sigma
```yaml
title: LSASS Memory Access (Credential Dumping)
status: stable
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess:
            - '0x1010'
            - '0x1410'
            - '0x143a'
            - '0x1fffff'
    filter_legit:
        SourceImage|endswith:
            - '\wininit.exe'
            - '\MsMpEng.exe'      # Defender
    condition: selection and not filter_legit
level: high
```

### Traduction SIEM
- **Elastic (EDR/Sysmon) :** `winlog.channel:"Microsoft-Windows-Sysmon/Operational" and event.code:10 and winlog.event_data.TargetImage:*lsass.exe`
- **AXAT (EDR) :** signal natif « credential access / LSASS read » — corréler dans XSOAR.

## 6. Contre-mesures / Hardening
- **LSA Protection (RunAsPPL)**, **Credential Guard**.
- Désactiver WDigest (pas de mot de passe en clair en mémoire).
- Restreindre les droits admin local (LAPS, Tiering).
- EDR en mode blocage.

## 7. Features pour l'agent IA
- Process source accédant à LSASS (feature : image non whitelistée).
- Masque d'accès demandé (lecture mémoire = suspect).
- Corrélation dump LSASS → mouvement latéral (PtH) dans les minutes suivantes.
- Rareté du binaire source (procdump/comsvcs sur un poste bureautique).

## 8. Références
- https://attack.mitre.org/techniques/T1003/001/
- https://github.com/gentilkiwi/mimikatz
