# 31 — Custom SSP (Malicious Security Support Provider)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence / Credential Access |
| **Technique MITRE** | T1547.005 (Security Support Provider) |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Administrateur local / DA sur le DC |
| **Impact** | Élevé (capture des mots de passe en clair à chaque authentification) |

---

## 1. Description

Un **SSP** est un DLL chargé par LSASS pour gérer l'authentification (Kerberos, NTLM, Negotiate…). En enregistrant un **SSP malveillant** (ex. `mimilib.dll`, ou via `memssp` de Mimikatz), l'attaquant fait **journaliser en clair** tous les identifiants qui transitent par LSASS. Sur un DC, cela capture les mots de passe de tout le domaine au fil des authentifications. Persistance : la valeur de registre `Security Packages` recharge le SSP au démarrage.

## 2. Prérequis
- Admin local / DA sur la machine (idéalement un DC).

## 3. Procédure de simulation (lab)

```powershell
# Mimikatz — SSP en mémoire (non persistant)
misc::memssp
# ou persistant : déposer mimilib.dll dans System32 et l'ajouter à :
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
# → mots de passe en clair dans C:\Windows\System32\kiwissp.log
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| **Registry** (Sysmon 13) | — | Modification de `HKLM\...\Lsa\Security Packages` |
| Sysmon | 7 | Chargement d'un DLL non signé/inconnu dans **lsass.exe** |
| Security | 4657 | Modification de valeur de registre (si audité) |

**Anomalie clé :** ajout d'un package à `Security Packages` ; DLL inconnue chargée par LSASS.

## 5. Détection

### Règle Sigma
```yaml
title: Custom SSP - Security Packages Registry Modification
status: stable
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|endswith: '\Control\Lsa\Security Packages'
    ssp_dll:
        EventID: 7        # image load
        Image|endswith: '\lsass.exe'
        Signed: 'false'
    condition: selection or ssp_dll
level: high
```

### Traduction SIEM
- **Elastic :** Sysmon 13 sur `\Lsa\Security Packages` ; Sysmon 7 DLL non signé dans lsass.
- **QRadar :** alerte immédiate sur modification de `Security Packages`, surtout sur un DC.

## 6. Contre-mesures / Hardening
- **LSA Protection (RunAsPPL)** — empêche le chargement de DLL non signés dans LSASS.
- Surveiller `Security Packages` et `Notification Packages`.
- Contrôle d'intégrité des DLL de System32.

## 7. Features pour l'agent IA
- Modification de la clé `Security Packages` (rarissime → forte alerte).
- Chargement de DLL non signé dans LSASS.
- Apparition d'un fichier de log inconnu (kiwissp.log) sur un DC.

## 8. Références
- https://attack.mitre.org/techniques/T1547/005/
- https://adsecurity.org/?p=1760
