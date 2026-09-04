# 03 — Null / Anonymous Sessions

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Discovery |
| **Technique MITRE** | T1087, T1135 |
| **Phase kill chain** | Discovery |
| **CVE** | — |
| **Privilèges requis** | Aucun (non authentifié) |
| **Impact** | Moyen (fuite d'infos sans compte) |

---

## 1. Description

Sur des DC/serveurs mal durcis, une **session SMB/LDAP anonyme** (« null session ») permet d'énumérer utilisateurs, groupes, politiques de mots de passe et partages **sans authentification**. Hérité des anciennes versions de Windows, encore présent par mauvaise configuration (`RestrictAnonymous`, `RestrictNullSessAccess`).

## 2. Prérequis
- Accès réseau SMB (445) / LDAP (389) sans compte.
- Cible autorisant l'anonyme.

## 3. Procédure de simulation (lab)

```bash
# Enumération anonyme
enum4linux-ng -A -u "" -p "" 10.0.0.10
rpcclient -U "" -N 10.0.0.10 -c "enumdomusers;querydominfo"
ldapsearch -x -H ldap://10.0.0.10 -b "dc=domaine,dc=local"   # LDAP anonyme
nxc smb 10.0.0.10 -u '' -p '' --shares
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security | 4624 | Logon **Type 3** avec `TargetUserName = ANONYMOUS LOGON` |
| Security | 5140 | Accès à un partage réseau |
| Security | 4672 | (parfois) |

**Anomalie :** `ANONYMOUS LOGON` accédant à des ressources d'annuaire.

## 5. Détection

### Règle Sigma
```yaml
title: Anonymous Logon Enumeration
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        TargetUserName: 'ANONYMOUS LOGON'
    condition: selection
level: medium
```

### Traduction SIEM
- **Elastic :** `event.code:4624 and winlog.event_data.TargetUserName:"ANONYMOUS LOGON" and winlog.event_data.LogonType:"3"`

## 6. Contre-mesures / Hardening
- `RestrictAnonymous = 1`, `RestrictAnonymousSAM = 1`, `RestrictNullSessAccess = 1`.
- Désactiver LDAP anonyme (`dsHeuristics`).
- Bloquer SMBv1.

## 7. Features pour l'agent IA
- Fréquence d'ANONYMOUS LOGON Type 3 par source.
- Diversité des ressources énumérées sous session anonyme.

## 8. Références
- https://attack.mitre.org/techniques/T1087/
- https://www.thehacker.recipes/ad/recon/
