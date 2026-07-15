# 04 — AS-REP Roasting Recon (User Enumeration)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Discovery |
| **Technique MITRE** | T1087.002 |
| **Phase kill chain** | Discovery |
| **CVE** | — |
| **Privilèges requis** | Aucun (via Kerberos) |
| **Impact** | Moyen (validation de noms de comptes sans lock-out) |

---

## 1. Description

Avant l'AS-REP Roasting (fiche 06), l'attaquant doit **valider des noms d'utilisateurs**. En envoyant des **AS-REQ Kerberos**, le KDC répond différemment selon que le compte existe ou non (`KDC_ERR_C_PRINCIPAL_UNKNOWN` vs `KDC_ERR_PREAUTH_REQUIRED`). Cette **énumération Kerberos** ne provoque **pas de verrouillage de compte** (contrairement au brute force NTLM), donc reste discrète.

## 2. Prérequis
- Accès Kerberos (88/tcp) au DC.
- Liste de noms candidats.

## 3. Procédure de simulation (lab)

```bash
# Kerbrute — énumération d'utilisateurs valides sans lockout
kerbrute userenum -d domaine.local --dc 10.0.0.10 users.txt
```

**Résultat :** liste des comptes existants (et ceux sans pré-auth, directement roastables).

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4768 | AS-REQ — nombreux échecs `0x6` (principal inconnu) |
| Security (DC) | 4771 | Kerberos pre-auth failed |

**Anomalie :** rafale de 4768/4771 avec de nombreux `TargetUserName` **distincts** et beaucoup de résultats « unknown principal ».

## 5. Détection

### Règle Sigma
```yaml
title: Kerberos User Enumeration (Kerbrute)
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4768
    condition: selection | count(TargetUserName) by IpAddress > 20
    timeframe: 2m
level: medium
```

### Traduction SIEM
- **QRadar :** compter les `TargetUserName` distincts par source IP sur une courte fenêtre.
- **Elastic :** agrégation cardinalité sur `TargetUserName` par `source.ip`.

## 6. Contre-mesures / Hardening
- Surveiller les rafales 4768/4771.
- Convention de nommage non devinable (limité).
- Alerter sur volume d'erreurs Kerberos `0x6`.

## 7. Features pour l'agent IA
- Cardinalité de `TargetUserName` distincts par source / fenêtre (feature clé).
- Ratio d'échecs « principal unknown » (énumération = beaucoup d'inconnus).
- Absence de verrouillage malgré volume (distingue de brute force NTLM).

## 8. Références
- https://github.com/ropnop/kerbrute
- https://attack.mitre.org/techniques/T1087/002/
