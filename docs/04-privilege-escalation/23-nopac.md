# 23 — noPac / sAMAccountName Spoofing (CVE-2021-42278 / 42287)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation |
| **Technique MITRE** | T1068 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | **CVE-2021-42278 + CVE-2021-42287** |
| **Privilèges requis** | Un compte de domaine standard (+ MachineAccountQuota > 0) |
| **Impact** | Critique (utilisateur standard → Domain Admin) |

---

## 1. Description

Chaîne de deux failles Kerberos :
- **CVE-2021-42278** : absence de validation du format des `sAMAccountName` de comptes machine (normalement terminés par `$`).
- **CVE-2021-42287** : quand un TGS demande un service dont le compte n'est pas trouvé, le KDC **cherche un compte au nom proche** (avec `$`).

L'attaquant crée un compte machine, le **renomme** en `DC01` (sans `$`, identique à un DC), demande un TGT, puis **renomme** le compte. Lorsqu'il demande un TGS S4U2Self, le KDC ne trouve plus `DC01`, se rabat sur **`DC01$`** (le vrai DC) et émet un ticket **au privilège du DC** → l'attaquant devient DA. C'est **noPac**.

## 2. Prérequis
- Compte de domaine standard.
- `ms-DS-MachineAccountQuota > 0` (défaut 10).
- DC non patché (novembre 2021).

## 3. Procédure de simulation (lab)

```bash
# noPac (Impacket / outil noPac.py)
noPac.py domaine.local/user:pass -dc-ip 10.0.0.10 -dc-host DC01 --impersonate Administrator -use-ldap -shell

# Manuellement : addcomputer → renommer en 'DC01' → getST S4U2Self → renommer
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4741** | Création d'un compte machine |
| Security (DC) | **4781** | **Renommage du compte** (sAMAccountName modifié) |
| Security (DC) | 4662 / 5136 | Modification d'attributs (sAMAccountName) |
| Security (DC) | 4769 | TGS S4U2Self avec sAMAccountName sans `$` |
| Security (DC) | 4768 | TGT pour le compte renommé |

**Anomalie clé :** un compte machine dont le `sAMAccountName` correspond à un **nom de DC sans `$`** ; 4741 + 4781 rapprochés par un utilisateur standard.

## 5. Détection

### Règle Sigma
```yaml
title: noPac - sAMAccountName Spoofing (Computer Renamed to DC Name)
status: experimental
logsource:
    product: windows
    service: security
detection:
    rename:
        EventID: 4781
    create:
        EventID: 4741
    tgt_nodollar:
        EventID: 4768
        TargetUserName|re: '^(?!.*\$).*(DC|SRV)\d+$'   # nom type DC sans $
    condition: rename or (create and tgt_nodollar)
level: critical
```

### Traduction SIEM
- **Elastic :** `event.code:4781` corrélé à `event.code:4741` par le même sujet, en < 5 min.
- **QRadar :** alerte sur compte machine renommé avec un nom sans `$` proche d'un DC.

## 6. Contre-mesures / Hardening
- **Patcher** (novembre 2021).
- **MachineAccountQuota = 0**.
- Surveiller 4741/4781 par des comptes non-admin.

## 7. Features pour l'agent IA
- Séquence 4741 → 4781 → 4768/4769 par un utilisateur standard (feature de séquence).
- `sAMAccountName` ressemblant à un DC sans `$`.
- Élévation vers 4672 juste après.

## 8. Références
- https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities
- https://github.com/Ridter/noPac
