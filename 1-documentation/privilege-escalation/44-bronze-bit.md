# 44 — Bronze Bit (CVE-2020-17049)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation / Lateral Movement |
| **Technique MITRE** | T1558 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | **CVE-2020-17049** |
| **Privilèges requis** | Clé (hash/AES) d'un compte avec délégation contrainte |
| **Impact** | Élevé (contourne les protections de délégation, usurpe des comptes protégés) |

---

## 1. Description

La **délégation contrainte** (S4U) permet à un service d'obtenir un ticket « au nom de » un utilisateur, pour des services précis. Deux garde-fous existaient : le drapeau **`forwardable`** du ticket, et l'impossibilité d'usurper les comptes marqués « sensibles / non délégables ». **Bronze Bit** exploite une faiblesse cryptographique : comme le ticket S4U2self est chiffré avec la clé du compte de service (que l'attaquant possède), il peut **modifier le drapeau `forwardable`** et **contourner ces protections** — usurpant même des comptes normalement non délégables (comme des admins). C'est une amplification de l'abus de délégation contrainte (fiche 21).

## 2. Prérequis
- Contrôle d'un compte disposant de **délégation contrainte** (sa clé NTLM/AES).
- DC non patché (novembre 2020).

## 3. Procédure de simulation (lab)

```bash
# getST avec l'option Bronze Bit (-force-forwardable)
getST.py -spn cifs/dc01.datacorp.local -impersonate Administrator \
   -hashes :<hash_svc> datacorp.local/svc_deleg -force-forwardable
```

**Résultat :** ticket d'`Administrator` même si ce compte était marqué non délégable.

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4769 | Requêtes S4U2self / S4U2proxy |
| Security (cible) | 4624 | Logon usurpé |

**Anomalie :** requêtes S4U impliquant l'usurpation d'un compte **protégé** / non délégable.

## 5. Détection

### Règle Sigma
```yaml
title: Bronze Bit - S4U Delegation Abuse (Protected Account Impersonation)
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TransmittedServices|exists: true    # présence de délégation S4U
    condition: selection
level: medium
falsepositives:
    - Délégation contrainte légitime
```

### Traduction SIEM
- **QRadar / Elastic :** 4769 avec `Transmitted Services` renseigné où le compte usurpé est un compte privilégié / Protected Users.

## 6. Contre-mesures / Hardening
- **Patcher** CVE-2020-17049 (novembre 2020).
- Marquer les comptes sensibles « Account is sensitive and cannot be delegated » + **Protected Users** (efficace une fois patché).
- Auditer/minimiser la délégation contrainte.

## 7. Features pour l'agent IA
- Requêtes S4U usurpant un compte privilégié / marqué non délégable.
- Compte de service effectuant soudainement des délégations vers des comptes sensibles.

## 8. Références
- https://www.netspi.com/blog/technical-blog/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-overview/
- https://github.com/fortra/impacket
