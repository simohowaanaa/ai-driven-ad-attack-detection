# 20 — Diamond Ticket

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence / Privilege Escalation |
| **Technique MITRE** | T1558.001 |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Clé AES du compte **krbtgt** |
| **Impact** | Critique (Golden Ticket furtif) |

---

## 1. Description

Le **Diamond Ticket** est une évolution furtive du Golden Ticket. Au lieu de **forger** un TGT de toutes pièces (Golden — détectable par un TGS sans TGT), l'attaquant **demande un vrai TGT au DC** (4768 légitime), puis le **déchiffre avec la clé krbtgt**, **modifie le PAC** (ajoute des groupes privilégiés) et le **re-chiffre**. Le ticket conserve donc des métadonnées cohérentes avec une émission légitime → beaucoup plus difficile à détecter.

## 2. Prérequis
- **Clé AES du krbtgt** (via DCSync/NTDS).
- Un compte de domaine valide pour obtenir le TGT initial.

## 3. Procédure de simulation (lab)

```bash
# Rubeus diamond
Rubeus.exe diamond /krbkey:<aes256_krbtgt> /user:lowpriv /password:pass /enctype:aes /ticketuser:Administrator /domain:domaine.local /dc:dc01.domaine.local /ptt
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4768 | TGT **légitimement** émis (contrairement au Golden) |
| Security (DC) | 4769 | TGS cohérent |

**Anomalie :** pas d'absence de 4768 (donc la détection Golden échoue). Détection via **incohérence du PAC** : groupes/privilèges revendiqués ≠ appartenance réelle du compte en base AD.

## 5. Détection

### Logique
Comparer les **groupes déclarés dans le PAC** (visibles côté service/DC) avec l'appartenance **réelle** du compte dans AD. Un écart = PAC falsifié. Nécessite un enrichissement (état AD) → **fort cas d'usage IA**.

### Règle Sigma (conceptuelle)
```yaml
title: Diamond/Forged Ticket - PAC Group Mismatch
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4672        # privilèges spéciaux inattendus
    condition: selection
level: medium
falsepositives:
    - Requiert enrichissement PAC vs appartenance réelle
```

### Traduction SIEM
- **Enrichissement XSOAR :** playbook qui compare, pour un logon privilégié, les SID du PAC aux groupes réels (requête LDAP) → alerte si écart.

## 6. Contre-mesures / Hardening
- Rotation double du **krbtgt** (invalide les tickets forgés).
- Réduire la durée de vie des tickets.
- Détection basée sur cohérence PAC / privilèges.

## 7. Features pour l'agent IA
- Écart PAC (groupes revendiqués) vs appartenance AD réelle (feature d'enrichissement clé).
- Compte non-privilégié obtenant soudainement des 4672.
- Élévation de privilège sans changement d'appartenance de groupe traçable.

## 8. Références
- https://attack.mitre.org/techniques/T1558/001/
- https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond
