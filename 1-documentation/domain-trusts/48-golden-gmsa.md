# 48 — Golden gMSA (KDS Root Key Abuse)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access / Persistence |
| **Technique MITRE** | T1552 / T1649 |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Accès à la **KDS Root Key** (Domain Admin / DC) |
| **Impact** | Critique (calcul offline des mots de passe de TOUS les gMSA, pour toujours) |

---

## 1. Description

Les mots de passe des **gMSA** (fiche 39) sont dérivés d'un secret central : la **KDS Root Key** (Key Distribution Service), stockée sur les DC. Normalement, seul le DC calcule les mots de passe gMSA à la demande. **Golden gMSA** : un attaquant qui vole la **KDS Root Key** peut **calculer hors-ligne le mot de passe de N'IMPORTE QUEL gMSA du domaine**, sans jamais réinterroger AD — et ce, **de façon persistante** (la KDS Root Key ne change quasiment jamais). C'est l'équivalent "gMSA" du Golden Ticket.

## 2. Prérequis
- Accès en lecture à la **KDS Root Key** (`CN=Master Root Keys,...`), typiquement Domain Admin / accès DC.

## 3. Procédure de simulation (lab)

```bash
# 1. Extraire la KDS Root Key
GoldenGMSA.exe kdsinfo
# 2. Calculer offline le mot de passe d'un gMSA cible
GoldenGMSA.exe compute --sid <SID_gMSA> --kdskey <kds_root_key>
→ svc_gmsa$ : mot de passe / hash NT  (calculé sans toucher au DC)
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4662 | Accès à l'objet **KDS Root Key** (`Master Root Keys`) |

**Anomalie clé :** lecture de la KDS Root Key — événement **rarissime** en fonctionnement normal.

## 5. Détection

### Règle Sigma
```yaml
title: Golden gMSA - KDS Root Key Access
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        ObjectName|contains: 'Master Root Keys'
    condition: selection
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:4662 and winlog.event_data.ObjectName:*Master Root Keys*`
- **QRadar :** alerte critique sur tout accès à la KDS Root Key hors DC/processus légitime.

## 6. Contre-mesures / Hardening
- Protéger l'accès aux DC et à la partition de configuration (la lecture de la KDS key = déjà très privilégié).
- Détection = principale défense (calcul offline sinon invisible).
- Traiter les gMSA privilégiés comme des actifs Tier 0.

## 7. Features pour l'agent IA
- Accès à l'objet KDS Root Key (feature booléenne rare et forte).
- Corrélation : accès KDS → authentification de gMSA depuis des hôtes inhabituels.

## 8. Références
- https://www.semperis.com/blog/golden-gmsa-attack/
- https://github.com/Semperis/GoldenGMSA
