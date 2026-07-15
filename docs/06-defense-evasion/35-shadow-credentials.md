# 35 — Shadow Credentials (msDS-KeyCredentialLink)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access / Persistence |
| **Technique MITRE** | T1556 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Droit d'écriture sur `msDS-KeyCredentialLink` de la cible |
| **Impact** | Élevé (usurpation sans changer le mot de passe) |

---

## 1. Description

L'attribut **`msDS-KeyCredentialLink`** stocke les clés publiques utilisées par **Windows Hello for Business / PKINIT** (Key Trust). Un attaquant disposant du droit d'écriture sur cet attribut d'un compte cible y ajoute **sa propre paire de clés** : il peut alors **s'authentifier en tant que la cible via PKINIT** et récupérer son TGT / hash NT — **sans connaître ni modifier le mot de passe**. Furtif et réversible. Souvent une étape de RBCD/ACL abuse repérée via BloodHound.

## 2. Prérequis
- Droit d'écriture (`GenericWrite`/`GenericAll`) sur `msDS-KeyCredentialLink` du compte cible.
- ADCS/PKINIT disponible dans le domaine.

## 3. Procédure de simulation (lab)

```bash
# Whisker (Windows) / pyWhisker (Linux) / Certipy shadow
certipy shadow auto -u attacker@domaine.local -p pass -account 'targetuser'
# → ajoute une KeyCredential, obtient un TGT + le hash NT de la cible
```
```powershell
Whisker.exe add /target:targetuser
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **5136** | Modification de l'attribut **`msDS-KeyCredentialLink`** |
| Security (DC) | 4768 | TGT via **PKINIT** (Certificate Info) juste après |
| Security (DC) | 4662 | Écriture sur l'objet cible |

**Anomalie clé :** modification de `msDS-KeyCredentialLink` (rare hors WHfB) suivie d'un TGT PKINIT.

## 5. Détection

### Règle Sigma
```yaml
title: Shadow Credentials - msDS-KeyCredentialLink Modification
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-KeyCredentialLink'
    condition: selection
level: high
falsepositives:
    - Enrôlement Windows Hello for Business légitime
```

### Traduction SIEM
- **Elastic :** `event.code:5136 and winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink"`
- **QRadar :** corréler la modif de l'attribut + TGT PKINIT du même compte en < quelques minutes ; exclure les serveurs d'enrôlement WHfB.

## 6. Contre-mesures / Hardening
- Auditer/limiter les droits d'écriture sur les objets (revue BloodHound des ACL).
- Surveiller `msDS-KeyCredentialLink` (peu de modifs légitimes hors WHfB).
- Retirer les KeyCredentials orphelines.

## 7. Features pour l'agent IA
- Modification de `msDS-KeyCredentialLink` par un principal ≠ serveur d'enrôlement WHfB.
- Séquence : write KeyCredentialLink → TGT PKINIT du compte cible.
- Cible = compte privilégié / DC (feature de sévérité).

## 8. Références
- https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
- https://github.com/ShutdownRepo/pywhisker
