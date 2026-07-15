# 02 — SPN Scanning

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Discovery |
| **Technique MITRE** | T1046, T1087 |
| **Phase kill chain** | Discovery |
| **CVE** | — |
| **Privilèges requis** | Compte de domaine authentifié |
| **Impact** | Moyen (préalable au Kerberoasting) |

---

## 1. Description

Le **SPN scanning** énumère via LDAP tous les comptes possédant un `servicePrincipalName`. Contrairement à un scan de ports, il est **discret** (une simple requête LDAP) et révèle les services (SQL, HTTP, CIFS…) et leurs comptes de service. C'est le repérage préalable au **Kerberoasting** (voir fiche 05).

## 2. Prérequis
- Compte de domaine valide, accès LDAP au DC.

## 3. Procédure de simulation (lab)

```powershell
# setspn natif (aucun outil tiers)
setspn -T domaine.local -Q */*
```
```bash
# Impacket
GetUserSPNs.py domaine.local/user:password -dc-ip 10.0.0.10
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4662 | Lecture d'objets AD (attribut SPN) |
| Directory Service | 1644 | Requête LDAP filtrée sur `servicePrincipalName` |

**Anomalies :** requête LDAP filtrant explicitement sur `servicePrincipalName=*`.

## 5. Détection

### Règle Sigma
```yaml
title: SPN Enumeration via LDAP Query
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains: 'servicePrincipalName'
    condition: selection
level: low
```

### Traduction SIEM
- **Elastic :** `event.code:4662 and winlog.event_data.Properties:*servicePrincipalName*`
- **QRadar :** corréler avec une rafale de 4769 (Kerberoasting) qui suit.

## 6. Contre-mesures / Hardening
- Détection surtout (l'action est légitime). Corréler avec le Kerberoasting aval.
- Comptes de service durcis (voir fiche 05).

## 7. Features pour l'agent IA
- Requête LDAP filtrée sur SPN + faible fréquence historique de l'hôte.
- **Séquence** : SPN scan → rafale de 4769 (fort indicateur de chaîne d'attaque).

## 8. Références
- https://attack.mitre.org/techniques/T1046/
- https://www.thehacker.recipes/ad/movement/kerberos/kerberoast
