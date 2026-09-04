# 11 — Password Spraying

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1110.003 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Aucun (liste d'utilisateurs) |
| **Impact** | Élevé (compromission de comptes à mots de passe faibles) |

---

## 1. Description

Au lieu de tester beaucoup de mots de passe sur un compte (brute force → lockout), le **password spraying** teste **un** mot de passe probable (`Été2025!`, `Welcome1`, `<Société>2025`) sur **beaucoup** de comptes. En restant sous le seuil de verrouillage par compte, l'attaquant évite les lock-out tout en trouvant les comptes faibles.

## 2. Prérequis
- Liste d'utilisateurs valides (voir fiches 01/04).
- Un point d'authentification (SMB, LDAP, Kerberos, OWA, ADFS, VPN…).

## 3. Procédure de simulation (lab)

```bash
# Kerberos (pas de lockout NTLM, mais échecs 4771)
kerbrute passwordspray -d domaine.local --dc 10.0.0.10 users.txt 'Ete2025!'

# SMB
nxc smb 10.0.0.10 -u users.txt -p 'Welcome1' --continue-on-success
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4625** | Échec de logon (NTLM) — **1 échec sur beaucoup de comptes** |
| Security (DC) | **4771** | Kerberos pre-auth failed (`0x18` = mauvais mot de passe) |
| Security (DC) | 4768/4776 | Contexte d'authentification |

**Signature comportementale :** **beaucoup de `TargetUserName` distincts** échouant, chacun **peu de fois**, depuis **une même source** dans une fenêtre — l'inverse du brute force.

## 5. Détection

### Logique
Compter les **comptes distincts** en échec par source sur une fenêtre, avec **peu d'échecs par compte** (motif « large et plat »).

### Règle Sigma
```yaml
title: Password Spraying - Many Accounts Failing from Single Source
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4625
            - 4771
    condition: selection | count(TargetUserName) by IpAddress > 15
    timeframe: 10m
level: high
```

### Traduction SIEM
- **QRadar :** `HAVING COUNT(DISTINCT TargetUserName) > 15 AND AVG(fails_per_user) < 3`.
- **Elastic :** cardinalité `TargetUserName` par `source.ip` avec seuil.

## 6. Contre-mesures / Hardening
- **MFA** partout (VPN, OWA, ADFS).
- Politique de mots de passe robuste + interdiction des mots de passe communs (Azure AD Password Protection on-prem).
- Smart lockout / surveillance des motifs plats.

## 7. Features pour l'agent IA
- Cardinalité `TargetUserName` distincts par source / fenêtre (feature clé).
- Distribution des échecs par compte (plate = spray, pointue = brute force).
- Nouveauté de la source (IP, hôte).
- Heure (souvent hors heures ouvrées).

## 8. Références
- https://attack.mitre.org/techniques/T1110/003/
- https://github.com/ropnop/kerbrute
