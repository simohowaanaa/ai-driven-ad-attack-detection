# 12 — Brute Force / Account Lockout

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1110.001 / T1110.002 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Aucun |
| **Impact** | Moyen (compromission ou déni de service par lockout) |

---

## 1. Description

Le **brute force** teste de nombreux mots de passe sur **un** compte. Deux effets : compromission d'un compte à mot de passe faible, ou **déni de service** — le verrouillage massif de comptes (parfois utilisé volontairement comme DoS ciblé). Moins furtif que le spraying, mais fréquent sur les surfaces exposées.

## 2. Prérequis
- Un point d'authentification atteignable.
- Un ou plusieurs noms de comptes.

## 3. Procédure de simulation (lab)

```bash
nxc smb 10.0.0.10 -u admin -p passwords.txt
hydra -l admin -P rockyou.txt smb://10.0.0.10
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4625** | Échecs de logon répétés sur le **même compte** |
| Security (DC) | **4740** | **Account locked out** |
| Security (DC) | 4771 | Kerberos pre-auth failed |

**Signature :** **beaucoup d'échecs sur un même `TargetUserName`** (motif « étroit et profond »), souvent suivi d'un 4740.

## 5. Détection

### Règle Sigma
```yaml
title: Brute Force - Many Failed Logons for Single Account
status: stable
logsource:
    product: windows
    service: security
detection:
    fails:
        EventID: 4625
    lockout:
        EventID: 4740
    condition: fails | count() by TargetUserName > 10 or lockout
    timeframe: 5m
level: medium
```

### Traduction SIEM
- **Elastic :** `event.code:4625` agrégé par `TargetUserName` avec seuil ; alerte immédiate sur `event.code:4740`.
- **QRadar :** building block « N failed logons same user < T ».

## 6. Contre-mesures / Hardening
- Politique de verrouillage raisonnée (éviter le DoS par lockout).
- MFA, mots de passe robustes.
- Bannissement d'IP / rate limiting sur les surfaces exposées.

## 7. Features pour l'agent IA
- Nombre d'échecs par (compte, source) / fenêtre.
- Forme de la distribution (profonde sur un compte = brute force vs plate = spray, cf. fiche 11).
- Événements 4740 (lockout) comme feature d'impact.

## 8. Références
- https://attack.mitre.org/techniques/T1110/
