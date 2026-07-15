# 19 — Silver Ticket

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence / Privilege Escalation |
| **Technique MITRE** | T1558.002 |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Hash NTLM / clé AES d'un **compte de service** (ou compte machine) |
| **Impact** | Élevé (accès à un service précis, très furtif) |

---

## 1. Description

Là où le Golden Ticket forge un **TGT** (clé krbtgt), le **Silver Ticket** forge directement un **TGS** pour **un service précis**, en utilisant la clé du **compte de service** propriétaire du SPN (ou du compte machine pour CIFS/HOST). Comme le TGS est présenté **directement au service sans passer par le DC**, l'attaque est **très furtive** : aucun 4768/4769 côté DC. Portée limitée au service ciblé mais quasi invisible.

## 2. Prérequis
- Hash/clé AES du compte de service ou du compte machine cible.
- SID du domaine, SPN du service visé.

## 3. Procédure de simulation (lab)

```powershell
kerberos::golden /user:Administrator /domain:domaine.local /sid:S-1-5-21-... /target:srv01.domaine.local /service:cifs /rc4:<hash_compte_service> /ptt
```
```bash
ticketer.py -nthash <service_hash> -domain-sid S-1-5-21-... -domain domaine.local -spn cifs/srv01.domaine.local Administrator
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (**cible**, pas le DC) | 4624 | Logon utilisant le TGS forgé |
| **Absence** de 4768/4769 côté DC | — | Signature d'anomalie (ticket jamais émis par le KDC) |

**Anomalie clé :** accès à un service **sans TGS correspondant (4769)** émis par le DC → le ticket a été forgé.

## 5. Détection

### Logique
Corréler un logon Kerberos sur un service avec **l'absence de 4769** correspondant côté DC. Nécessite une corrélation stateful (endpoint ↔ DC) → **cas d'usage IA**.

### Règle Sigma
```yaml
title: Silver Ticket - Service Logon Without Corresponding TGS
status: experimental
logsource:
    product: windows
    service: security
detection:
    logon:
        EventID: 4624
        AuthenticationPackageName: 'Kerberos'
    # corrélation "pas de 4769 correspondant" → moteur SIEM/IA
    condition: logon
level: medium
falsepositives:
    - Nécessite corrélation DC/endpoint pour être fiable
```

### Traduction SIEM
- **Elastic (EQL) :** logon Kerberos sur endpoint sans 4769 associé côté DC.
- **QRadar :** règle d'absence d'événement corrélé.

## 6. Contre-mesures / Hardening
- Rotation régulière des mots de passe de comptes de service et **comptes machine** (défaut 30j — ne pas désactiver).
- Désactiver RC4.
- Journaliser les logons côté **serveurs membres** (pas seulement les DC).

## 7. Features pour l'agent IA
- Logon Kerberos sur service **sans 4769 amont** (feature de corrélation).
- Incohérences PAC (privilèges revendiqués).
- Comptes machine dont le mot de passe n'a pas tourné depuis longtemps (surface).

## 8. Références
- https://attack.mitre.org/techniques/T1558/002/
- https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver
