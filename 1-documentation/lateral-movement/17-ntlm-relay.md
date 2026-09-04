# 17 — NTLM Relay (SMB Relay)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Lateral Movement / Credential Access |
| **Technique MITRE** | T1557.001 |
| **Phase kill chain** | Lateral Movement |
| **CVE** | — |
| **Privilèges requis** | Position réseau + coercion d'authentification |
| **Impact** | Élevé à Critique (selon la cible relayée) |

---

## 1. Description

Plutôt que de casser un hash Net-NTLM capturé (fiche 07), l'attaquant le **relaie en temps réel** vers un autre service qui accepte NTLM et n'impose pas de **signing**. Il **s'authentifie ainsi en tant que la victime** sans jamais connaître son secret. Combiné à une **coercion** (PetitPotam, PrinterBug) forçant un DC/serveur à s'authentifier, le relais vers **LDAP** ou **ADCS (ESC8)** peut mener à une compromission du domaine.

## 2. Prérequis
- Position réseau (MITM/poisoning) ou coercion.
- Cible sans **SMB signing / LDAP signing / channel binding**.

## 3. Procédure de simulation (lab)

```bash
# 1. Relais vers SMB (ou LDAP/HTTP-ADCS)
ntlmrelayx.py -t smb://10.0.0.20 -smb2support
ntlmrelayx.py -t ldaps://dc01 --delegate-access       # RBCD
ntlmrelayx.py -t http://adcs/certsrv/certfnsh.asp --adcs   # ESC8

# 2. Déclencher l'authentification (coercion)
PetitPotam.py 10.0.0.50 10.0.0.10       # force le DC à s'authentifier
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (cible) | 4624 | Logon NTLM Type 3 depuis l'IP **de l'attaquant** au nom de la victime |
| Security (DC) | 4776 | Validation NTLM |
| NDR / Zeek | — | Flux SMB/LDAP/HTTP relayé, coercion (MS-EFSR/MS-RPRN) |

**Anomalie :** un compte (souvent un **compte machine** de serveur/DC) s'authentifiant **depuis une IP inattendue** ; source du logon ≠ machine réelle du compte.

## 5. Détection

### Logique
Détecter un compte machine (`SERVER$`, `DC$`) s'authentifiant depuis une IP qui n'est pas la sienne ; détecter la coercion (appels MS-EFSR/MS-RPRN vers un DC).

### Règle Sigma
```yaml
title: NTLM Relay - Machine Account Auth from Unexpected Source
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
        TargetUserName|endswith: '$'
    condition: selection
level: high
```
> À corréler avec un mapping compte machine → IP attendue (sinon faux positifs).

### Traduction SIEM
- **Elastic :** `event.code:4624 and winlog.event_data.LogonType:"3" and winlog.event_data.AuthenticationPackageName:"NTLM" and winlog.event_data.TargetUserName:*$`
- **NDR :** détection PetitPotam/PrinterBug (EfsRpcOpenFileRaw, RpcRemoteFindFirstPrinterChangeNotification).

## 6. Contre-mesures / Hardening
- **SMB signing** obligatoire ; **LDAP signing + channel binding**.
- **EPA** (Extended Protection for Authentication) sur ADCS/OWA.
- Désactiver NTLM autant que possible.
- Patcher/mitiger PetitPotam & PrinterBug.

## 7. Features pour l'agent IA
- Écart entre IP source d'un logon et IP attendue du compte (surtout comptes machine).
- Détection de coercion (RPC MS-EFSR/MS-RPRN vers DC).
- Séquence : coercion → logon NTLM relayé → action privilégiée (RBCD/cert).

## 8. Références
- https://attack.mitre.org/techniques/T1557/001/
- https://www.thehacker.recipes/ad/movement/ntlm/relay
