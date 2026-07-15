# 06 — AS-REP Roasting

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1558.004 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Aucun (peut être fait sans compte) ou compte de domaine |
| **Impact** | Élevé |

---

## 1. Description

Normalement, la phase d'authentification Kerberos (AS-REQ) exige une **pré-authentification** : le client prouve qu'il connaît le mot de passe en chiffrant un horodatage. Si un compte a l'attribut **`DONT_REQ_PREAUTH`** activé (`Do not require Kerberos preauthentication`), le KDC renvoie directement une **AS-REP** contenant une portion chiffrée avec le hash du compte — **sans preuve d'identité préalable**.

L'attaquant récupère cette AS-REP et casse le hash **hors-ligne**. Contrairement au Kerberoasting, il n'a **pas besoin de compte valide** s'il connaît un nom d'utilisateur vulnérable.

## 2. Prérequis

- Connaître (ou énumérer) des noms d'utilisateurs.
- Au moins un compte avec `DONT_REQ_PREAUTH` activé (mauvaise config fréquente sur vieux comptes/applications).

## 3. Procédure de simulation (lab)

> ⚠️ Lab isolé uniquement.

**Outils :** Impacket (`GetNPUsers.py`), Rubeus, Hashcat.

```bash
# Sans compte : tester une liste d'utilisateurs
GetNPUsers.py DOMAINE.LOCAL/ -usersfile users.txt -no-pass -dc-ip 10.0.0.10

# Avec un compte : énumérer automatiquement les comptes vulnérables
GetNPUsers.py DOMAINE.LOCAL/user:password -request -dc-ip 10.0.0.10 -outputfile asrep.hash
```

```bash
# Cassage offline
hashcat -m 18200 asrep.hash rockyou.txt
```

**Résultat attendu :** hash `$krb5asrep$23$user@DOMAIN...` → mot de passe en clair.

## 4. Télémétrie générée (logs)

### Event IDs clés
| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4768** | TGT (AS-REQ) requested |

**Champs discriminants du 4768 :**
- `Pre-Authentication Type = 0` → **AS-REP sans pré-auth** (signal central).
- `Ticket Encryption Type = 0x17` (RC4) → cassage facilité.
- Plusieurs 4768 avec preauth type 0 depuis une même source.

## 5. Détection

### Logique de détection
Tout **4768 avec `PreAuthType = 0`** est intrinsèquement suspect. À corréler avec un volume anormal ou une source externe/inhabituelle.

### Règle Sigma
```yaml
title: AS-REP Roasting - Kerberos Pre-Auth Disabled Ticket Request
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4768
        PreAuthType: '0'
        TicketEncryptionType: '0x17'
    condition: selection
level: high
```

### Traduction SIEM
- **QRadar (AQL) :**
```sql
SELECT sourceip, "TargetUserName", COUNT(*) AS c
FROM events
WHERE "EventID" = 4768 AND "PreAuthType" = '0'
GROUP BY sourceip, "TargetUserName" LAST 15 MINUTES
```
- **Elastic (KQL) :** `event.code:4768 and winlog.event_data.PreAuthType:"0"`

## 6. Contre-mesures / Hardening

- **Auditer et retirer** `DONT_REQ_PREAUTH` sur tous les comptes (`Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`).
- Mots de passe forts sur les comptes historiquement concernés.
- Désactiver RC4.

## 7. Features pour l'agent IA

- Compteur de 4768 avec `PreAuthType=0` par source / fenêtre.
- Nouveauté de la relation (source, compte cible) vs baseline.
- Enumération : nombre d'utilisateurs distincts sondés depuis une source (beaucoup d'échecs `KDC_ERR_C_PRINCIPAL_UNKNOWN`).
- Type de chiffrement demandé.

## 8. Références

- https://attack.mitre.org/techniques/T1558/004/
- https://www.thehacker.recipes/ad/movement/kerberos/asreproast
