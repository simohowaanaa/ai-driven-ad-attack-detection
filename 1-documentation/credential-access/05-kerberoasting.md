# 05 — Kerberoasting

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1558.003 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Tout compte de domaine authentifié |
| **Impact** | Élevé (compromission de comptes de service, souvent privilégiés) |

---

## 1. Description

Dans Kerberos, tout compte de domaine peut demander un **ticket de service (TGS)** pour n'importe quel service enregistré via un **SPN** (Service Principal Name). La partie du ticket destinée au service est **chiffrée avec le hash NTLM du compte de service** propriétaire du SPN.

L'attaquant demande des TGS pour des comptes de service, extrait la portion chiffrée, et la casse **hors-ligne** (Hashcat) pour récupérer le mot de passe en clair. Les comptes de service ont souvent des mots de passe faibles, rarement changés, et des privilèges élevés → cible idéale.

Le point clé : **aucune interaction avec le compte de service n'est requise**, et la phase de cassage est offline (invisible du SIEM). Seule la **demande de TGS** est observable.

## 2. Prérequis

- Un compte de domaine valide (même non privilégié).
- Existence de comptes utilisateurs avec un `servicePrincipalName` défini (comptes de service).
- Idéalement, chiffrement **RC4 (etype 0x17)** encore autorisé → cassage bien plus rapide qu'AES.

## 3. Procédure de simulation (lab)

> ⚠️ Lab isolé uniquement.

**Outils :** Rubeus, Impacket (`GetUserSPNs.py`), Hashcat.

```bash
# 1. Énumérer les comptes avec SPN (depuis Linux/attaquant)
GetUserSPNs.py DOMAINE.LOCAL/user:password -dc-ip 10.0.0.10

# 2. Demander les TGS et récupérer les hashes (format hashcat)
GetUserSPNs.py DOMAINE.LOCAL/user:password -dc-ip 10.0.0.10 -request -outputfile kerberoast.hash
```

```powershell
# Alternative Windows avec Rubeus (force RC4 pour un cassage plus rapide)
Rubeus.exe kerberoast /outfile:hashes.txt /tgtdeleg
```

```bash
# 3. Cassage offline
hashcat -m 13100 kerberoast.hash rockyou.txt
```

**Résultat attendu :** hashes `$krb5tgs$23$...` puis mot de passe en clair du compte de service.

## 4. Télémétrie générée (logs)

### Sources de logs
- Windows Security (Domain Controller)

### Event IDs clés
| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4769** | Kerberos service ticket (TGS) requested — **l'événement central** |
| Security (DC) | 4768 | TGT requested (contexte) |

**Champs discriminants du 4769 :**
- `Ticket Encryption Type = 0x17` (RC4) → très suspect si le domaine supporte AES.
- `Service Name` = compte utilisateur (pas une machine se terminant par `$`).
- `Ticket Options` = 0x40810000.
- Volume : **plusieurs 4769 en rafale** depuis un même compte source vers plusieurs SPN.

## 5. Détection

### Logique de détection
Alerter quand un même compte demande des **TGS pour de nombreux SPN de comptes utilisateurs** dans une courte fenêtre, **surtout en RC4** alors qu'AES est disponible. Le RC4 seul est un signal fort car les clients modernes négocient AES par défaut.

### Règle Sigma
```yaml
title: Potential Kerberoasting via RC4 Encryption
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
        TicketOptions: '0x40810000'
    filter:
        ServiceName|endswith: '$'      # exclut les comptes machine
        ServiceName: 'krbtgt'
    condition: selection and not filter
level: high
```

### Traduction SIEM
- **QRadar (AQL) :**
```sql
SELECT sourceip, "AccountName", COUNT(*) AS tgs_count
FROM events
WHERE "EventID" = 4769
  AND "TicketEncryptionType" = '0x17'
  AND "ServiceName" NOT LIKE '%$'
GROUP BY sourceip, "AccountName"
HAVING tgs_count > 10 LAST 10 MINUTES
```
- **Elastic (KQL) :**
```
event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"
and not winlog.event_data.ServiceName:*$
```

## 6. Contre-mesures / Hardening

- Utiliser des **gMSA/dMSA** (mots de passe gérés, 120+ caractères, rotation auto).
- Mots de passe de comptes de service ≥ 25 caractères aléatoires.
- **Désactiver RC4** dans les politiques Kerberos (forcer AES).
- Comptes de service **non membres de groupes privilégiés** (principe du moindre privilège).
- Marquer les comptes sensibles « Account is sensitive and cannot be delegated ».

## 7. Features pour l'agent IA

- Nombre de 4769 par compte source / fenêtre glissante (5–10 min).
- Ratio RC4 vs AES par compte.
- Nombre de SPN **distincts** ciblés par une même source.
- Écart au comportement historique du compte (baseline horaire/quotidienne).
- `ServiceName` pointant vers un compte utilisateur vs machine (feature binaire).
- Heure de la requête vs heures ouvrées habituelles du compte.

## 8. Références

- https://attack.mitre.org/techniques/T1558/003/
- https://www.thehacker.recipes/ad/movement/kerberos/kerberoast
- https://github.com/GhostPack/Rubeus
