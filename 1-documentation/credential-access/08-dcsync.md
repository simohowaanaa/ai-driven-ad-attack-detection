# 08 — DCSync

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1003.006 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Droits de réplication (`DS-Replication-Get-Changes` + `...-All`) — typiquement Domain Admin / Enterprise Admin |
| **Impact** | Critique (extraction de tous les hashes du domaine, dont krbtgt) |

---

## 1. Description

DCSync abuse le protocole de réplication AD (**MS-DRSR / `IDL_DRSGetNCChanges`**). Un attaquant disposant des droits de réplication se fait passer pour un contrôleur de domaine et **demande au vrai DC de lui répliquer les secrets** d'un compte (hash NTLM, clés Kerberos, y compris **krbtgt**).

C'est extrêmement puissant : pas besoin de code sur le DC, pas de dump LSASS. La récupération du hash **krbtgt** ouvre la porte au **Golden Ticket**.

## 2. Prérequis

- Compte disposant des droits étendus **`Replicating Directory Changes`** et **`Replicating Directory Changes All`** sur l'objet domaine. Par défaut : Domain Admins, Enterprise Admins, Administrators, DCs.
- Souvent obtenu après un `AdminSDHolder`/ACL abuse ou compromission d'un compte privilégié.

## 3. Procédure de simulation (lab)

> ⚠️ Lab isolé uniquement.

**Outils :** Mimikatz, Impacket (`secretsdump.py`).

```powershell
# Mimikatz — extraire le hash d'un compte précis (ex : krbtgt)
lsadump::dcsync /domain:domaine.local /user:krbtgt
```

```bash
# Impacket — dump complet du domaine via DCSync
secretsdump.py DOMAINE.LOCAL/admin:password@10.0.0.10 -just-dc
```

**Résultat attendu :** hashes NTLM + clés Kerberos de tous les comptes (ou du compte ciblé).

## 4. Télémétrie générée (logs)

### Event IDs clés
| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4662** | Operation performed on an AD object (accès à un objet avec le GUID de réplication) |

**Champs discriminants du 4662 :**
- `Properties` contient les GUID de contrôle de réplication :
  - `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes)
  - `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes-All)
- **Le compte source n'est PAS un contrôleur de domaine** → anomalie majeure.

## 5. Détection

### Logique de détection
Un 4662 avec les GUID de réplication provenant d'un compte **qui n'est pas un DC** = DCSync quasi certain. La whitelist des vrais DC est la clé pour éliminer les faux positifs (la réplication légitime DC↔DC est normale).

### Règle Sigma
```yaml
title: DCSync - Directory Replication from Non-DC Account
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter_dc:
        SubjectUserName|endswith: '$'   # comptes machine / DC légitimes → à affiner avec liste de DC
    condition: selection and not filter_dc
level: critical
```
> ⚠️ Affiner `filter_dc` avec la **liste explicite des comptes de DC** ; se contenter du `$` laisse passer un compte machine compromis.

### Traduction SIEM
- **QRadar (AQL) :**
```sql
SELECT "SubjectUserName", sourceip
FROM events
WHERE "EventID" = 4662
  AND "Properties" LIKE '%1131f6aa-9c07-11d1%'
  AND "SubjectUserName" NOT IN (SELECT dc_account FROM reference_table('Domain_Controllers'))
```
- **Elastic (KQL) :**
```
event.code:4662 and winlog.event_data.Properties:*1131f6aa-9c07-11d1*
and not winlog.event_data.SubjectUserName:("DC01$" or "DC02$")
```

## 6. Contre-mesures / Hardening

- **Auditer les ACL** du domaine : retirer les droits de réplication non nécessaires.
- Surveiller/protéger les groupes privilégiés (Tiering, PAW).
- Détection = principale défense (l'action est légitime par design).
- Rotation régulière (double) du mot de passe **krbtgt**.

## 7. Features pour l'agent IA

- Événement 4662 avec GUID de réplication + source hors liste DC (feature booléenne très discriminante).
- Nouveauté du compte effectuant une réplication (jamais vu répliquer auparavant).
- Corrélation temporelle avec une élévation de privilèges récente du compte.
- Volume/horaire inhabituel de réplication.

## 8. Références

- https://attack.mitre.org/techniques/T1003/006/
- https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync
