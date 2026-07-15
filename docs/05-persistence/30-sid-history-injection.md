# 30 — SID History Injection

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence / Privilege Escalation |
| **Technique MITRE** | T1134.005 (SID-History Injection) |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Domain Admin / SYSTEM sur DC (ou DCShadow) |
| **Impact** | Critique (privilèges cachés dans un compte anodin) |

---

## 1. Description

L'attribut **`sIDHistory`** existe pour les migrations de domaines : un compte migré conserve ses anciens SID pour garder ses accès. Un attaquant y **injecte le SID d'un groupe privilégié** (ex. Domain Admins, `S-1-5-21-...-512`) sur un compte anodin. Ce compte obtient alors, de façon **transparente et discrète**, les privilèges de ce groupe — sans en être membre visible. Persistance furtive : le compte n'apparaît pas dans « Domain Admins ».

## 2. Prérequis
- Droits DA/SYSTEM sur un DC (l'écriture de sIDHistory intra-domaine nécessite des privilèges élevés, ou passe par DCShadow — fiche 27).

## 3. Procédure de simulation (lab)

```powershell
# Mimikatz
sid::add /sid:S-1-5-21-...-512 /sam:targetuser
# ou via DCShadow pour la furtivité
lsadump::dcshadow /object:targetuser /attribute:sidHistory /value:S-1-5-21-...-512
```
```bash
# Impacket (post-DCSync)
# secretsdump + réinjection selon scénario
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4765** | **SID History added to an account** |
| Security (DC) | 4766 | Échec d'ajout de SID History |
| Security (DC) | 4738 | Compte utilisateur modifié |
| Security (DC) | 5136 | Modification de l'attribut `sIDHistory` |

**Anomalie clé :** 4765 (rare hors migration) ; un compte anodin dont le token contient le SID d'un groupe privilégié sans en être membre.

## 5. Détection

### Règle Sigma
```yaml
title: SID History Injection
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4765
            - 4766
    sid_attr:
        EventID: 5136
        AttributeLDAPDisplayName: 'sIDHistory'
    condition: selection or sid_attr
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:(4765 or 4766)` ; ou `event.code:5136 and winlog.event_data.AttributeLDAPDisplayName:"sIDHistory"`.
- **QRadar :** revue périodique des comptes avec sIDHistory contenant des RID privilégiés (512, 519, 518, 516).

## 6. Contre-mesures / Hardening
- **SID Filtering** sur les relations de confiance.
- Audit régulier de l'attribut `sIDHistory` (aucun compte ne devrait avoir de SID privilégié hors migration).
- Alerter sur 4765.

## 7. Features pour l'agent IA
- Événement 4765 (rare → forte alerte).
- Présence d'un SID privilégié dans le token d'un compte non membre du groupe (enrichissement).
- Corrélation avec DCShadow / accès DC récent.

## 8. Références
- https://attack.mitre.org/techniques/T1134/005/
- https://adsecurity.org/?p=1772
