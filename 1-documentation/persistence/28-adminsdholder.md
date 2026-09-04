# 28 — AdminSDHolder Abuse

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence |
| **Technique MITRE** | T1098 (Account Manipulation) |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Droits d'écriture sur l'objet AdminSDHolder (typiquement DA) |
| **Impact** | Élevé (persistance auto-réappliquée toutes les 60 min) |

---

## 1. Description

L'objet **AdminSDHolder** définit une ACL « modèle » que le processus **SDProp** ré-applique **toutes les 60 minutes** à tous les comptes/groupes protégés (Domain Admins, etc.) via l'attribut `adminCount=1`. Un attaquant qui **ajoute sa propre ACE** (ex. `Full Control`) sur AdminSDHolder verra ce droit **automatiquement propagé et restauré** sur les objets protégés — même si un admin le retire manuellement. Persistance résiliente et discrète.

## 2. Prérequis
- Droit d'écriture sur `CN=AdminSDHolder,CN=System,DC=...` (souvent DA au départ).

## 3. Procédure de simulation (lab)

```powershell
# PowerView — ajouter des droits pour l'attaquant sur AdminSDHolder
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domaine,DC=local' `
  -PrincipalIdentity attacker -Rights All
# Attendre le cycle SDProp (60 min) ou le forcer
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **5136** | Modification de la **DACL** de l'objet AdminSDHolder |
| Security (DC) | 4780 | ACL définie sur des comptes admin (par SDProp) |
| Security (DC) | 4738 | Modification de compte utilisateur (adminCount) |

**Anomalie clé :** modification de la DACL d'AdminSDHolder ; comptes non-admin acquérant soudainement `adminCount=1`.

## 5. Détection

### Règle Sigma
```yaml
title: AdminSDHolder ACL Modification (Persistence)
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        ObjectDN|contains: 'CN=AdminSDHolder,CN=System'
        AttributeLDAPDisplayName: 'nTSecurityDescriptor'
    condition: selection
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:5136 and winlog.event_data.ObjectDN:*AdminSDHolder* and winlog.event_data.AttributeLDAPDisplayName:"nTSecurityDescriptor"`
- **QRadar :** alerter sur toute modification d'AdminSDHolder + revue périodique des comptes `adminCount=1` inattendus.

## 6. Contre-mesures / Hardening
- Restreindre l'écriture sur AdminSDHolder aux seuls admins de niveau 0.
- Audit régulier des objets `adminCount=1` et des ACL des objets protégés.
- Alerte immédiate sur 5136 ciblant AdminSDHolder.

## 7. Features pour l'agent IA
- Modification de la DACL d'AdminSDHolder (événement rarissime → forte alerte).
- Apparition de nouveaux `adminCount=1` non corrélés à un ajout de groupe légitime.
- ACE accordant Full Control à un principal non-admin sur objets protégés.

## 8. Références
- https://attack.mitre.org/techniques/T1098/
- https://adsecurity.org/?p=1906
