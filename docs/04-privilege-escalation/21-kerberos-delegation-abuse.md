# 21 — Kerberos Delegation Abuse (Unconstrained / Constrained / RBCD)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation |
| **Technique MITRE** | T1558, T1134 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | — |
| **Privilèges requis** | Variable (contrôle d'un objet délégué / droit d'écrire un attribut) |
| **Impact** | Critique (usurpation d'identité, potentiellement DA) |

---

## 1. Description

La **délégation Kerberos** permet à un service d'agir « au nom » d'un utilisateur. Trois variantes abusables :

- **Unconstrained (UD)** : un hôte avec délégation non contrainte **met en cache les TGT** de tout utilisateur qui s'y connecte. En forçant un DA (ou un DC via coercion) à s'y authentifier, on capture son TGT → compromission.
- **Constrained (CD)** : le service peut demander des tickets pour des services précis « au nom » d'un utilisateur (S4U2Proxy). Abus si on contrôle le compte délégué, avec **S4U2Self** pour usurper n'importe qui (protocol transition).
- **Resource-Based Constrained Delegation (RBCD)** : la délégation est définie **côté ressource** (`msDS-AllowedToActOnBehalfOfOtherIdentity`). Si on peut **écrire cet attribut** sur un ordinateur cible (via un compte machine qu'on crée), on usurpe un admin sur cette machine.

## 2. Prérequis
- **UD** : contrôle d'un hôte en délégation non contrainte + coercion d'un compte privilégié.
- **CD** : contrôle du compte de service délégué.
- **RBCD** : droit d'écriture sur `msDS-AllowedToActOnBehalfOf...` de la cible + un compte machine contrôlé (par défaut `MachineAccountQuota=10`).

## 3. Procédure de simulation (lab)

```bash
# RBCD complet (Impacket)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Pass123' domaine.local/user:pass
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write domaine.local/user:pass
getST.py -spn cifs/target.domaine.local -impersonate Administrator 'domaine.local/EVIL$:Pass123'

# Unconstrained : capturer les TGT (Rubeus monitor) + coercion
Rubeus.exe monitor /interval:5
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4769 | Requêtes **S4U2Self / S4U2Proxy** |
| Security (DC) | **4742** | Modification d'un objet ordinateur (écriture `msDS-AllowedToActOnBehalfOf...`) |
| Security (DC) | **4741** | **Création d'un compte machine** (`EVIL$`) — MachineAccountQuota |
| Security (DC) | 4624 | Logon usurpé sur la cible |

**Anomalies :** création de compte machine par un utilisateur standard ; modification de l'attribut de délégation ; tickets S4U.

## 5. Détection

### Règle Sigma (RBCD write)
```yaml
title: RBCD - Delegation Attribute Modified / Machine Account Created by User
status: experimental
logsource:
    product: windows
    service: security
detection:
    account_created:
        EventID: 4741       # nouveau compte machine
    deleg_modified:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOfOtherIdentity'
    condition: account_created or deleg_modified
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:5136 and winlog.event_data.AttributeLDAPDisplayName:"msDS-AllowedToActOnBehalfOfOtherIdentity"`
- **QRadar :** 4741 dont le `SubjectUserName` n'est pas un admin de délégation habituel.

## 6. Contre-mesures / Hardening
- **MachineAccountQuota = 0** (empêche la création de comptes machine par les users).
- Éliminer la **délégation non contrainte** (sauf DC) ; marquer les comptes sensibles « cannot be delegated » + Protected Users.
- Auditer `msDS-AllowedToActOnBehalfOfOtherIdentity`.

## 7. Features pour l'agent IA
- Création de compte machine par un utilisateur non-admin (4741 anormal).
- Modification de l'attribut de délégation (5136) — rare et sensible.
- Tickets S4U2Self/S4U2Proxy inhabituels.
- Un utilisateur atteignant `MachineAccountQuota`.

## 8. Références
- https://attack.mitre.org/techniques/T1558/
- https://www.thehacker.recipes/ad/movement/kerberos/delegations
