# 39 — gMSA Password Abuse (ReadGMSAPassword)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1078 / T1552 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Appartenance au groupe autorisé à lire le mot de passe gMSA |
| **Impact** | Élevé (compromission d'un compte de service souvent privilégié) |

---

## 1. Description

Un **gMSA** (group Managed Service Account) est un compte de service dont le mot de passe (240 octets) est **géré automatiquement par AD** et récupérable seulement par des principals autorisés (attribut `msDS-GroupMSAMembership`). C'est une **bonne pratique anti-Kerberoasting**. Mais si un attaquant contrôle un compte **listé dans `msDS-GroupMSAMembership`**, il peut **lire le blob du mot de passe** (`msDS-ManagedPassword`), en calculer le hash NTLM, et **usurper le gMSA** — souvent privilégié.

## 2. Prérequis
- Contrôle d'un compte autorisé à lire le gMSA (relation trouvée via BloodHound : arête `ReadGMSAPassword`).

## 3. Procédure de simulation (lab)

```bash
# Récupérer le blob et calculer le hash NT du gMSA
nxc ldap 10.0.0.10 -u pc-design-07$ -H <hash> --gmsa
# ou
gMSADumper.py -u othmane -p Marketing2025 -d datacorp.local
```

**Résultat :** `svc_gmsa$ → NTLM: 3f8a...` → utilisable en Pass-the-Hash / Silver Ticket.

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4662 | Lecture de l'attribut `msDS-ManagedPassword` |

**Anomalie :** lecture de `msDS-ManagedPassword` par un principal inattendu.

## 5. Détection

### Règle Sigma
```yaml
title: gMSA Managed Password Read
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains: 'msDS-ManagedPassword'
    condition: selection
level: medium
```

### Traduction SIEM
- **Elastic :** `event.code:4662 and winlog.event_data.Properties:*msDS-ManagedPassword*`

## 6. Contre-mesures / Hardening
- **Restreindre** `msDS-GroupMSAMembership` aux seuls hôtes qui exécutent le service.
- Auditer les arêtes `ReadGMSAPassword` (BloodHound) régulièrement.
- Ne pas mettre les gMSA dans des groupes privilégiés inutilement.

## 7. Features pour l'agent IA
- Lecture de `msDS-ManagedPassword` par un principal hors liste attendue.
- Corrélation : lecture gMSA → authentification du gMSA depuis un hôte inhabituel.
- Nouveauté de la relation (compte lecteur, gMSA).

## 8. Références
- https://www.thehacker.recipes/ad/movement/credentials/dumping/gmsa
- https://github.com/micahvandeusen/gMSADumper
