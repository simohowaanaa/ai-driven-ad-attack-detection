# 25 — ADCS Abuse (ESC1–ESC8, Certipy)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation / Persistence |
| **Technique MITRE** | T1649 (Steal or Forge Authentication Certificates) |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | Diverses mauvaises configs (ESC1-8), CVE-2022-26923 (ESC alt.) |
| **Privilèges requis** | Variable (souvent utilisateur standard) |
| **Impact** | Critique (certificat → authentification en tant que DA) |

---

## 1. Description

**AD Certificate Services (ADCS)** émet des certificats utilisables pour l'authentification Kerberos (PKINIT). De **mauvaises configurations de templates/CA** permettent à un attaquant d'obtenir un certificat **au nom d'un compte privilégié** — un certificat reste valide même après changement de mot de passe → **persistance**. Catégories (SpecterOps « Certified Pre-Owned ») :

| Vecteur | Résumé |
|---------|--------|
| **ESC1** | Template autorisant un **SAN arbitraire** + auth client → certif au nom d'un DA |
| **ESC2** | Template « Any Purpose » ou pas d'EKU |
| **ESC3** | Certificate Request Agent (enrollment agent) |
| **ESC4** | ACL faibles sur le template (write) |
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTNAME2` sur la CA |
| **ESC7** | Droits `ManageCA`/`ManageCertificates` |
| **ESC8** | **Endpoint HTTP de la CA** + relais NTLM (voir fiche 17/24) |

## 2. Prérequis
- ADCS déployé, au moins un template/CA mal configuré.
- Compte de domaine (souvent standard) ; pour ESC8, une coercion.

## 3. Procédure de simulation (lab)

```bash
# Recon des mauvaises configs
certipy find -u user@domaine.local -p pass -dc-ip 10.0.0.10 -vulnerable -stdout

# ESC1 : demander un certif au nom d'un admin (SAN arbitraire)
certipy req -u user@domaine.local -p pass -ca CA01 -template VulnTemplate -upn administrator@domaine.local

# Authentifier avec le certificat → TGT + hash NT
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| CA / Security | **4886 / 4887** | Demande / émission de certificat |
| CA / Security | 4899/4900 | Modification de template CA |
| Security (DC) | 4768 | TGT via **PKINIT** (certificat) — `Certificate Information` renseigné |
| Security (DC) | 4624 | Logon consécutif |

**Anomalie clé :** certificat émis dont le **SAN/UPN ≠ le demandeur** ; TGT PKINIT pour un compte à privilèges obtenu via certificat récent.

## 5. Détection

### Règle Sigma
```yaml
title: ADCS Abuse - Certificate Issued with Mismatched SAN / PKINIT for Privileged User
status: experimental
logsource:
    product: windows
    service: security
detection:
    cert_issued:
        EventID: 4887
    pkinit:
        EventID: 4768
        CertificateInformation|exists: true
    condition: cert_issued or pkinit
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:4886 or event.code:4887` (enrichir : demandeur ≠ SAN) ; `event.code:4768 and winlog.event_data.CertificateInfo:*`.
- **XSOAR :** playbook comparant `Requester` vs `SubjectAltName` du certificat → alerte si divergence.

## 6. Contre-mesures / Hardening
- Auditer avec `certipy find` / **PSPKIAudit** ; corriger les templates (retirer SAN arbitraire, EKU stricts, ACL).
- Désactiver `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6).
- **EPA + désactiver HTTP** sur l'enrollment web (ESC8).
- Mapping fort certificat↔compte (KB5014754).

## 7. Features pour l'agent IA
- Divergence Requester ↔ SAN/UPN du certificat émis (feature d'enrichissement clé).
- TGT PKINIT pour un compte privilégié depuis un certificat fraîchement émis.
- Émission de certificat par/pour un compte inhabituel.
- Modifications de templates/CA (rares).

## 8. Références
- https://posts.specterops.io/certified-pre-owned-d95910965cd2
- https://github.com/ly4k/Certipy
