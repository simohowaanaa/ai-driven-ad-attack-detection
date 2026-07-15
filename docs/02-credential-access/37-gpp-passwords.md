# 37 — GPP Passwords (cPassword / MS14-025)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1552.006 (Group Policy Preferences) |
| **Phase kill chain** | Credential Access |
| **CVE** | MS14-025 |
| **Privilèges requis** | Tout compte de domaine (lecture de SYSVOL) |
| **Impact** | Élevé (mot de passe souvent d'un compte admin local, réutilisé partout) |

---

## 1. Description

Les **Group Policy Preferences (GPP)** permettaient de pousser des configurations (créer un compte admin local, mapper un lecteur…) contenant parfois un **mot de passe**. Ce mot de passe était stocké dans un fichier XML dans **SYSVOL** (partage lisible par tout le domaine), chiffré en AES… mais **Microsoft a publié la clé AES** ! N'importe quel compte peut donc lire ces fichiers et **déchiffrer le mot de passe**. Souvent un compte **admin local identique sur tout le parc** → compromission massive.

## 2. Prérequis
- Un compte de domaine (lecture de `\\domaine\SYSVOL`).
- Une GPP avec `cpassword` déployée (héritage — encore fréquent).

## 3. Procédure de simulation (lab)

```bash
# Chercher et déchiffrer automatiquement
nxc smb 10.0.0.10 -u othmane -p Marketing2025 -M gpp_password

# Ou manuellement : trouver les XML puis déchiffrer
findstr /S /I cpassword \\datacorp.local\SYSVOL\*.xml
gpp-decrypt <chaine_cpassword_chiffree>
```

**Résultat :** mot de passe en clair (ex. un compte `LocalAdmin`).

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 5145 | Accès au partage SYSVOL / aux fichiers `Groups.xml`, `Services.xml` |
| Sysmon | 3 | Connexion SMB vers SYSVOL |

**Anomalie :** lecture ciblée des fichiers GPP (`*.xml` contenant `cpassword`) dans SYSVOL.

## 5. Détection

### Règle Sigma
```yaml
title: GPP Password Access in SYSVOL
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        ShareName|contains: 'SYSVOL'
        RelativeTargetName|endswith:
            - 'Groups.xml'
            - 'Services.xml'
            - 'ScheduledTasks.xml'
    condition: selection
level: medium
```

### Traduction SIEM
- **Elastic :** `event.code:5145 and winlog.event_data.ShareName:*SYSVOL* and winlog.event_data.RelativeTargetName:(*Groups.xml* or *Services.xml*)`

## 6. Contre-mesures / Hardening
- Appliquer **MS14-025** (empêche la création de nouvelles GPP avec mot de passe).
- **Auditer et supprimer** les XML existants contenant `cpassword` dans SYSVOL.
- Utiliser **LAPS** pour les mots de passe admin local (voir fiche 38).

## 7. Features pour l'agent IA
- Accès aux fichiers GPP `*.xml` dans SYSVOL par un compte inhabituel.
- Recherche récursive de `cpassword` (motif de scan).
- Corrélation : lecture GPP → connexion admin local sur plusieurs machines.

## 8. Références
- https://attack.mitre.org/techniques/T1552/006/
- https://adsecurity.org/?p=2288
