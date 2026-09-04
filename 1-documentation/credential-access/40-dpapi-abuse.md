# 40 — DPAPI Abuse

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1555 / T1552 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Accès local (utilisateur) ; ou Domain Admin pour la clé de sauvegarde |
| **Impact** | Élevé (déchiffrement de mots de passe navigateurs, RDP, Wi-Fi, certificats…) |

---

## 1. Description

**DPAPI** (Data Protection API) est le mécanisme Windows qui chiffre les secrets des applications : mots de passe **navigateurs**, identifiants **RDP**, clés **Wi-Fi**, cookies, certificats… Il s'appuie sur une **clé maître (masterkey)** dérivée du mot de passe de l'utilisateur. Deux abus :
- **Local** : depuis la session d'un utilisateur, déchiffrer ses propres secrets DPAPI.
- **Domaine (le plus grave)** : AD stocke une **clé de sauvegarde DPAPI de domaine** (`domain backup key`). Un Domain Admin qui la vole peut **déchiffrer les secrets DPAPI de N'IMPORTE QUEL utilisateur du domaine** — persistance et pillage massif.

## 2. Prérequis
- **Local** : accès à la session/aux fichiers de l'utilisateur.
- **Domaine** : privilèges Domain Admin (pour extraire la backup key du DC).

## 3. Procédure de simulation (lab)

```powershell
# Local — déchiffrer les masterkeys de l'utilisateur courant
mimikatz # dpapi::masterkey /in:"%APPDATA%\...\Protect\...\masterkey"

# Domaine — voler la clé de sauvegarde DPAPI (une seule fois, réutilisable "à vie")
mimikatz # lsadump::backupkeys /system:dc01.datacorp.local /export
```
```bash
# Impacket
dpapi.py backupkeys -t datacorp.local/admin:pass@dc01 --export
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4662 | Accès à l'objet **BCKUPKEY** (clé de sauvegarde DPAPI) |
| Sysmon | 10 | Accès LSASS (extraction locale) |

**Anomalie :** accès à l'objet `BCKUPKEY` du domaine (rarissime) ; lecture massive de masterkeys.

## 5. Détection

### Règle Sigma
```yaml
title: DPAPI Domain Backup Key Access
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        ObjectName|contains: 'BCKUPKEY'
    condition: selection
level: high
```

### Traduction SIEM
- **Elastic :** `event.code:4662 and winlog.event_data.ObjectName:*BCKUPKEY*`

## 6. Contre-mesures / Hardening
- Protéger les DC (l'extraction de la backup key = déjà Domain Admin).
- Credential Guard (protège certains secrets).
- Surveiller l'accès à l'objet `BCKUPKEY`.

## 7. Features pour l'agent IA
- Accès à l'objet `BCKUPKEY` du domaine (événement extrêmement rare → alerte forte).
- Volume de masterkeys déchiffrées sur un hôte.
- Corrélation avec un accès LSASS / privilèges DA récents.

## 8. Références
- https://attack.mitre.org/techniques/T1555/
- https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets
