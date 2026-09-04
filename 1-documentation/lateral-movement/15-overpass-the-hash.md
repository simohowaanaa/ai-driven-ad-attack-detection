# 15 — Overpass-the-Hash (Pass-the-Key)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Lateral Movement |
| **Technique MITRE** | T1550.002 / T1558 |
| **Phase kill chain** | Lateral Movement |
| **CVE** | — |
| **Privilèges requis** | Hash NTLM ou clé AES d'un compte |
| **Impact** | Élevé |

---

## 1. Description

L'**Overpass-the-Hash** convertit un **hash NTLM** (ou une clé AES) en un **vrai TGT Kerberos**. L'attaquant utilise le hash pour la pré-authentification Kerberos et obtient un ticket légitime — combinant la furtivité de Kerberos avec un secret volé. Cela permet ensuite d'utiliser des outils Kerberos (au lieu de NTLM, plus surveillé).

## 2. Prérequis
- Hash NTLM / clé AES d'un compte (LSASS, DCSync…).

## 3. Procédure de simulation (lab)

```powershell
# Mimikatz — hash → TGT
sekurlsa::pth /user:admin /domain:domaine.local /ntlm:<hash> /run:powershell.exe
# puis dans la nouvelle session : Rubeus asktgt, ou accès Kerberos
```
```bash
# Rubeus — demander un TGT à partir du hash/clé
Rubeus.exe asktgt /user:admin /rc4:<hash> /ptt
# ou clé AES (plus furtif, pas de RC4)
Rubeus.exe asktgt /user:admin /aes256:<key> /ptt
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4768** | TGT demandé — **type de chiffrement RC4 (0x17)** si `/rc4` |
| Sysmon | 10 | Accès LSASS préalable |

**Anomalie :** demande de TGT en **RC4** pour un compte qui utilise normalement AES ; TGT obtenu sans logon interactif préalable de l'utilisateur.

## 5. Détection

### Règle Sigma
```yaml
title: Overpass-the-Hash - RC4 TGT Request Anomaly
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4768
        TicketEncryptionType: '0x17'   # RC4
    condition: selection
level: medium
falsepositives:
    - Environnements legacy encore en RC4
```

### Traduction SIEM
- **Elastic :** `event.code:4768 and winlog.event_data.TicketEncryptionType:"0x17"` + baseline par compte.
- **QRadar :** anomalie « compte demandant soudainement du RC4 ».

## 6. Contre-mesures / Hardening
- **Désactiver RC4** → force l'usage d'AES et réduit la surface.
- Credential Guard, Protected Users.

## 7. Features pour l'agent IA
- Changement du type de chiffrement Kerberos par compte (AES→RC4).
- TGT sans logon interactif traçable en amont.
- Corrélation LSASS access → nouveau TGT.

## 8. Références
- https://attack.mitre.org/techniques/T1550/002/
- https://www.thehacker.recipes/ad/movement/kerberos/pass-the-key
