# 14 — Pass-the-Ticket (PtT)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Lateral Movement |
| **Technique MITRE** | T1550.003 |
| **Phase kill chain** | Lateral Movement |
| **CVE** | — |
| **Privilèges requis** | Accès à un ticket Kerberos (TGT/TGS) volé |
| **Impact** | Élevé |

---

## 1. Description

Kerberos matérialise l'authentification par des **tickets** (TGT/TGS). Un attaquant qui **vole un ticket** en mémoire (via LSASS dump) peut l'**injecter** dans sa propre session (`.kirbi`/`.ccache`) et se faire passer pour la victime, **sans connaître ni le mot de passe ni le hash**. Un TGT volé permet de demander des TGS pour tout service accessible à la victime.

## 2. Prérequis
- Un ticket valide extrait (LSASS, fichier ccache Linux, `.kirbi`).

## 3. Procédure de simulation (lab)

```powershell
# Mimikatz — exporter puis réinjecter
sekurlsa::tickets /export
kerberos::ptt [0;abc]-2-0-...-user@krbtgt-DOMAINE.LOCAL.kirbi
```
```bash
# Impacket / Linux
export KRB5CCNAME=/tmp/stolen.ccache
psexec.py -k -no-pass domaine.local/user@dc01
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4769 | TGS demandé avec un TGT volé |
| Security (cible) | 4624 | Logon Type 3, `AuthenticationPackage = Kerberos` |
| Sysmon | 10 | Accès LSASS (vol préalable du ticket) |

**Anomalie :** ticket utilisé depuis une **machine/adresse différente** de celle où il a été émis ; incohérence hôte source vs ticket.

## 5. Détection

### Logique
Corréler l'**IP/host d'émission** du ticket (4768/4769) avec l'IP/host d'**utilisation** — un TGT utilisé depuis une autre machine est suspect. Détecter l'accès LSASS préalable.

### Règle Sigma
```yaml
title: Pass-the-Ticket - Kerberos Ticket Used from Different Host
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
    # corrélation IP émission vs utilisation → moteur SIEM/IA
    condition: selection
level: medium
```

### Traduction SIEM
- **Elastic (EQL) :** séquence 4768(IP_A) → 4769(IP_B) pour le même compte.
- **QRadar :** corréler avec Sysmon 10 (LSASS) en amont.

## 6. Contre-mesures / Hardening
- Credential Guard, Protected Users (limite la mise en cache des tickets).
- Réduire la durée de vie des tickets.
- Détecter/empêcher le dump LSASS (fiche 09).

## 7. Features pour l'agent IA
- Distance/écart entre host d'émission et host d'usage d'un ticket.
- Réutilisation d'un même ticket depuis plusieurs sources.
- Corrélation LSASS access → activité Kerberos ailleurs.

## 8. Références
- https://attack.mitre.org/techniques/T1550/003/
- https://www.thehacker.recipes/ad/movement/kerberos/ptt
