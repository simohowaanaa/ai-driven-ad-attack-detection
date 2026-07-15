# 01 — LDAP Enumeration (BloodHound / SharpHound)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Discovery |
| **Technique MITRE** | T1087.002, T1069.002, T1482 |
| **Phase kill chain** | Discovery |
| **CVE** | — |
| **Privilèges requis** | Tout compte de domaine authentifié |
| **Impact** | Moyen (cartographie complète des chemins d'attaque) |

---

## 1. Description

AD est une base LDAP interrogeable par tout compte authentifié. Des outils comme **SharpHound** (collecteur de **BloodHound**) émettent en masse des requêtes LDAP + sessions SMB pour cartographier utilisateurs, groupes, ACL, sessions, GPO, relations de confiance et **délégations**. Le résultat est un graphe des **chemins d'attaque** vers Domain Admin. C'est presque toujours la première étape d'une intrusion AD.

## 2. Prérequis

- Un compte de domaine valide (non privilégié suffit).
- Connectivité LDAP (389/636) et SMB (445) vers le DC.

## 3. Procédure de simulation (lab)

```bash
# BloodHound.py (Linux)
bloodhound-python -u user -p password -d domaine.local -ns 10.0.0.10 -c All
```
```powershell
# SharpHound (Windows)
SharpHound.exe -c All --zipfilename loot
```

**Résultat attendu :** archive JSON/ZIP importable dans BloodHound.

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4662 | Accès massif aux objets AD |
| Directory Service | 1644 | Requêtes LDAP coûteuses/inefficaces (si audit activé) |
| Security (DC) | 4661 | Handle to object (SAM/DS) |
| Sysmon | 3 | Connexions réseau vers 389/445 |

**Anomalies :** volume anormal de requêtes LDAP depuis une station, énumération de tous les objets en peu de temps.

## 5. Détection

### Logique
Volume/diversité anormale de requêtes LDAP d'un même hôte, filtres LDAP caractéristiques de SharpHound, pics de 4662/1644.

### Règle Sigma
```yaml
title: Possible BloodHound/SharpHound LDAP Enumeration
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
    timeframe: 5m
    condition: selection | count() by SubjectUserName > 1000
level: medium
```
> Le vrai signal est le **volume** — mieux capté par un seuil/anomalie que par un simple match.

### Traduction SIEM
- **Elastic (KQL) :** `event.code:4662` agrégé par `winlog.event_data.SubjectUserName` avec seuil.
- **QRadar :** règle de type « behavior » comptant les 4662 distincts par utilisateur/heure.
- **NDR :** détection de volume LDAP (Zeek `ldap.log`).

## 6. Contre-mesures / Hardening

- Activer l'audit LDAP coûteux (event 1644).
- Restreindre l'énumération (peu praticable — AD est ouvert par design).
- Déployer des **comptes/objets leurres (honeytokens)** dans AD pour détecter la collecte.

## 7. Features pour l'agent IA

- Nombre de requêtes LDAP / objets distincts consultés par hôte / fenêtre.
- Entropie des types d'objets demandés (un utilisateur normal ne lit pas tout AD).
- Nouveauté de l'hôte comme source d'énumération de masse.
- Corrélation LDAP massif + sessions SMB multiples.

## 8. Références

- https://attack.mitre.org/techniques/T1087/002/
- https://github.com/SpecterOps/BloodHound
