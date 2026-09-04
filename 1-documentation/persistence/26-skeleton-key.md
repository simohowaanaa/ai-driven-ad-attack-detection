# 26 — Skeleton Key

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence / Defense Evasion |
| **Technique MITRE** | T1556.001 |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Domain Admin / SYSTEM sur le DC |
| **Impact** | Critique (mot de passe maître pour tous les comptes) |

---

## 1. Description

**Skeleton Key** patche en mémoire le processus **LSASS d'un DC** pour injecter un **mot de passe maître** valable pour **tous les comptes** du domaine, tout en laissant les vrais mots de passe fonctionner. L'attaquant peut alors s'authentifier comme n'importe qui avec le mot de passe maître (par défaut Mimikatz : `mimikatz`). Non persistant au reboot (en mémoire), mais très puissant tant que le DC n'est pas redémarré.

## 2. Prérequis
- Droits admin/SYSTEM sur le DC.
- Contourner LSA Protection (nécessite un driver signé côté attaquant → plus dur si RunAsPPL).

## 3. Procédure de simulation (lab)

```powershell
# Mimikatz sur le DC
privilege::debug
misc::skeleton
# Ensuite : auth de n'importe quel compte avec le mot de passe "mimikatz"
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| System | **7045** | Service/driver chargé (si `mimidrv` pour patcher LSA protection) |
| Sysmon | **10** | Accès à `lsass.exe` avec droits d'écriture mémoire |
| Sysmon | 7 | Chargement d'image dans lsass |
| Security | 4673/4611 | Usage de privilèges / subsystem d'auth |

**Anomalie clé :** écriture dans la mémoire de LSASS sur un **DC** ; les comptes s'authentifient avec un downgrade RC4 anormal.

## 5. Détection

### Règle Sigma
```yaml
title: Skeleton Key - LSASS Memory Patch on Domain Controller
status: experimental
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1438'
            - '0x143a'
            - '0x1fffff'    # accès en écriture mémoire
    condition: selection
level: critical
```

### Traduction SIEM
- **Elastic :** Sysmon EID 10 sur lsass avec masque d'écriture, sur un hôte de la table des DC.
- **QRadar :** corréler 7045 (mimidrv) + accès LSASS sur DC.

## 6. Contre-mesures / Hardening
- **RunAsPPL / LSA Protection** (empêche le patch mémoire).
- Restreindre l'accès admin aux DC (Tiering, PAW).
- Redémarrage supprime la Skeleton Key (détection = clé).

## 7. Features pour l'agent IA
- Accès en écriture à LSASS sur un DC (feature critique rare).
- Chargement de driver non signé/inconnu sur DC.
- Authentifications multiples réussies avec downgrade de chiffrement anormal.

## 8. Références
- https://attack.mitre.org/techniques/T1556/001/
- https://www.thehacker.recipes/ad/persistence/
