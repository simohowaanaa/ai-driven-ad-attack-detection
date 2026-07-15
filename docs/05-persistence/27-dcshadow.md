# 27 — DCShadow

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence / Defense Evasion |
| **Technique MITRE** | T1207 (Rogue Domain Controller) |
| **Phase kill chain** | Defense Evasion |
| **CVE** | — |
| **Privilèges requis** | Domain Admin (droits de réplication) |
| **Impact** | Critique (modifications AD furtives, non journalisées normalement) |

---

## 1. Description

**DCShadow** enregistre temporairement un **faux contrôleur de domaine** (en modifiant l'objet dans la partition de configuration), puis **pousse des modifications** dans AD via la réplication légitime (SID History, ACL, `primaryGroupID`, etc.). Comme les changements arrivent **par réplication** et non par une écriture LDAP classique, ils **contournent en grande partie le journal de sécurité** — d'où l'usage en persistance/évasion furtive.

## 2. Prérequis
- Droits Domain Admin (ou équivalent : écriture sur l'objet Configuration + droits de réplication).

## 3. Procédure de simulation (lab)

```powershell
# Mimikatz — 2 instances : une SYSTEM (serveur), une DA (push)
# Instance SYSTEM :
lsadump::dcshadow /object:targetuser /attribute:sidHistory /value:S-1-5-21-...-519
# Instance DA :
lsadump::dcshadow /push
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4742** | Modification de l'objet ordinateur (ajout SPN `GC/…`, `DRS`) |
| Security (DC) | **5137 / 5136** | Création/modification d'objet dans la partition Configuration (nTDSDSA) |
| Security (DC) | 4662 | Opérations de réplication (`GetNCChanges` **entrantes** inhabituelles) |

**Anomalie clé :** apparition d'un objet **nTDSDSA / serveur** dans la config non associé à un vrai DC ; ajout de SPN de réplication à un hôte non-DC.

## 5. Détection

### Règle Sigma
```yaml
title: DCShadow - Rogue DC Registration
status: experimental
logsource:
    product: windows
    service: security
detection:
    spn_add:
        EventID: 4742
        ServicePrincipalNames|contains:
            - 'GC/'
            - 'E3514235-4B06-11D1-AB04-00C04FC2DCD2'   # GUID service réplication (DRS)
    config_obj:
        EventID: 5137
        ObjectClass: 'nTDSDSA'
    condition: spn_add or config_obj
level: critical
```

### Traduction SIEM
- **Elastic :** `event.code:5137 and winlog.event_data.ObjectClass:"nTDSDSA"` ; ou 4742 ajoutant le SPN DRS.
- **QRadar :** alerter sur toute réplication provenant d'une source hors table des DC.

## 6. Contre-mesures / Hardening
- Détection = principale défense (l'action mime la réplication légitime).
- Surveiller les objets de la partition Configuration (nTDSDSA).
- Limiter strictement les comptes disposant des droits de réplication.

## 7. Features pour l'agent IA
- Nouvel objet nTDSDSA / SPN de réplication ajouté à un hôte hors liste DC (feature booléenne forte).
- Réplication entrante depuis une source non-DC.
- Modification d'attributs sensibles (sidHistory, primaryGroupID) hors chemin LDAP normal.

## 8. Références
- https://attack.mitre.org/techniques/T1207/
- https://www.dcshadow.com/
