# 47 — Domain / Forest Trust Abuse (SID History & Trust Key)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation / Lateral Movement |
| **Technique MITRE** | T1134.005 / T1482 |
| **Phase kill chain** | Privilege Escalation (inter-domaine) |
| **CVE** | — |
| **Privilèges requis** | Domain Admin sur un domaine d'une relation de confiance |
| **Impact** | Critique (passer d'un domaine compromis à un autre, voire à toute la forêt) |

---

## 1. Description

Les entreprises relient plusieurs domaines par des **relations de confiance (trusts)** : les utilisateurs d'un domaine A peuvent accéder aux ressources d'un domaine B. Deux abus majeurs :

- **SID History inter-domaine :** en forgeant un ticket (Golden Ticket) et en y injectant le **SID d'un groupe privilégié de l'AUTRE domaine** (ex. Enterprise Admins), on obtient des droits **dans le domaine cible**. Si le **SID Filtering** n'est pas actif (cas fréquent des trusts **intra-forêt**), l'attaque réussit → compromission de toute la **forêt**.
- **Trust Key (inter-realm TGT) :** chaque trust a une **clé partagée**. En la volant (via DCSync sur le compte de trust `DOMAINB$`), on forge un **ticket inter-domaine** pour accéder au domaine de confiance.

## 2. Prérequis
- **Domain Admin** sur un domaine (souvent obtenu via les catégories précédentes).
- Une relation de confiance vers le domaine cible.
- SID Filtering absent/faible (par défaut pour les trusts intra-forêt).

## 3. Procédure de simulation (lab)

```powershell
# Golden Ticket inter-domaine avec SID History Enterprise Admins de la forêt
mimikatz # kerberos::golden /user:Administrator /domain:child.datacorp.local \
  /sid:<SID_child> /krbtgt:<hash> /sids:<SID_racine>-519 /ptt
```
```bash
# Voler la clé de trust puis forger un TGT inter-realm
secretsdump.py -just-dc-user 'DOMAINB$' datacorp.local/admin@dc01
ticketer.py -nthash <trust_key> -domain-sid ... -domain child.datacorp.local \
  -spn krbtgt/parent.datacorp.local Administrator
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC cible) | 4769 | TGS inter-domaine avec **SID History** privilégié |
| Security (DC) | 4768 | TGT inter-realm |
| Security | 4662 | DCSync du compte de trust (`DOMAINB$`) |

**Anomalie clé :** un ticket provenant d'un domaine de confiance revendiquant des SID privilégiés du domaine local (Enterprise Admins).

## 5. Détection

### Règle Sigma
```yaml
title: Cross-Domain Trust Abuse - Privileged SID History in Foreign Ticket
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        # SID History contenant des RID privilégiés (512/518/519) d'un autre domaine
    condition: selection
level: high
falsepositives:
    - Requiert enrichissement sur les SID présents dans le ticket
```

### Traduction SIEM
- **XSOAR :** playbook inspectant les SID d'un ticket inter-domaine ; alerte si RID privilégié (519 Enterprise Admins) présent.
- **QRadar :** 4662 sur un compte de trust (`*$` de type trust) = très suspect.

## 6. Contre-mesures / Hardening
- **Activer le SID Filtering / Quarantine** sur les trusts (surtout externes).
- Modèle de **forêt rouge / ESAE / Tier 0** pour isoler les domaines critiques.
- Considérer la **forêt** comme la vraie frontière de sécurité (pas le domaine).
- Rotation des clés de trust.

## 7. Features pour l'agent IA
- Ticket inter-domaine revendiquant des SID privilégiés d'un autre domaine (feature d'enrichissement).
- DCSync visant un **compte de trust**.
- Activité inter-domaine inhabituelle depuis un domaine récemment compromis.

## 8. Références
- https://attack.mitre.org/techniques/T1134/005/
- https://www.thehacker.recipes/ad/movement/trusts
