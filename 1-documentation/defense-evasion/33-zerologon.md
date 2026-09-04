# 33 — Zerologon (CVE-2020-1472)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation / Defense Evasion |
| **Technique MITRE** | T1068 |
| **Phase kill chain** | Privilege Escalation |
| **CVE** | **CVE-2020-1472** |
| **Privilèges requis** | Aucun — simple accès réseau au DC (non authentifié) |
| **Impact** | Critique (prise de contrôle du DC en quelques secondes) |

---

## 1. Description

Faille cryptographique dans **Netlogon (MS-NRPC)** : le mode de chiffrement **AES-CFB8** était utilisé avec un **vecteur d'initialisation (IV) fixé à zéro**. En envoyant des messages d'authentification avec un challenge nul, un attaquant a ~1 chance sur 256 par tentative de s'authentifier — atteignable en quelques secondes de brute force.

L'attaquant peut alors **réinitialiser le mot de passe machine du DC à une valeur vide** dans AD, puis effectuer un **DCSync** pour extraire tous les secrets (dont krbtgt). Non authentifié, ultra-rapide, dévastateur.

> ⚠️ Réinitialiser le mot de passe du DC **casse le DC en production** s'il n'est pas restauré. En lab uniquement, et prévoir la restauration du secret machine.

## 2. Prérequis

- Connectivité réseau vers le DC (port Netlogon/RPC).
- DC non patché (correctif d'août 2020 / enforcement de février 2021 absent).

## 3. Procédure de simulation (lab)

> ⚠️ Lab isolé — peut rendre le DC inutilisable si le secret n'est pas restauré.

**Outils :** Impacket (`secretsdump.py`), scripts PoC (SecuraBV/zerologon, `set_empty_pw`).

```bash
# 1. Tester la vulnérabilité
python3 zerologon_tester.py DC01 10.0.0.10

# 2. Exploiter : réinitialiser le mot de passe machine du DC à vide
python3 cve-2020-1472-exploit.py DC01 10.0.0.10

# 3. DCSync avec le compte machine du DC (mot de passe vide)
secretsdump.py -no-pass -just-dc 'DOMAINE.LOCAL/DC01$@10.0.0.10'

# 4. (Lab) RESTAURER le mot de passe machine du DC — impératif
python3 restorepassword.py DOMAINE.LOCAL/DC01@DC01 -target-ip 10.0.0.10 -hexpass <original>
```

**Résultat attendu :** dump complet des hashes du domaine.

## 4. Télémétrie générée (logs)

### Event IDs clés
| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | **4742** | Computer account changed (mot de passe machine du **DC** modifié) |
| Security (DC) | **4672** | Special privileges assigned to new logon |
| System | 5805 / 5723 | Netlogon — échecs d'établissement de canal sécurisé |
| Security (DC) | 4624 | Logon anormal du compte machine du DC |
| Security (DC) | 4662 | DCSync consécutif (voir fiche 08) |

**Anomalies discriminantes :**
- **4742 sur le compte machine d'un DC** (`DC01$`) modifié par un compte anormal / anonyme → signal quasi unique.
- Rafale de tentatives Netlogon échouées juste avant.

## 5. Détection

### Logique de détection
Le changement du mot de passe du **compte machine d'un DC** est un événement rarissime en fonctionnement normal. Un 4742 ciblant un DC, surtout non initié par le processus légitime de rotation, doit déclencher une alerte **critique** immédiate.

### Règle Sigma
```yaml
title: Zerologon - Domain Controller Machine Account Password Change
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4742
        TargetUserName|endswith: '$'    # compte machine
    dc_filter:
        TargetUserName:
            - 'DC01$'
            - 'DC02$'                    # liste des DC
    condition: selection and dc_filter
level: critical
```

### Traduction SIEM
- **Elastic (KQL) :** `event.code:4742 and winlog.event_data.TargetUserName:("DC01$" or "DC02$")`
- **QRadar :** alerte sur 4742 où `TargetUserName` ∈ table de référence des DC + corrélation avec 4662 (DCSync) dans les minutes suivantes.

## 6. Contre-mesures / Hardening

- **Patcher** (correctif de 2020 + enforcement mode de 2021 — obligatoire).
- Activer `FullSecureChannelProtection` (enforcement Netlogon).
- Surveiller les 4742 sur comptes de DC.

## 7. Features pour l'agent IA

- Événement 4742 ciblant un compte de DC (feature booléenne critique).
- Volume de tentatives Netlogon échouées (5805/erreurs RPC) par source avant le succès.
- Séquence caractéristique : rafale Netlogon → 4742 sur DC → 4662 DCSync (feature de séquence temporelle — cas d'usage idéal pour un modèle séquentiel).

## 8. Références

- https://attack.mitre.org/techniques/T1068/
- https://www.secura.com/blog/zero-logon
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472
