# 18 — Golden Ticket

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Persistence / Privilege Escalation |
| **Technique MITRE** | T1558.001 |
| **Phase kill chain** | Persistence |
| **CVE** | — |
| **Privilèges requis** | Hash/clé AES du compte **krbtgt** (obtenu via DCSync ou NTDS.dit) |
| **Impact** | Critique (accès domaine complet, quasi indétectable, persistant) |

---

## 1. Description

Le compte **krbtgt** signe et chiffre tous les **TGT** du domaine. Qui possède sa clé peut **forger un TGT arbitraire** (« Golden Ticket ») : n'importe quel utilisateur, membre de n'importe quel groupe (ex. Domain Admins via le PAC), avec une durée de vie choisie (par défaut Mimikatz : 10 ans).

Comme le TGT est forgé hors-ligne et accepté par tous les DC sans re-vérification, c'est un moyen de **persistance de très haut niveau**. Seule la rotation (double) du mot de passe krbtgt l'invalide.

## 2. Prérequis

- Hash NTLM **ou** clé AES256 du compte **krbtgt**.
- SID du domaine.
- Généralement précédé d'un **DCSync** ou d'une extraction **NTDS.dit**.

## 3. Procédure de simulation (lab)

> ⚠️ Lab isolé uniquement.

**Outils :** Mimikatz, Impacket (`ticketer.py`).

```powershell
# Mimikatz — forger et injecter le TGT
kerberos::golden /user:Administrator /domain:domaine.local /sid:S-1-5-21-... /krbtgt:<hash_NTLM_krbtgt> /ptt
```

```bash
# Impacket
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain domaine.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domaine.local/Administrator@dc01
```

**Résultat attendu :** accès administrateur au domaine sans mot de passe valide.

## 4. Télémétrie générée (logs)

### Event IDs clés
| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 4769 | TGS request **sans 4768 préalable** (le TGT n'a jamais été émis par le DC) |
| Security (DC) | 4624 | Logon avec le compte usurpé |

**Anomalies discriminantes :**
- **TGS (4769) sans TGT (4768) correspondant** pour le compte → le TGT n'a jamais été légitimement émis.
- Durée de vie de ticket anormale (10 ans par défaut Mimikatz).
- Champs incohérents dans le PAC / nom de domaine mal formé (anciennes versions de Mimikatz mettaient `eo.oe.kiwi`).
- Compte inexistant/désactivé présentant une activité Kerberos.

## 5. Détection

### Logique de détection
Difficile par signature. Approches :
1. **Corrélation 4769 sans 4768** correspondant (nécessite de suivre l'état par compte → cas d'usage IA idéal).
2. Durée de vie de ticket > politique de domaine.
3. Activité d'un compte krbtgt-forgé (SID/RID incohérents).

### Règle Sigma
```yaml
title: Golden Ticket - TGS Request Without Corresponding TGT
status: experimental
logsource:
    product: windows
    service: security
detection:
    tgs:
        EventID: 4769
    # La corrélation "absence de 4768 associé" se fait côté moteur (SIEM/IA), pas dans un simple match
    condition: tgs
level: high
falsepositives:
    - Renouvellements légitimes ; nécessite corrélation stateful
```

### Traduction SIEM
- **Elastic (EQL) — séquence anormale :** rechercher des 4769 pour un compte sans 4768 dans la fenêtre précédente.
- **QRadar :** règle de type « building block » sur l'absence d'événement corrélé (rule with anomaly).

## 6. Contre-mesures / Hardening

- **Rotation double du mot de passe krbtgt** (2 fois, à intervalle > durée de vie max des tickets) — invalide tous les Golden Tickets existants.
- Réduire la durée de vie maximale des tickets.
- Protéger l'accès aux secrets (DCSync/NTDS = prérequis).
- Tiering / PAW pour limiter la compromission initiale du krbtgt.

## 7. Features pour l'agent IA

- **Feature phare :** ratio/écart entre événements 4769 et 4768 par compte (un Golden Ticket casse cette relation).
- Durée de vie demandée des tickets vs politique.
- Comptes présentant une activité Kerberos sans authentification initiale traçable.
- Incohérences PAC (groupes revendiqués vs appartenance réelle en base).

## 8. Références

- https://attack.mitre.org/techniques/T1558/001/
- https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden
