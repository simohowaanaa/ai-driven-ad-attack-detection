# Detection — Phases 5 et 6

> Ce dossier répond à la question centrale du projet : comment détecter les attaques que Wazuh ne voit pas par défaut ?

---

## Contexte — Pourquoi ce dossier existe

La Phase 4 a montré que **6 attaques sur 12** passaient complètement inaperçues dans Wazuh. La raison n'est pas que Wazuh est mauvais — c'est que **les catégories d'audit Windows correspondantes n'étaient pas activées**, et qu'**aucune règle ne ciblait ces événements** même quand ils remontaient.

Ce dossier contient la réponse en deux temps :

```
Problème (Phase 4)              Solution (Phase 5)            Solution (Phase 6)
──────────────────              ──────────────────            ──────────────────
6 attaques invisibles    →      Activer les audits      →     Pour les attaques
dans Wazuh par défaut           + écrire 7 règles             sans signature fixe
                                Wazuh sur-mesure              → agent IA
```

---

## Phase 5 — Règles Wazuh custom

**Fichier :** [`01-regles-wazuh.md`](01-regles-wazuh.md)

### Ce qui a été fait

**Étape 1 — Activer les audits Windows manquants**

Par défaut, Windows ne journalise pas tout. Certaines catégories d'audit sont désactivées. Sans elles, l'action se produit mais *aucun événement n'est écrit* dans les logs — Wazuh n'a rien à lire.

Les 5 catégories activées sur les 2 contrôleurs de domaine :

| Catégorie d'audit | Événement généré | Attaque couverte |
|-------------------|:----------------:|-----------------|
| Directory Service Access | 4662 | DCSync, Énumération LDAP |
| Kerberos Authentication Service | 4768 | AS-REP Roasting |
| Kerberos Service Ticket Operations | 4769 | Kerberoasting |
| Certification Services | 4887 | ADCS ESC1 |
| Process Creation | 4688 | MSSQL RCE |

**Étape 2 — Écrire les règles dans Wazuh**

Une fois les événements visibles, encore faut-il que Wazuh les reconnaisse comme des attaques. 7 règles ont été écrites dans `/var/ossec/etc/rules/local_rules.xml` et testées en conditions réelles.

### Les 7 règles validées en live

| ID | Attaque détectée | Résultat |
|:--:|-----------------|----------|
| 100010 | DCSync | ✅ 3 hits — `tywin.lannister` identifié comme attaquant |
| 100011 | Kerberoasting | ✅ 3 hits — tickets RC4 détectés |
| 100012 | ADCS ESC1 | ✅ 2 hits — certificat `administrator` émis et capturé |
| 100013 | MSSQL RCE | ✅ 7 hits — commande `xp_cmdshell whoami` capturée |
| 100014 | AS-REP Roasting | ✅ 1 hit — compte sans pré-authentification détecté |
| 100017 | Pass-the-Hash | ✅ 5 hits — logon NTLM de type 3 détecté |
| 100019 | Trust Abuse | ✅ 18 hits — mouvement cross-domain NORTH→SEVENKINGDOMS |

→ [Lire la documentation complète Phase 5](01-regles-wazuh.md)

---

## Phase 6 — Agent IA (Isolation Forest)

**Fichiers :** [`02-agent-ia.md`](02-agent-ia.md) · [`anomaly_detection.py`](anomaly_detection.py)

### Pourquoi les règles ne suffisent pas

Certaines attaques sont **cryptographiquement valides** — le contrôleur de domaine lui-même ne voit aucune différence entre un Golden Ticket forgé et un ticket légitime. Aucune règle de signature ne peut les attraper.

La solution : ne pas chercher une signature fixe, mais détecter un **comportement anormal** — un compte qui se comporte différemment des autres comptes du domaine.

### Comment ça marche

```
Wazuh OpenSearch     →    Feature engineering      →    Isolation Forest    →    Rapport
(5 000 alertes/24h)       10 variables par compte        scikit-learn              d'anomalies
                          construites depuis les logs
```

Pour chaque compte du domaine, le script calcule 10 indicateurs comportementaux : volume d'activité, nombre de logons NTLM, ratio Kerberos/NTLM, activité nocturne, et surtout `tgs_without_tgt` — le nombre de tickets TGS demandés sans AS-REQ (TGT) précédent, signature comportementale du **Golden Ticket**.

### Résultats (18 août 2026 — 23 comptes analysés)

| Compte | Score | Anomalie détectée |
|--------|:-----:|------------------|
| `robb.stark` | -0.170 | Bot RDP — 1 461 events en 24h |
| `eddard.stark` | -0.086 | **Pass-the-Hash** — 17 logons NTLM inhabituels |
| `robb.stark@NORTH…` | -0.083 | **Golden Ticket** — 610 TGS sans TGT précédent |
| `sql_svc` | -0.022 | **MSSQL RCE** — alertes xp_cmdshell |

> **Le résultat le plus significatif :** `robb.stark@NORTH` présente 610 tickets TGS sans aucune demande de TGT précédente. C'est la signature exacte du Golden Ticket — ticket forgé hors-ligne, présenté directement au KDC. Cette anomalie est **indétectable par toute règle de signature** et n'est révélée que par l'analyse comportementale.

### Utiliser le script

```bash
# 1. Exporter les alertes des dernières 24h depuis Wazuh
curl -k -u 'admin:<password>' \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=5000" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-24h"}}}}' \
  -o /tmp/wazuh_alerts.json

# 2. Lancer l'agent
python3 anomaly_detection.py /tmp/wazuh_alerts.json
```

**Dépendances :** `pip install scikit-learn pandas numpy`

→ [Lire la documentation complète Phase 6](02-agent-ia.md) · [Voir le script Python](anomaly_detection.py)

---

## Ce que couvre chaque approche

| Attaque | Règle (Phase 5) | Agent IA (Phase 6) |
|---------|:---------------:|:-----------------:|
| DCSync | ✅ | — |
| Kerberoasting | ✅ | — |
| ADCS ESC1 | ✅ | — |
| MSSQL RCE | ✅ | ✅ confirmé |
| AS-REP Roasting | ✅ | — |
| Pass-the-Hash | ✅ | ✅ confirmé |
| Trust Abuse | ✅ | — |
| **Golden Ticket** | ❌ indétectable | ✅ détecté |
| Énumération LDAP | ❌ indétectable | ⚠️ données insuffisantes |
| LLMNR Poisoning | ❌ attaque réseau | ❌ hors périmètre |
