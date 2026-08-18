# 🤖 Phase 6 — Agent IA de détection d'anomalies AD

> **But :** détecter les attaques que les règles de signature (Phase 5) ne peuvent pas capturer — Golden Ticket, énumération LDAP, Pass-the-Hash furtif — en apprenant le comportement normal des comptes et en alertant sur les anomalies.

---

## 🧠 Pourquoi l'IA après les règles ?

Les règles Wazuh (Phase 5) détectent les attaques à **signature fixe** : un event précis, un champ précis, une valeur précise. Mais certaines attaques sont **cryptographiquement légitimes** — le DC lui-même ne voit aucune différence.

| Approche | Ce qu'elle détecte | Limite |
|----------|-------------------|--------|
| Règles (Phase 5) | Signature connue et fixe | Aveugle aux attaques "valides" |
| IA (Phase 6) | Comportement anormal | Peut générer des faux positifs |

**Phase 5 + Phase 6 = couverture complète** — l'architecture d'un SOC moderne.

---

## 🎯 Attaques ciblées

| Attaque | Pourquoi l'IA et pas une règle |
|---------|-------------------------------|
| **Golden Ticket** | Ticket forgé cryptographiquement valide — aucune signature. Signal : TGS sans TGT précédent (le ticket est présenté directement sans AS-REQ normal) |
| **Énumération LDAP** | Pas d'events sans SACLs objet. Signal : volume anormalement élevé de requêtes LDAP par compte |
| **Pass-the-Hash furtif** | Règle 100017 trop bruyante (faux positifs). Signal : NTLM inhabituel pour ce compte, heure ou IP anormale |

---

## 🏗️ Architecture du pipeline

```
Wazuh OpenSearch  →  Export JSON  →  Feature Engineering  →  Isolation Forest  →  Scores d'anomalie
(wazuh-alerts-*)      5000 alerts     par compte/24h           sklearn                rapport
```

### Features comportementales construites par compte

| Feature | Description | Attaque ciblée |
|---------|-------------|----------------|
| `nb_events` | Volume total d'activité | Énumération (pic) |
| `nb_custom` | Nb d'alertes custom Phase 5 | Corrélation règles |
| `nb_ntlm` | Nb de logons NTLM | Pass-the-Hash |
| `nb_type3` | Nb de logons réseau (type 3) | Mouvement latéral |
| `tgs_no_tgt` | TGS sans TGT précédent | **Golden Ticket** |
| `nb_night` | Events entre 22h et 6h | Comportement nocturne |
| `nb_ips` | Nb d'IPs sources distinctes | Spread latéral |
| `ntlm_ratio` | Ratio NTLM/(NTLM+Kerberos) | PtH vs auth normale |
| `nb_4662` | Accès Directory Service | Énumération LDAP |
| `rule_level_max` | Niveau d'alerte max atteint | Sévérité globale |

---

## ⚙️ Modèle — Isolation Forest

**Choix du modèle :** Isolation Forest (scikit-learn) — algorithme de détection d'anomalies **non supervisé**, idéal ici car :
- On n'a pas de labels "attaque/normal" propres sur les données réelles
- Il isole les points anormaux en construisant des arbres de décision aléatoires
- Les points rares (anomalies) sont isolés plus rapidement = score plus bas

**Paramètres :**
- `n_estimators=200` — 200 arbres pour une estimation robuste
- `contamination=0.15` — on suppose ~15% d'activité anormale dans le lab (réaliste vu nos simulations)
- `random_state=42` — reproductibilité

**Score de décision :** plus le score est bas (négatif), plus le compte est anormal.

---

## 📊 Résultats — 18 août 2026

**Données :** 5000 alertes Wazuh des dernières 24h, 23 comptes non-machine analysés.

### Anomalies détectées (4/23)

| Compte | Score | Events | Custom | NTLM | TGS_sans_TGT | Interprétation |
|--------|-------|--------|--------|------|--------------|----------------|
| **robb.stark** | -0.170 | 1461 | 56 | 0 | 0 | Bot RDP automatisé (`bot_rdp.ps1`) — volume anormal |
| **eddard.stark** | -0.086 | 114 | 17 | 17 | 0 | **Pass-the-Hash** — 17 logons NTLM inhabituels |
| **robb.stark@NORTH...** | -0.083 | 610 | 46 | 0 | 610 | **Golden Ticket** — 610 TGS sans TGT précédent ✅ |
| **sql_svc** | -0.022 | 20 | 7 | 3 | 0 | **MSSQL RCE** — alertes xp_cmdshell + logons suspects |

### Comptes normaux (extrait)

| Compte | Score | Events | Interprétation |
|--------|-------|--------|----------------|
| brandon.stark | +0.051 | 14 | Activité normale |
| cersei.lannister | +0.129 | 13 | Activité normale |
| arya.stark | +0.163 | 6 | Activité normale |

---

## 🔑 Résultat clé — Golden Ticket détecté

```
robb.stark@NORTH.SEVENKINGDOMS.LOCAL
  tgs_no_tgt = 610  ← 610 tickets TGS présentés sans AS-REQ (TGT) précédent
```

**C'est exactement la signature du Golden Ticket** : l'attaquant forge un TGT valide hors-ligne avec le hash krbtgt, le présente directement au KDC pour obtenir des TGS — aucune demande de TGT normale n'apparaît dans les logs. Cette anomalie est **indétectable par règle signature** mais ressort clairement dans l'Isolation Forest.

---

## 🛠️ Script

Fichier : [`simulation/phase6_anomaly_detection.py`](phase6_anomaly_detection.py)

```bash
# Export des alertes depuis OpenSearch
curl -k -u 'admin:<password>' "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=5000" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-24h"}}}}' \
  -o /tmp/wazuh_alerts.json

# Exécution
python3 phase6_anomaly_detection.py /tmp/wazuh_alerts.json
```

---

## 📊 Bilan Phase 6

| Attaque | Méthode | Résultat |
|---------|---------|----------|
| Golden Ticket | `tgs_no_tgt` feature | ✅ Détecté (610 TGS sans TGT) |
| Pass-the-Hash | `nb_ntlm` + alertes custom | ✅ Détecté (eddard.stark, 17 NTLM) |
| MSSQL RCE (confirmation) | `nb_custom` + `nb_type3` | ✅ Confirmé (sql_svc) |
| Comportement bot | Volume extrême | ✅ Détecté (robb.stark, 1461 events) |
| Énumération LDAP | `nb_4662` | ⚠️ Pas assez de données (SACLs non posées) |

**L'agent IA complète les règles de signature : les attaques cryptographiquement valides (Golden Ticket) sont maintenant détectées par comportement.**

---

⬅️ Retour aux [règles de détection (Phase 5)](04-detection-avancee.md)
