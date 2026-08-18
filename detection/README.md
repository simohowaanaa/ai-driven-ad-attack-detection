# Detection — Règles custom & Agent IA

> **Phases 5 et 6 du PFA** — après avoir identifié les angles morts en Phase 4, cette partie les comble : règles de détection Wazuh sur-mesure, puis agent IA pour les attaques sans signature fixe.

---

## Contenu

| Fichier | Phase | Description |
|---------|:-----:|-------------|
| [`01-regles-wazuh.md`](01-regles-wazuh.md) | **5** | Activation des audits Windows + 7 règles Wazuh custom validées en live (DCSync, Kerberoasting, ADCS ESC1, MSSQL RCE, AS-REP Roasting, Pass-the-Hash, Trust Abuse) |
| [`02-agent-ia.md`](02-agent-ia.md) | **6** | Pipeline Isolation Forest : feature engineering comportemental → détection anomalies (Golden Ticket, PtH furtif) |
| [`anomaly_detection.py`](anomaly_detection.py) | **6** | Script Python — export OpenSearch → features → Isolation Forest → rapport |

---

## Résumé Phase 5 — 7 règles Wazuh

| ID | Attaque | Event | Résultat |
|----|---------|-------|----------|
| 100010 | DCSync | 4662 | ✅ 3 hits live (tywin.lannister) |
| 100011 | Kerberoasting | 4769 + RC4 0x17 | ✅ 3 hits live |
| 100012 | ADCS ESC1 | 4887 | ✅ 2 hits live (cert admin émis) |
| 100013 | MSSQL RCE | 4688 (parent sqlservr) | ✅ 7 hits live (xp_cmdshell) |
| 100014 | AS-REP Roasting | 4768 + preAuthType=0 | ✅ 1 hit live |
| 100017 | Pass-the-Hash | 4624 + NTLM type 3 | ✅ 5 hits live |
| 100019 | Trust Abuse | NTLM NORTH→SEVENKINGDOMS | ✅ 18 hits live |

## Résumé Phase 6 — Isolation Forest

```
23 comptes analysés · 4 anomalies détectées
```

| Compte | Score | Anomalie |
|--------|-------|----------|
| robb.stark | -0.170 | Bot RDP (1461 events) |
| eddard.stark | -0.086 | Pass-the-Hash (17 logons NTLM) |
| robb.stark@NORTH… | -0.083 | **Golden Ticket** (610 TGS sans TGT) |
| sql_svc | -0.022 | MSSQL RCE (alertes xp_cmdshell) |

## Utilisation du script

```bash
# 1. Export des alertes (sur le Wazuh manager)
curl -k -u 'admin:<password>' \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=5000" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-24h"}}}}' \
  -o /tmp/wazuh_alerts.json

# 2. Lancer l'agent
python3 anomaly_detection.py /tmp/wazuh_alerts.json
```

**Dépendances :** `pip install scikit-learn pandas numpy`
