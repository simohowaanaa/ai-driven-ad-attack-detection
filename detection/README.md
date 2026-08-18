# 🤖 Agent IA — Détection d'anomalies Active Directory

> **Phase 6 du PFA** — détection comportementale des attaques que les règles de signature ne peuvent pas capturer.

## Contenu

| Fichier | Description |
|---------|-------------|
| [`phase6_anomaly_detection.py`](phase6_anomaly_detection.py) | Pipeline complet : export OpenSearch → feature engineering → Isolation Forest → rapport |

## Utilisation

```bash
# 1. Exporter les alertes Wazuh depuis OpenSearch (sur le Wazuh manager)
curl -k -u 'admin:<password>' "https://127.0.0.1:9200/wazuh-alerts-*/_search?size=5000" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-24h"}}}}' \
  -o /tmp/wazuh_alerts.json

# 2. Lancer l'agent
python3 phase6_anomaly_detection.py /tmp/wazuh_alerts.json
```

## Méthodologie

Pipeline non supervisé (Isolation Forest, scikit-learn) :

1. **Chargement** — parsing des alertes JSON depuis OpenSearch
2. **Feature engineering** — 10 features comportementales par compte (volume, NTLM, `tgs_without_tgt`, ratio, heures nocturnes…)
3. **Modèle** — `IsolationForest(n_estimators=200, contamination=0.15)`
4. **Rapport** — scores d'anomalie + interprétation par compte

La feature clé est `tgs_without_tgt = max(TGS_count - TGT_count, 0)` : signature comportementale du **Golden Ticket** (tickets forgés hors-ligne, présentés sans AS-REQ normal).

## Résultats (18 août 2026)

| Compte | Score | Interprétation |
|--------|-------|----------------|
| robb.stark | -0.170 | Bot RDP automatisé (1461 events) |
| eddard.stark | -0.086 | **Pass-the-Hash** (17 logons NTLM) |
| robb.stark@NORTH… | -0.083 | **Golden Ticket** (610 TGS sans TGT) |
| sql_svc | -0.022 | **MSSQL RCE** (alertes xp_cmdshell) |

Documentation complète : [`simulation/05-agent-ia.md`](../simulation/05-agent-ia.md)
