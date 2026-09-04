# Phase 6 — AI Anomaly Detection Agent (Isolation Forest)

This folder contains the AI-based detection agent built to cover the attacks that cannot be detected by signature rules — primarily the Golden Ticket, which produces a cryptographically valid Kerberos ticket indistinguishable from a legitimate one.

## Why rules are not enough

Signature-based rules work by matching known patterns in events. They fail when:
- The attack uses legitimate Windows mechanisms (Golden Ticket, LDAP enumeration)
- The attacker's activity is technically valid (correct Kerberos ticket, valid certificate)
- The attack is new and has no known signature

The solution is behavioral analysis: instead of looking for a fixed signature, we ask whether an account's behavior is abnormal compared to all other accounts.

## How the agent works

The agent runs as a Python script on exported Wazuh alerts (JSON from OpenSearch API).

```
Wazuh OpenSearch  -->  Export JSON  -->  Feature Engineering  -->  Isolation Forest  -->  Anomaly Report
    (alerts)         (24h window)      (10 features / account)     (unsupervised)       (ranked accounts)
```

### Algorithm: Isolation Forest

Isolation Forest is an unsupervised machine learning algorithm. It does not need labeled examples of attacks. Instead, it builds random decision trees and measures how many splits are needed to isolate each data point. Anomalous accounts are isolated in fewer steps — they have extreme values on at least one feature.

Score interpretation: the lower (more negative) the score, the more anomalous the account.

### Features computed per account (24h window)

| Feature | Description | Attack targeted |
|---------|-------------|----------------|
| `nb_events` | Total event count | General anomalous volume |
| `nb_ntlm_logons` | NTLM logon count | Pass-the-Hash |
| `nb_kerb_logons` | Kerberos logon count | Baseline |
| `nb_logon_type3` | Network logon count (Type 3) | Pass-the-Hash, lateral movement |
| `nb_failed_4625` | Failed logon count | Password spraying, brute force |
| `nb_4769` | TGS ticket request count | Kerberoasting |
| `nb_4769_rc4` | RC4 TGS requests | Kerberoasting |
| `nb_4662` | DS replication operation count | DCSync |
| `nb_night_events` | Events between 22:00 and 06:00 | Off-hours attacks |
| `tgs_without_tgt` | TGS count minus TGT count (min 0) | **Golden Ticket** |

The `tgs_without_tgt` feature is the key behavioral indicator for Golden Ticket detection. In normal Kerberos flow, a client must first obtain a TGT (AS-REQ / AS-REP) before requesting any TGS. A forged Golden Ticket is presented directly to the KDC without any prior TGT request — so this counter will be high while the TGT count is zero.

## Results (23 accounts analyzed — 18 August 2026)

| Rank | Account | Score | Feature triggered | Interpretation |
|:----:|---------|:-----:|-------------------|----------------|
| 1 | robb.stark | -0.170 | nb_events = 1461 | Automated RDP bot — high volume |
| 2 | eddard.stark | -0.086 | nb_ntlm_logons = 17 | Pass-the-Hash |
| 3 | robb.stark@NORTH | -0.083 | tgs_without_tgt = 610 | **Golden Ticket** |
| 4 | sql_svc | -0.022 | xp_cmdshell alerts | MSSQL RCE |

Account `robb.stark@NORTH` made 610 TGS requests without a single prior TGT request. This is physically impossible in legitimate Kerberos and is the exact behavioral signature of a Golden Ticket used in the environment.

## How to run

```bash
# Install dependencies
pip install -r requirements.txt

# Export Wazuh alerts from OpenSearch to JSON
# (query the last 24h of alerts via the Wazuh API or dashboard export)

# Run the agent
python anomaly_detection.py /path/to/wazuh_alerts.json
```

## Contents

| File | Description |
|------|-------------|
| `anomaly_detection.py` | Main script — load, feature engineering, Isolation Forest, report |
| `requirements.txt` | Python dependencies |
| `data/sample_alerts.json` | Sample Wazuh export for testing the script |
| `results/phase6-results.csv` | Full results from the 18 August 2026 run |
| `screenshots/` | Score distribution and Golden Ticket detection screenshot |

## Configuration

| Parameter | Value | Effect |
|-----------|-------|--------|
| `contamination` | 0.15 | Expected fraction of anomalies (15%) |
| `n_estimators` | 200 | Number of trees — higher = more stable results |
| `random_state` | 42 | Reproducible results |
