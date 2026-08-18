"""
Phase 6 — Agent IA de détection d'anomalies AD
Isolation Forest sur les alertes Wazuh exportées depuis OpenSearch
"""

import json
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime

# ─── 1. CHARGEMENT DES ALERTES ───────────────────────────────────────────────

def load_alerts(filepath):
    with open(filepath, "r") as f:
        raw = json.load(f)
    hits = raw.get("hits", {}).get("hits", [])
    records = []
    for h in hits:
        src = h.get("_source", {})
        win = src.get("data", {}).get("win", {})
        evtdata = win.get("eventdata", {})
        system  = win.get("system", {})
        rule    = src.get("rule", {})
        ts_str  = src.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            ts = None
        records.append({
            "timestamp":        ts,
            "hour":             ts.hour if ts else -1,
            "agent_name":       src.get("agent", {}).get("name", ""),
            "rule_id":          str(rule.get("id", "")),
            "rule_level":       int(rule.get("level", 0)),
            "event_id":         system.get("eventID", ""),
            "user":             evtdata.get("targetUserName") or evtdata.get("subjectUserName") or "",
            "domain":           evtdata.get("targetDomainName") or evtdata.get("subjectDomainName") or "",
            "logon_type":       evtdata.get("logonType", ""),
            "auth_package":     evtdata.get("authenticationPackageName", ""),
            "src_ip":           evtdata.get("ipAddress", ""),
            "process_name":     evtdata.get("newProcessName", ""),
            "parent_process":   evtdata.get("parentProcessName", ""),
        })
    return pd.DataFrame(records)

# ─── 2. FEATURE ENGINEERING PAR UTILISATEUR ──────────────────────────────────

def build_features(df):
    df = df[df["user"].str.len() > 0].copy()
    df = df[~df["user"].str.endswith("$")]   # exclut les comptes machine

    g = df.groupby("user")

    features = pd.DataFrame({
        # Volume d'activité
        "nb_events":          g.size(),
        "nb_rule_levels_max": g["rule_level"].max(),
        "nb_distinct_agents": g["agent_name"].nunique(),
        "nb_distinct_ips":    g["src_ip"].nunique(),

        # Logons
        "nb_logon_4624":      g.apply(lambda x: (x["event_id"] == "4624").sum()),
        "nb_failed_4625":     g.apply(lambda x: (x["event_id"] == "4625").sum()),
        "nb_ntlm_logons":     g.apply(lambda x: (x["auth_package"] == "NTLM").sum()),
        "nb_kerb_logons":     g.apply(lambda x: (x["auth_package"] == "Kerberos").sum()),
        "nb_logon_type3":     g.apply(lambda x: (x["logon_type"] == "3").sum()),

        # Kerberos
        "nb_4768":            g.apply(lambda x: (x["event_id"] == "4768").sum()),
        "nb_4769":            g.apply(lambda x: (x["event_id"] == "4769").sum()),
        "nb_4769_rc4":        g.apply(lambda x: (
            (x["event_id"] == "4769") & (x["rule_id"] == "100011")
        ).sum()),

        # Directory / ADCS / MSSQL
        "nb_4662":            g.apply(lambda x: (x["event_id"] == "4662").sum()),
        "nb_4688":            g.apply(lambda x: (x["event_id"] == "4688").sum()),
        "nb_4887":            g.apply(lambda x: (x["event_id"] == "4887").sum()),

        # Alertes custom
        "nb_custom_alerts":   g.apply(lambda x: x["rule_id"].str.startswith("1000").sum()),

        # Temporel
        "mean_hour":          g["hour"].mean(),
        "std_hour":           g["hour"].std().fillna(0),
        "nb_night_events":    g.apply(lambda x: ((x["hour"] >= 22) | (x["hour"] <= 6)).sum()),

        # Ratio NTLM vs Kerberos
        "ntlm_ratio":         g.apply(lambda x: (
            (x["auth_package"] == "NTLM").sum() /
            max((x["auth_package"].isin(["NTLM","Kerberos"])).sum(), 1)
        )),

        # Ratio TGS sans TGT (signature Golden Ticket)
        "tgs_without_tgt":    g.apply(lambda x: max(
            (x["event_id"] == "4769").sum() - (x["event_id"] == "4768").sum(), 0
        )),
    })

    return features.fillna(0)

# ─── 3. ISOLATION FOREST ─────────────────────────────────────────────────────

def run_isolation_forest(features, contamination=0.1):
    scaler = StandardScaler()
    X = scaler.fit_transform(features)
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42
    )
    model.fit(X)
    scores = model.decision_function(X)   # plus bas = plus anormal
    labels = model.predict(X)             # -1 = anomalie, 1 = normal
    return scores, labels

# ─── 4. RAPPORT ──────────────────────────────────────────────────────────────

def print_report(features, scores, labels):
    results = features.copy()
    results["anomaly_score"] = scores
    results["is_anomaly"]    = labels == -1
    results = results.sort_values("anomaly_score")

    print("\n" + "="*70)
    print("PHASE 6 — RAPPORT DE DÉTECTION D'ANOMALIES AD")
    print("="*70)
    print(f"\nComptes analysés : {len(results)}")
    print(f"Anomalies détectées : {results['is_anomaly'].sum()}")
    print("\n─── TOP 10 COMPTES LES PLUS SUSPECTS ───────────────────────────────")

    top = results.head(10)
    for user, row in top.iterrows():
        flag = "🔴 ANOMALIE" if row["is_anomaly"] else "🟡 SUSPECT"
        print(f"\n{flag} | {user}")
        print(f"  Score anomalie    : {row['anomaly_score']:.4f}  (plus bas = plus suspect)")
        print(f"  Events totaux     : {int(row['nb_events'])}")
        print(f"  Alertes custom    : {int(row['nb_custom_alerts'])}")
        print(f"  Logons NTLM       : {int(row['nb_ntlm_logons'])}  |  Kerberos : {int(row['nb_kerb_logons'])}")
        print(f"  Logon type 3      : {int(row['nb_logon_type3'])}")
        print(f"  TGS sans TGT      : {int(row['tgs_without_tgt'])}  ← signature Golden Ticket")
        print(f"  Events nocturnes  : {int(row['nb_night_events'])}  (22h-6h)")
        print(f"  IPs distinctes    : {int(row['nb_distinct_ips'])}")
        print(f"  Agents distincts  : {int(row['nb_distinct_agents'])}")

    print("\n─── COMPTES NORMAUX (extrait) ───────────────────────────────────────")
    normal = results[~results["is_anomaly"]].tail(5)
    for user, row in normal.iterrows():
        print(f"  ✅ {user:30s}  score={row['anomaly_score']:.4f}  events={int(row['nb_events'])}")

    print("\n" + "="*70)

    # Sauvegarde CSV
    results.to_csv("/tmp/phase6_resultats.csv")
    print("Résultats complets sauvegardés dans /tmp/phase6_resultats.csv")
    print("="*70 + "\n")

# ─── MAIN ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "/tmp/wazuh_alerts.json"
    print(f"Chargement des alertes depuis {filepath}...")
    df = load_alerts(filepath)
    print(f"  {len(df)} events chargés, {df['user'].nunique()} utilisateurs uniques")

    print("Construction des features comportementales...")
    features = build_features(df)
    print(f"  {len(features)} comptes non-machine avec activité")

    print("Entraînement Isolation Forest...")
    scores, labels = run_isolation_forest(features, contamination=0.15)

    print_report(features, scores, labels)
