# Active Directory Attack Detection — Wazuh + Isolation Forest

**Internship project — Dataprotect SOC — Juillet–Août 2026**

![Phase 1](https://img.shields.io/badge/Phase%201%20Documentation-done-22c55e?style=flat-square)
![Phase 2](https://img.shields.io/badge/Phase%202%20Lab-done-22c55e?style=flat-square)
![Phase 3](https://img.shields.io/badge/Phase%203%20Wazuh-done-22c55e?style=flat-square)
![Phase 4](https://img.shields.io/badge/Phase%204%20Simulation-done-22c55e?style=flat-square)
![Phase 5](https://img.shields.io/badge/Phase%205%20Rules-done-22c55e?style=flat-square)
![Phase 6](https://img.shields.io/badge/Phase%206%20AI%20Agent-done-22c55e?style=flat-square)

---

## What this project does

This project builds a complete Active Directory attack detection pipeline — from theoretical documentation to a live AI anomaly detection agent — covering all steps in between: a vulnerable AD lab, a SIEM with custom rules, and 12 real attacks simulated end to end.

The central question: **how far can Wazuh detect AD attacks out of the box, and how do we cover the blind spots?**

The answer comes in two layers:
- **Custom Wazuh rules** (Phase 5) — for attacks that have a known signature in Windows Event Logs
- **Isolation Forest AI agent** (Phase 6) — for attacks that are cryptographically valid and leave no detectable signature (Golden Ticket)

**Authors:** Maimouni Mohammed & Chafak Othmane
**Supervisor (Dataprotect):** Benkirane Abbes
**Academic supervisor (EMSI):** Bakkaliyedri Othman

---

## Repository structure

```
ai-driven-ad-attack-detection/
|
+-- 1-documentation/     Phase 1 — 48 AD attack technique files (MITRE ATT&CK)
+-- 2-lab/               Phase 2 — GOAD-Light lab deployment on Azure
+-- 3-siem/              Phase 3 — Wazuh SIEM installation and configuration
+-- 4-attacks/           Phase 4 — 12 attack playbooks + detection results
+-- 5-detection/         Phase 5 — 7 custom Wazuh rules (XML + documentation)
+-- 6-ai-agent/          Phase 6 — Isolation Forest anomaly detection agent
+-- reports/             Official internship reports
```

Each folder has its own README explaining what it contains and how to use it.

---

## Lab overview

The lab is a deliberately vulnerable Active Directory environment (GOAD-Light by Orange Cyberdefense), deployed on a Linux Azure VM with nested virtualization.

| Machine | IP | Role | Domain |
|---------|----|------|--------|
| kingslanding (DC01) | 192.168.56.10 | Root domain controller, ADCS CA | sevenkingdoms.local |
| winterfell (DC02) | 192.168.56.11 | Child domain controller | north.sevenkingdoms.local |
| castelblack (SRV02) | 192.168.56.22 | Member server, SQL Server 2019 | north.sevenkingdoms.local |
| Wazuh | 192.168.56.51 | SIEM — indexer, manager, dashboard | — |

The two domains are linked by a parent-child trust to enable cross-domain attack simulation.

---

## Phase 1 — Attack documentation

48 technique files covering the main Active Directory attack categories, organized by MITRE ATT&CK tactic. Each file contains the attack description, prerequisites, Windows Event IDs generated, a Sigma detection rule, and remediation steps.

| Tactic | Techniques |
|--------|-----------|
| Reconnaissance | 4 |
| Credential Access | 12 |
| Lateral Movement | 5 |
| Privilege Escalation | 14 |
| Persistence | 7 |
| Defense Evasion | 4 |
| Domain Trusts | 2 |

See [1-documentation/README.md](1-documentation/README.md)

---

## Phase 2 — Lab deployment

GOAD-Light deployed on Azure (Ubuntu 24.04 — Standard_E4s_v3 — 4 vCPU / 32 GB RAM) using VirtualBox, Vagrant, and Ansible. Nested virtualization was required to run VirtualBox inside the Azure Linux VM.

See [2-lab/README.md](2-lab/README.md) — [Setup guide](2-lab/setup/01-azure-vm.md) — [Automated script](2-lab/setup/azure-goad-setup.sh)

---

## Phase 3 — Wazuh SIEM

Wazuh deployed on a fourth VM (192.168.56.51) with agents on all three Windows machines. Missing Windows audit categories were enabled via Group Policy on both domain controllers.

See [3-siem/README.md](3-siem/README.md)

---

## Phase 4 — Attack simulation

12 attacks replayed in live conditions. Each attack is documented with the exact commands, the result obtained, and what Wazuh saw (or did not see).

| # | Attack | MITRE | Default Wazuh | After Phase 5 | Phase 6 AI |
|:-:|--------|-------|:-------------:|:-------------:|:----------:|
| 01 | Kerberoasting | T1558.003 | Partial | Detected | — |
| 02 | AS-REP Roasting | T1558.004 | Blind | Detected | — |
| 03 | LDAP Enumeration | T1087 | Blind | Blind | — |
| 04 | LLMNR Poisoning | T1557.001 | Blind | Blind | — |
| 05 | Password Spraying | T1110.003 | Detected | Detected | — |
| 06 | DCSync | T1003.006 | Blind | Detected | — |
| 07 | ACL Abuse | T1222 | Detected | Detected | — |
| 08 | ADCS ESC1 | T1649 | Blind | Detected | — |
| 09 | Pass-the-Hash | T1550.002 | Partial | Detected | — |
| 10 | MSSQL RCE | T1210 | Blind | Detected | — |
| 11 | Golden Ticket | T1558.001 | Partial | Blind | Detected |
| 12 | Trust Abuse | T1482 | Partial | Detected | — |

Default score: 2/12 — After Phase 5: 9/12 — After Phase 6: Golden Ticket covered

See [4-attacks/README.md](4-attacks/README.md)

---

## Phase 5 — Custom Wazuh rules

7 rules written in XML and deployed in `/var/ossec/etc/rules/local_rules.xml`. All validated by replaying the attacks after deployment.

| Rule | Attack | Event | Live result |
|:----:|--------|:-----:|------------|
| 100010 | DCSync | 4662 | 3 hits — tywin.lannister |
| 100011 | Kerberoasting | 4769 + RC4 | 3 hits — RC4 burst |
| 100012 | ADCS ESC1 | 4887 | 2 hits — Administrator certificate |
| 100013 | MSSQL RCE | 4688 | 7 hits — cmd.exe from sqlservr.exe |
| 100014 | AS-REP Roasting | 4768 | 1 hit — no pre-authentication |
| 100017 | Pass-the-Hash | 4624 + NTLM | 5 hits — NTLM network logon |
| 100019 | Trust Abuse | 4624 cross-domain | 18 hits — NORTH to SEVENKINGDOMS |

See [5-detection/README.md](5-detection/README.md) — [Rules XML](5-detection/rules/local_rules.xml)

---

## Phase 6 — AI anomaly detection agent

An Isolation Forest model runs on 24h of Wazuh alerts exported from OpenSearch. It computes 10 behavioral features per account and ranks them by anomaly score.

The key feature is `tgs_without_tgt`: the number of TGS tickets requested without a prior TGT request. In legitimate Kerberos, a client always obtains a TGT first. A Golden Ticket is forged offline and presented directly — so this counter will be high with no TGT in the logs. This is undetectable by any signature rule.

Results (23 accounts — 18 August 2026):

| Account | Score | Signal | Interpretation |
|---------|:-----:|--------|----------------|
| robb.stark | -0.170 | 1461 events | Automated RDP bot |
| eddard.stark | -0.086 | 17 NTLM logons | Pass-the-Hash |
| robb.stark@NORTH | -0.083 | 610 TGS, 0 TGT | **Golden Ticket** |
| sql_svc | -0.022 | xp_cmdshell alerts | MSSQL RCE |

See [6-ai-agent/README.md](6-ai-agent/README.md) — [Python script](6-ai-agent/anomaly_detection.py)

---

## Stack

| Layer | Technology |
|-------|-----------|
| Vulnerable AD lab | GOAD-Light (Orange Cyberdefense) — VirtualBox, Vagrant, Ansible |
| Cloud infrastructure | Microsoft Azure — Linux VM with nested virtualization |
| SIEM | Wazuh — indexer (OpenSearch), manager, dashboard, Windows agents |
| Offensive tools | impacket, Certipy, bloodhound-python, evil-winrm, kerbrute, Responder |
| AI agent | Python 3 — scikit-learn, pandas, numpy |
| Reference framework | MITRE ATT&CK Enterprise |

---

## Ethical framework

All attacks were performed exclusively in an isolated, intentionally vulnerable environment (GOAD-Light) for defensive research and educational purposes. None of these techniques should be used on a real system without explicit written authorization.
