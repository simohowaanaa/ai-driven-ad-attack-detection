# Phase 3 — SIEM Wazuh Configuration

This folder documents the Wazuh SIEM installation and configuration. Wazuh was deployed on a dedicated VM in the lab and connected to all three Windows machines via agents.

## Wazuh Architecture

Wazuh is composed of three components deployed on the same server (192.168.56.51):

| Component | Role |
|-----------|------|
| Wazuh Indexer | Stores and indexes all alerts (based on OpenSearch) |
| Wazuh Manager | Receives logs from agents, applies detection rules |
| Wazuh Dashboard | Web interface for alert visualization and threat hunting |

Three agents were installed on the Windows machines:

| Agent | Machine | IP |
|-------|---------|-----|
| Agent 1 | kingslanding (DC01) | 192.168.56.10 |
| Agent 2 | winterfell (DC02) | 192.168.56.11 |
| Agent 3 | castelblack (SRV02) | 192.168.56.22 |

Each agent forwards Windows Event Logs to the Wazuh Manager in real time.

## Contents

| File | Description |
|------|-------------|
| `setup/01-wazuh-server.md` | How to install Wazuh indexer, manager and dashboard |
| `setup/02-agents-windows.md` | How to deploy and register agents on the Windows VMs |
| `setup/03-audit-policies.md` | How to enable missing Windows audit categories via GPO |
| `config/start-wazuh.sh` | Script to start all Wazuh services |
| `screenshots/` | Screenshots of the dashboard and active agents |

## Default detection limits

Wazuh installed with default settings detected only 2 out of 12 simulated attacks. The main reasons:

1. **Missing audit categories** — Windows does not log Kerberos, ADCS, process creation, or DS Access events by default. If Windows does not write the log, Wazuh has nothing to read.
2. **No targeted rules** — Even when logs exist, rules must be written to identify malicious patterns.

Audit policies were enabled in Phase 3 and custom rules were written in Phase 5.

## Audit categories enabled (via GPO)

| Audit Category | Event Generated | Attack Covered |
|----------------|----------------|----------------|
| Directory Service Access | 4662 | DCSync |
| Kerberos Authentication Service | 4768 | AS-REP Roasting |
| Kerberos Service Ticket Operations | 4769 | Kerberoasting |
| Certification Services | 4886 / 4887 | ADCS ESC1 |
| Process Creation (with command line) | 4688 | MSSQL RCE |
