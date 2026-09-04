# Phase 4 — Attack Simulation Results

This folder contains the playbooks for all 12 Active Directory attacks simulated in the GOAD-Light lab. Each playbook documents the attack technique, the exact commands used, the result, and what Wazuh detected (or missed) before and after custom rules were applied.

## Detection Coverage

| # | Attack | MITRE | Default Wazuh | After Rules (Phase 5) | AI Agent (Phase 6) |
|:-:|--------|-------|:-------------:|:---------------------:|:------------------:|
| 01 | Kerberoasting | T1558.003 | Partial | Detected (rule 100011) | — |
| 02 | AS-REP Roasting | T1558.004 | Blind | Detected (rule 100014) | — |
| 03 | LDAP Enumeration | T1087 | Blind | Blind (structural) | — |
| 04 | LLMNR Poisoning | T1557.001 | Blind | Blind (structural) | — |
| 05 | Password Spraying | T1110.003 | Detected | Detected | — |
| 06 | DCSync | T1003.006 | Blind | Detected (rule 100010) | — |
| 07 | ACL Abuse | T1222 | Detected | Detected | — |
| 08 | ADCS ESC1 | T1649 | Blind | Detected (rule 100012) | — |
| 09 | Pass-the-Hash | T1550.002 | Partial | Detected (rule 100017) | — |
| 10 | MSSQL RCE | T1210 | Blind | Detected (rule 100013) | — |
| 11 | Golden Ticket | T1558.001 | Partial | Blind (no signature) | Detected |
| 12 | Cross-Domain Trust Abuse | T1482 | Partial | Detected (rule 100019) | — |

**Default Wazuh score: 2/12**
**After Phase 5 rules: 9/12**
**After Phase 6 AI agent: covers Golden Ticket**

## Status definitions

| Status | Meaning |
|--------|---------|
| Detected | Wazuh raised an alert automatically |
| Partial | Relevant events visible in logs but no alert triggered |
| Blind | No logs generated at all — audit category missing |
| Blind (structural) | Attack happens at network level, no Windows Event Log exists |

## Contents

| File / Folder | Description |
|---------------|-------------|
| `playbooks/01-kerberoasting.md` to `12-trust-inter-domain.md` | One file per attack: technique, commands, result, Wazuh output |
| `mitre-mapping.md` | All 12 attacks mapped on the MITRE ATT&CK matrix |
| `detection-coverage.md` | Full detection analysis: what Wazuh sees and what it misses |
| `glossary.md` | Definitions: Kerberos, TGT, TGS, NTLM, DCSync, SPN... |
| `screenshots/` | Screenshots of each attack and corresponding Wazuh view |

## Tools used

| Tool | Source | Used for |
|------|--------|---------|
| impacket (GetUserSPNs, secretsdump, ticketer) | github.com/fortra/impacket | Kerberoasting, DCSync, Golden Ticket |
| Certipy | github.com/ly4k/Certipy | ADCS ESC1 |
| bloodhound-python | github.com/fox-it/BloodHound.py | LDAP Enumeration |
| evil-winrm | github.com/Hackplayers/evil-winrm | Pass-the-Hash |
| kerbrute | github.com/ropnop/kerbrute | Password Spraying |
| Responder | github.com/lgandx/Responder | LLMNR Poisoning |
