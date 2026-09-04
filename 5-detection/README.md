# Phase 5 — Custom Wazuh Detection Rules

This folder contains the 7 custom Wazuh rules written to cover the attacks that were invisible in Phase 4. All rules were validated in live conditions by replaying the corresponding attacks after deployment.

## What changed between Phase 4 and Phase 5

**Before (Phase 4):** Wazuh default configuration detected 2 attacks out of 12.

**After (Phase 5):** 9 attacks out of 12 are now detected.

Two improvements were made:
1. Missing Windows audit categories were enabled on both domain controllers via Group Policy (GPO).
2. Seven custom rules were written and deployed in `/var/ossec/etc/rules/local_rules.xml`.

## The 7 Rules

| Rule ID | Attack | Event ID | Live Result |
|:-------:|--------|:--------:|------------|
| 100010 | DCSync | 4662 | 3 hits — tywin.lannister identified |
| 100011 | Kerberoasting | 4769 + RC4 (0x17) | 3 hits — RC4 burst detected |
| 100012 | ADCS ESC1 | 4887 | 2 hits — Administrator certificate captured |
| 100013 | MSSQL RCE via xp_cmdshell | 4688 | 7 hits — cmd.exe spawned by sqlservr.exe |
| 100014 | AS-REP Roasting | 4768 + preAuthType=0 | 1 hit — account without pre-authentication |
| 100017 | Pass-the-Hash | 4624 + NTLM + Type 3 | 5 hits — NTLM network logon |
| 100019 | Cross-Domain Trust Abuse | 4624 cross-domain | 18 hits — NORTH to SEVENKINGDOMS |

## Contents

| File | Description |
|------|-------------|
| `rules/local_rules.xml` | The 7 rules ready to deploy on a Wazuh manager |
| `rules/rules-explained.md` | Each rule explained line by line |
| `screenshots/` | Wazuh dashboard screenshots showing live detections |

## How to deploy the rules

Copy `rules/local_rules.xml` to the Wazuh manager:

```bash
scp rules/local_rules.xml wazuh-manager:/var/ossec/etc/rules/local_rules.xml
systemctl restart wazuh-manager
```

## Remaining blind spots after Phase 5

Three attacks remain partially or fully undetected by rules:

| Attack | Reason |
|--------|--------|
| LDAP Enumeration | Uses legitimate AD queries — no signature to detect |
| LLMNR Poisoning | Network-layer attack — no Windows Event Log generated |
| Golden Ticket | Ticket is cryptographically valid — indistinguishable from legitimate |

Golden Ticket detection is handled by the AI agent in Phase 6.
