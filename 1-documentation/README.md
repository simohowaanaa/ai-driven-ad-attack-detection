# Phase 1 — Active Directory Attack Reference

This folder contains the theoretical reference for 48 Active Directory attack techniques, organized by MITRE ATT&CK tactic. Each file documents one technique with its prerequisites, generated Windows Event IDs, detection logic, and remediation steps.

## Structure

| Folder | Tactic | Techniques |
|--------|--------|-----------|
| `reconnaissance/` | Initial discovery of AD objects and paths | 4 |
| `credential-access/` | Stealing or forging credentials | 12 |
| `lateral-movement/` | Moving between machines using stolen credentials | 5 |
| `privilege-escalation/` | Gaining higher privileges in the domain | 14 |
| `persistence/` | Maintaining access after initial compromise | 7 |
| `defense-evasion/` | Bypassing detection mechanisms | 4 |
| `domain-trusts/` | Abusing cross-domain and cross-forest trusts | 2 |

## How to read a technique file

Each file follows the same structure:

- **Description** — what the attack does and why it works
- **Prerequisites** — what the attacker needs to launch it
- **Simulation** — exact commands used in the GOAD-Light lab
- **Detection** — Windows Event IDs generated, Sigma rule
- **Remediation** — how to fix the configuration or limit exposure

## Relation to the project

These 48 files were written during Phase 1 of the project, before any lab work. They served as the knowledge base for selecting the 12 attacks simulated in Phase 4 and designing the detection rules in Phase 5.

The 12 attacks that were actually simulated are documented in detail in `4-attacks/playbooks/`.
