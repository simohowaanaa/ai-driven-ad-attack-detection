# Phase 2 — Lab Deployment (GOAD-Light on Azure)

This folder documents how the Active Directory lab was deployed. The lab uses GOAD-Light (Game of Active Directory by Orange Cyberdefense), an intentionally vulnerable AD environment designed for offensive and defensive security training.

## Lab Architecture

```
  Azure VM — Ubuntu 24.04 — Standard_E4s_v3 — 4 vCPU / 32 GB RAM
  +------------------------------------------------------------------+
  |                        VirtualBox                                 |
  |                                                                   |
  |  +-------------+    +-------------+    +---------------------+   |
  |  |    DC01     |    |    DC02     |    |       SRV02         |   |
  |  | kingslanding|    |  winterfell |    |    castelblack      |   |
  |  | 192.168.56.10    | 192.168.56.11   | 192.168.56.22       |   |
  |  | sevenkingdoms    | north.seven...  | MSSQL Server        |   |
  |  +------+------+    +------+------+    +---------+-----------+   |
  |         |  Wazuh agent    |  Wazuh agent         |  Wazuh agent  |
  |         +-----------------+----------------------+               |
  |                    +-------+-------+                             |
  |                    |  Wazuh SIEM   |  192.168.56.51             |
  |                    +---------------+                             |
  |              Host-only network — 192.168.56.0/24                |
  +------------------------------------------------------------------+
              SSH + tunnel from local workstation
```

## Machines

| Machine | Hostname | IP | Domain | Role |
|---------|----------|----|--------|------|
| DC01 | kingslanding | 192.168.56.10 | sevenkingdoms.local | Root domain controller, ADCS CA |
| DC02 | winterfell | 192.168.56.11 | north.sevenkingdoms.local | Child domain controller |
| SRV02 | castelblack | 192.168.56.22 | north.sevenkingdoms.local | Member server, SQL Server 2019 |
| Wazuh | wazuh | 192.168.56.51 | — | SIEM (indexer + manager + dashboard) |

The two domains are linked by a parent-child trust, enabling cross-domain attack simulation.

## Contents

| File | Description |
|------|-------------|
| `setup/01-azure-vm.md` | How to provision the Azure VM with nested virtualization |
| `setup/azure-goad-setup.sh` | Automated shell script to install all tools and deploy GOAD-Light |
| `screenshots/` | Screenshots of the deployed lab |

## Why Azure and not local

A local deployment was attempted first (Windows + Hyper-V + WSL2 + VirtualBox). It failed due to conflicts between hypervisor layers that caused WinRM (used by Ansible) to become unreliable. Moving to an Azure Linux VM with nested virtualization resolved all conflicts.
