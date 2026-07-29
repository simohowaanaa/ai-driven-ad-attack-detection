# 🗺️ Mapping MITRE ATT&CK — les 12 attaques simulées

> Vue consolidée des techniques MITRE couvertes par la Phase 4, organisée par tactique. Sert de référence rapide pour le rapport et la soutenance.

---

| Tactique MITRE | Technique | Attaque | Statut détection |
|---|---|---|:---:|
| **Reconnaissance / Discovery** | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | [03 — Énumération](attaques/03-enumeration.md) | 🔴 |
| **Credential Access** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | [01 — Kerberoasting](attaques/01-kerberoasting.md) | 🟡 |
| **Credential Access** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | [02 — AS-REP Roasting](attaques/02-asrep-roasting.md) | 🔴 |
| **Credential Access** | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | [04 — LLMNR Poisoning](attaques/04-llmnr-poisoning.md) | 🔴 |
| **Credential Access** | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | [05 — Password Spraying](attaques/05-password-spraying.md) | 🟢 |
| **Credential Access** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | [06 — DCSync](attaques/06-dcsync.md) | 🔴 |
| **Privilege Escalation** | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) | [07 — Abus d'ACL](attaques/07-acl-abuse.md) | 🟢 |
| **Privilege Escalation** | [T1649](https://attack.mitre.org/techniques/T1649/) | [08 — ADCS ESC1](attaques/08-adcs-esc1.md) | 🔴 |
| **Lateral Movement** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | [09 — Pass-the-Hash](attaques/09-pass-the-hash.md) | 🟡 |
| **Lateral Movement / Execution** | [T1210](https://attack.mitre.org/techniques/T1210/) | [10 — MSSQL RCE](attaques/10-mssql-rce.md) | 🔴 |
| **Persistence** | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | [11 — Golden Ticket](attaques/11-golden-ticket.md) | 🟡 |
| **Domain Trusts** | [T1482](https://attack.mitre.org/techniques/T1482/) | [12 — Abus de trust](attaques/12-trust-inter-domaine.md) | 🟡 |

---

## 📈 Répartition par tactique

```
Credential Access    ████████████ 5 attaques  (01, 02, 04, 05, 06)
Privilege Escalation ████████     2 attaques  (07, 08)
Lateral Movement     ████████     2 attaques  (09, 10)
Persistence          ████         1 attaque   (11)
Domain Trusts         ████         1 attaque   (12)
Reconnaissance        ████         1 attaque   (03)
```

La **Credential Access** domine (logique : c'est le point d'entrée de toute intrusion AD), mais la couverture s'étend jusqu'à la **compromission de forêt** (Domain Trusts, Privilege Escalation), donnant une kill chain complète de bout en bout.

---

⬅️ Retour à la [simulation des attaques](03-attaques.md)
