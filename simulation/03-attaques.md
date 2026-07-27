# ⚔️ Phase 4 — Simulation des attaques & détection Wazuh

> **But :** rejouer les attaques documentées dans [`../docs/`](../docs/) sur le lab GOAD, puis **vérifier dans Wazuh** (Phase 3) qu'elles laissent une trace détectable. La démonstration centrale du PFA : **attaque → trace → détection.**

> **Méthode :** les outils (impacket, netexec) sont installés **directement sur l'hôte Azure** (qui voit le réseau du lab `192.168.56.0/24`) — pas besoin d'une VM Kali séparée.

---

## 📁 Organisation
Chaque attaque a **sa propre fiche** dans [`attaques/`](attaques/), au format standard défini par [`attaques/00-TEMPLATE.md`](attaques/00-TEMPLATE.md), avec les **captures intégrées** (exécution + détection).

---

## 🗺️ Roadmap des attaques (faisables dans GOAD-Light)

Ordre logique d'une intrusion (kill chain), par catégorie :

| # | Attaque | Catégorie | MITRE | Fiche | Statut | Détection Wazuh |
|---|---------|-----------|-------|-------|:------:|-----------------|
| 01 | Kerberoasting | Credential Access | T1558.003 | [01](attaques/01-kerberoasting.md) | ✅ | ✅ (rule 92652) |
| 02 | AS-REP Roasting | Credential Access | T1558.004 | [02](attaques/02-asrep-roasting.md) | ✅ | ⚠️ angle mort (4768 non audité) |
| 03 | Énumération (SMB/LDAP, users) | Recon | T1087 | *à venir* | ⬜ | — |
| 04 | LLMNR/NBT-NS Poisoning | Credential Access | T1557.001 | *à venir* | ⬜ | — |
| 05 | Password Spraying | Credential Access | T1110.003 | *à venir* | ⬜ | — |
| 06 | DCSync | Credential Access | T1003.006 | [06](attaques/06-dcsync.md) | ✅ | ⚠️ angle mort critique (4662 non audité) |
| 07 | Abus ACL (GenericAll…) | Privilege Escalation | T1222 | *à venir* | ⬜ | — |
| 08 | ADCS ESC1 (certificat) | Privilege Escalation | T1649 | *à venir* | ⬜ | — |
| 09 | Pass-the-Hash | Lateral Movement | T1550.002 | *à venir* | ⬜ | — |
| 10 | MSSQL trusted links | Lateral Movement | T1210 | *à venir* | ⬜ | — |
| 11 | Golden Ticket | Persistence | T1558.001 | *à venir* | ⬜ | — |
| 12 | Abus de trust inter-domaine | Domain Trusts | T1482 | *à venir* | ⬜ | — |

> Liste **réaliste** (~12 attaques solides) plutôt que « les 48 » : certaines des 48 documentées nécessitent des composants absents de GOAD-Light (Exchange, forêts multiples, PKI avancée). Ça reste une **couverture large et démonstrative**.

---

## 🔑 Comptes GOAD utilisés (lab isolé)

| Domaine | Compte | Mot de passe | Note |
|---------|--------|--------------|------|
| `sevenkingdoms.local` (DC01 · .10) | `tywin.lannister` | `powerkingftw135` | utilisateur |
| `north.sevenkingdoms.local` (DC02 · .11) | `arya.stark` | `Needle` | utilisateur |
| `north.sevenkingdoms.local` | `eddard.stark` | `FightP3aceAndHonor!` | **Domain Admin** |

> ⚠️ Ces identifiants ne valent **que** pour ce lab d'entraînement isolé. Les attaques ne se pratiquent JAMAIS sur un réseau réel.

---

## 🖼️ Convention des captures
Rangées dans [`screenshots/attacks/`](screenshots/attacks/) :
`attack-NN-<nom>-command.png` (exécution) et `attack-NN-<nom>-wazuh.png` (détection).
