# ⚔️ Phase 4 — Simulation des attaques & détection Wazuh (index)

> **But :** rejouer les attaques documentées dans [`../docs/`](../docs/) sur le lab GOAD, puis **vérifier dans Wazuh** (Phase 3) qu'elles laissent une trace détectable. La démonstration centrale du PFA : **attaque → trace → détection.**

> **Méthode :** les outils (impacket, netexec) sont installés **directement sur l'hôte Azure** (qui voit le réseau du lab `192.168.56.0/24`) — pas besoin d'une VM Kali séparée.

## 📁 Une fiche par attaque
Chaque attaque a **son propre fichier** dans [`attaques/`](attaques/), avec les **captures intégrées** (exécution + détection Wazuh).

| # | Attaque | MITRE | Fiche | Simulée | Détectée Wazuh |
|---|---------|-------|-------|:-------:|:--------------:|
| 01 | Kerberoasting | T1558.003 | [`attaques/01-kerberoasting.md`](attaques/01-kerberoasting.md) | ✅ | ✅ (rule 92652) |
| 02 | AS-REP Roasting | T1558.004 | [`attaques/02-asrep-roasting.md`](attaques/02-asrep-roasting.md) | ✅ | ⚠️ angle mort (4768 non audité) |
| 03 | DCSync | T1003.006 | *à venir* | ⬜ | ⬜ |
| 04 | Password Spray | T1110.003 | *à venir* | ⬜ | ⬜ |

## 🔑 Comptes GOAD utilisés (lab isolé)
| Domaine | Compte | Mot de passe |
|---------|--------|--------------|
| `sevenkingdoms.local` (DC01 · .10) | `tywin.lannister` | `powerkingftw135` |
| `north.sevenkingdoms.local` (DC02 · .11) | `arya.stark` | `Needle` |

> ⚠️ Ces identifiants ne valent **que** pour ce lab d'entraînement isolé. Les attaques ne se pratiquent JAMAIS sur un réseau réel.

## 🖼️ Convention des captures
Rangées dans [`screenshots/attacks/`](screenshots/attacks/) :
`attack-NN-<nom>-command.png` (l'exécution) et `attack-NN-<nom>-wazuh.png` (la détection).
