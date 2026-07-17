# 📸 Captures d'écran — montage du lab

Range ici les captures du montage du lab (pour le rapport PFA / GitHub).

## Convention de nommage
`<phase>-<NN>-<description>.png` — numérotées dans l'ordre.

## Captures du lab Azure (GOAD)
| Nom du fichier | Contenu |
|----------------|---------|
| `azure-01-deployment-complete.png` | Page "Your deployment is complete" |
| `azure-02-vm-overview.png` | Overview de la VM (taille, IP publique, Ubuntu 24.04) |
| `azure-03-nested-virt.png` | `grep -c vmx /proc/cpuinfo` > 0 (nested virt OK) |
| `azure-04-tools-installed.png` | Versions VirtualBox / Vagrant / Ansible |
| `azure-05-goad-deployed.png` | Récap GOAD déployé + `vagrant status` (VM running) |
| `azure-06-wazuh-dashboard.png` | **Phase 3** — dashboard Wazuh : 3 agents actifs (100 % coverage) |
| `azure-07-attack-kerberoast.png` | *(à venir, Phase 4)* Première attaque + alerte Wazuh |

> ⚠️ Le repo est **privé** : pas de souci pour l'IP publique. Si un jour tu le rends public, pense à **masquer l'IP** sur les captures.
