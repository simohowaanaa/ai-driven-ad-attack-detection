# Screenshots

Captures organisées par phase.

## Structure

```
screenshots/
├── azure-01-deployment-complete.png     ← déploiement Azure terminé
├── azure-02-vm-overview.png             ← aperçu VM (taille, IP, OS)
├── azure-03-nested-virt.png             ← virtualisation imbriquée confirmée
├── azure-04-tools-installed.png         ← VirtualBox / Vagrant / Ansible
├── azure-05-goad-deployed.png           ← GOAD déployé (vagrant status)
├── azure-06-wazuh-dashboard.png         ← dashboard Wazuh, 3 agents actifs
├── attacks/                             ← captures Phase 4 (attaque + détection Wazuh)
│   └── attack-NN-<nom>-{command,wazuh}.png
└── phase5/                              ← captures Phase 5 (règles custom)
    ├── phase5-audit-kingslanding-dsacls.png
    └── phase5-dcsync-rule-detected.png
```

## Convention de nommage

- Lab/setup : `azure-NN-<description>.png`
- Attaques Phase 4 : `attack-NN-<nom>-command.png` (exécution) et `attack-NN-<nom>-wazuh.png` (détection)
- Phase 5 : `phase5-<description>.png`
