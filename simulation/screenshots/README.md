# Screenshots

Captures d'écran du lab et des attaques, organisées par phase.

---

## Structure

```
screenshots/
│
├── azure-01-deployment-complete.png     Déploiement Azure terminé ("Your deployment is complete")
├── azure-02-vm-overview.png             Vue d'ensemble de la VM (taille, IP, Ubuntu 24.04)
├── azure-03-nested-virt.png             Virtualisation imbriquée confirmée (vmx détecté)
├── azure-04-tools-installed.png         VirtualBox, Vagrant, Ansible installés
├── azure-05-goad-deployed.png           GOAD-Light déployé — vagrant status (3 VM running)
├── azure-06-wazuh-dashboard.png         Dashboard Wazuh — 3 agents actifs (100% coverage)
│
├── attacks/                             Captures Phase 4 — une par attaque
│   ├── attack-NN-<nom>-command.png      La commande d'attaque et son résultat
│   └── attack-NN-<nom>-wazuh.png        Ce que Wazuh a détecté (ou pas)
│
└── phase5/                              Captures Phase 5 — règles custom
    ├── phase5-audit-kingslanding-dsacls.png    SACL DCSync posée sur kingslanding
    └── phase5-dcsync-rule-detected.png         Règle 100010 : DCSync détecté en live
```

## Convention de nommage

| Préfixe | Phase | Exemple |
|---------|-------|---------|
| `azure-NN-` | Phase 2 (déploiement) | `azure-05-goad-deployed.png` |
| `attack-NN-<nom>-command` | Phase 4 (exécution attaque) | `attack-06-dcsync-command.png` |
| `attack-NN-<nom>-wazuh` | Phase 4 (détection Wazuh) | `attack-06-dcsync-wazuh.png` |
| `phase5-` | Phase 5 (règles custom) | `phase5-dcsync-rule-detected.png` |
