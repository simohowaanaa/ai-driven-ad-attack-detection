# 🗄️ Archive — approche locale abandonnée

Ce dossier conserve la **première approche** de montage du lab, qui a été **abandonnée**, uniquement comme **trace de la démarche** (utile pour le mémoire / la soutenance). **Ne pas suivre ces guides pour déployer.**

## Pourquoi abandonnée ?
Le montage **local** (Windows + VirtualBox + **Hyper-V** + WSL2) s'est heurté à un mur : **WinRM fondamentalement instable** dans cet empilement (les VM bootent mais Vagrant/Ansible ne les configurent pas de façon fiable).

➡️ **Solution retenue et fonctionnelle : déploiement sur une VM Linux Azure** → voir [`../01-deploiement-azure.md`](../01-deploiement-azure.md).

## Contenu
| Fichier | Description |
|---------|-------------|
| [`lab-setup-local.md`](lab-setup-local.md) | Guide du montage local (abandonné) |
| [`wsl-setup.sh`](wsl-setup.sh) · [`wsl-fix-python312.sh`](wsl-fix-python312.sh) | Scripts de provisioning de l'approche locale |
