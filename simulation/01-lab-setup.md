# 🏗️ Phase 2 — Montage du Lab LOCAL (GOAD-Light sur VirtualBox)

> ⚠️ **APPROCHE ABANDONNÉE — ne pas suivre ce guide pour déployer.**
> Ce montage **local** (Windows + VirtualBox + **Hyper-V** + WSL2) s'est heurté à un mur : **WinRM fondamentalement instable** dans cet empilement — les VM bootent mais Vagrant/Ansible ne les configurent pas de façon fiable (erreurs `device not ready`, `init_auth timeout`, VM injoignables par Ansible).
> ✅ **Solution retenue et fonctionnelle : déploiement sur une VM Linux Azure** → voir **[`02-azure-goad.md`](02-azure-goad.md)**.
> Ce document est conservé comme **trace de la démarche** (ce qui a été tenté, le diagnostic, le pivot vers Azure) — utile pour le mémoire/soutenance.

> **But :** construire un Active Directory vulnérable et isolé pour rejouer les 48 attaques et générer des logs.
> **Légende :** 🧑‍💻 = action à faire par toi · ✅ = déjà fait · 📸 = capture d'écran à prendre pour le rapport/GitHub.

---

## Résumé de l'environnement

| Élément | Valeur |
|---------|--------|
| Hôte | Windows 11 · i9-14900HX · 31.7 Go RAM · VT-x ✅ |
| Base vulnérable | **GOAD-Light** (2 VM Windows Server) |
| Attaquant | Kali Linux |
| Contrôleur Ansible | WSL2 (Ubuntu) |
| Provider | VirtualBox |

**Pourquoi GOAD-Light ?** 2 VM au lieu de 5 → tient large dans 32 Go, couvre ~90 % de nos attaques (Cat. 1 à 6). On pourra passer au GOAD complet plus tard pour les *trusts* (Cat. 7).

---

## Étape 0 — Pré-requis (état actuel)

| Composant | État |
|-----------|------|
| Virtualisation (VT-x) | ✅ activée |
| RAM / disque | ✅ OK |
| git / python / winget | ✅ présents |
| WSL2 | ⬜ à réparer/installer |
| VirtualBox | ⬜ à installer |
| Vagrant | ⬜ à installer |

---

## Étape 1 — 🧑‍💻 Installer / réparer WSL2 (Ubuntu)

WSL2 nous sert de **contrôleur Ansible** (la partie qui configure l'AD vulnérable).

1. Ouvre **PowerShell en administrateur** (clic droit sur le menu Démarrer → *Terminal (Admin)*).
2. Lance :
   ```powershell
   wsl --install -d Ubuntu
   ```
3. **Redémarre** le PC si demandé.
4. Au redémarrage, Ubuntu s'ouvre et demande de créer un **user + mot de passe** Linux (note-les).
5. Vérifie :
   ```powershell
   wsl -l -v
   ```
   → tu dois voir `Ubuntu ... VERSION 2`.

📸 **Capture 1 :** la sortie de `wsl -l -v` montrant Ubuntu en version 2.

---

## Étape 2 — 🧑‍💻 Installer VirtualBox + Vagrant

Dans **PowerShell administrateur** :

```powershell
winget install --id Oracle.VirtualBox -e
winget install --id Hashicorp.Vagrant -e
```

> Accepte les fenêtres UAC. Après l'install de Vagrant, **ferme et rouvre** tes terminaux (pour rafraîchir le PATH).

Vérifie (PowerShell normal) :
```powershell
VBoxManage --version
vagrant --version
```

📸 **Capture 2 :** les versions de VirtualBox et Vagrant affichées.

---

## Étape 3 — 🧑‍💻 Préparer WSL2 (Ansible + Vagrant → VirtualBox Windows)

Ouvre **Ubuntu (WSL)** et exécute :

```bash
# Mise à jour + outils de base
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3 python3-pip python3-venv

# Vagrant DANS WSL (il pilotera le VirtualBox de Windows)
wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y vagrant
```

Puis on connecte **Vagrant (WSL) → VirtualBox (Windows)**. Ajoute ces lignes à la fin de `~/.bashrc` :

```bash
echo 'export VAGRANT_WSL_ENABLE_WINDOWS_ACCESS="1"' >> ~/.bashrc
echo 'export PATH="$PATH:/mnt/c/Program Files/Oracle/VirtualBox"' >> ~/.bashrc
echo 'export VAGRANT_DEFAULT_PROVIDER=virtualbox' >> ~/.bashrc
source ~/.bashrc
```

Vérifie que WSL voit bien VirtualBox de Windows :
```bash
VBoxManage.exe --version
```

📸 **Capture 3 :** `VBoxManage.exe --version` qui répond **depuis WSL** (preuve que le pont WSL↔VirtualBox marche).

---

## Étape 4 — 🧑‍💻 Déployer GOAD-Light

Toujours dans **Ubuntu (WSL)** :

```bash
# Récupérer GOAD
cd ~
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD

# Installer les dépendances Python (ansible, pywinrm...) dans un venv
python3 -m venv .venv && source .venv/bin/activate
pip install ansible pywinrm

# Lancer le gestionnaire GOAD
./goad.sh
```

Dans l'invite interactive `goad>`, sélectionne :
```
set_lab GOAD-Light
set_provider virtualbox
install
```

> ⏳ Le déploiement est **long** (30 min à 2 h) : Vagrant télécharge les images Windows Server, crée les 2 VM, puis Ansible installe l'AD et les vulnérabilités. Laisse tourner.

Si le `goad.sh` interactif pose souci, l'équivalent en une commande :
```bash
./goad.sh -t install -l GOAD-Light -p virtualbox
```

📸 **Capture 4 :** le message de fin de déploiement GOAD ("recap" en vert / "Successfully").
📸 **Capture 5 :** l'interface **VirtualBox** montrant les 2 VM GOAD-Light démarrées (ex. `GOAD-Light-DC01`, `GOAD-Light-SRV02`).

---

## Étape 5 — 🧑‍💻 Ajouter la VM attaquant (Kali)

1. Télécharge l'image **Kali pour VirtualBox** : https://www.kali.org/get-kali/#kali-virtual-machines (format `.7z` VirtualBox).
2. Décompresse, puis dans VirtualBox : *Fichier → Importer un appareil virtuel* (ou double-clic sur le `.vbox`).
3. **Réseau :** mets la carte réseau de Kali sur le **même réseau interne/hôte** que les VM GOAD (souvent `VirtualBox Host-Only Network` ou le réseau `192.168.56.0/24` de GOAD). Objectif : Kali doit **pinguer le DC**.
4. Démarre Kali (login par défaut : `kali` / `kali`).

📸 **Capture 6 :** Kali démarré, avec un `ip a` montrant son adresse dans le réseau du lab.

---

## Étape 6 — 🧑‍💻 Vérifier que le lab fonctionne

Le test de validation : depuis **Kali**, prouver qu'on parle bien à l'AD.

```bash
# 1. Ping du DC (l'IP du DC GOAD-Light, souvent 192.168.56.10 ou .11)
ping -c 3 192.168.56.11

# 2. Énumération anonyme / test SMB (installer netexec si absent : pipx install netexec)
nxc smb 192.168.56.11

# 3. Lister les utilisateurs du domaine avec un compte GOAD
#    (GOAD fournit des comptes ; ex. domaine sevenkingdoms.local)
nxc smb 192.168.56.11 -u <user> -p <password> --users
```

> Les identifiants et IP exacts sont donnés par GOAD à la fin de l'install (fichier `GOAD/ad/GOAD-Light/data/` et la doc GOAD).

📸 **Capture 7 :** la sortie de `nxc smb` affichant le nom du domaine et la version Windows du DC (preuve que le lab répond).
📸 **Capture 8 :** la liste des utilisateurs du domaine énumérés (`--users`).

---

## ✅ Fin de la Phase 2

À ce stade tu as :
- Un **AD vulnérable** (GOAD-Light) qui tourne.
- Une **machine attaquant** (Kali) connectée au même réseau.
- La **preuve** que Kali communique avec le DC.

➡️ **Phase 3 :** installer **Sysmon + Winlogbeat** sur les VM Windows et brancher **Elastic**, pour capturer les logs quand on attaquera.

---

## 📸 Récap des captures à mettre sur GitHub

| # | Capture | Étape |
|---|---------|-------|
| 1 | `wsl -l -v` → Ubuntu v2 | 1 |
| 2 | Versions VirtualBox + Vagrant | 2 |
| 3 | `VBoxManage.exe --version` depuis WSL | 3 |
| 4 | Fin de déploiement GOAD (succès) | 4 |
| 5 | VirtualBox avec les 2 VM GOAD démarrées | 4 |
| 6 | Kali démarré + `ip a` | 5 |
| 7 | `nxc smb` sur le DC (domaine + OS) | 6 |
| 8 | Liste des utilisateurs du domaine | 6 |

> 💡 Range ces captures dans un dossier `simulation/screenshots/` du repo et référence-les ici.
