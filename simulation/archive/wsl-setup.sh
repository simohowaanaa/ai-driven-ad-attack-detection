#!/usr/bin/env bash
# =============================================================
#  GOAD Lab - Preparation de l'environnement WSL (Phase 2)
#  A lancer DANS Ubuntu (WSL) :
#     bash /mnt/c/Users/simoh/Desktop/Dataprotect/simulation/wsl-setup.sh
#  Demande le mot de passe sudo une seule fois.
# =============================================================
set -e

echo "==> [1/6] Mise a jour APT + outils de base (sudo)"
sudo apt-get update
sudo apt-get install -y git python3 python3-pip python3-venv python3-full curl unzip gnupg lsb-release

echo "==> [2/6] Installation de Vagrant dans WSL (repo HashiCorp)"
wget -qO - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
# codename 'noble' (24.04 LTS) : compatible et supporte par HashiCorp
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com noble main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update
sudo apt-get install -y vagrant

echo "==> [3/6] Plugin vagrant-reload"
vagrant plugin install vagrant-reload || echo "   (plugin a reverifier plus tard)"

echo "==> [4/6] Pont Vagrant -> VirtualBox Windows (~/.bashrc)"
if ! grep -q VAGRANT_WSL_ENABLE_WINDOWS_ACCESS ~/.bashrc; then
cat >> ~/.bashrc <<'RC'

# --- GOAD lab : pont WSL -> VirtualBox Windows ---
export VAGRANT_WSL_ENABLE_WINDOWS_ACCESS="1"
export PATH="$PATH:/mnt/c/Program Files/Oracle/VirtualBox"
export VAGRANT_DEFAULT_PROVIDER=virtualbox
RC
  echo "   variables ajoutees a ~/.bashrc"
else
  echo "   variables deja presentes"
fi

echo "==> [5/6] Clonage de GOAD (dans ~/GOAD)"
cd ~
if [ ! -d GOAD ]; then
  git clone https://github.com/Orange-Cyberdefense/GOAD.git
else
  echo "   GOAD deja clone"
fi

echo "==> [6/6] Environnement Python (ansible + pywinrm)"
cd ~/GOAD
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install ansible pywinrm

echo ""
echo "============================================================="
echo "[+] PREPARATION TERMINEE."
echo "    Verifs :"
echo "      vagrant --version"
echo "      VBoxManage.exe --version"
echo "      ansible --version   (apres 'source ~/GOAD/.venv/bin/activate')"
echo ""
echo "    Etape suivante (deploiement GOAD-Light) :"
echo "      cd ~/GOAD && source .venv/bin/activate && bash goad.sh"
echo "============================================================="
