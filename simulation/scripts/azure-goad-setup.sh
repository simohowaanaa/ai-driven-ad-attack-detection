#!/usr/bin/env bash
# =============================================================
#  Installation de l'outillage GOAD sur la VM Azure (Ubuntu 24.04)
#  A lancer DANS la VM Azure (via SSH) :
#     bash setup-goad.sh
#  (l'utilisateur Azure a le sudo sans mot de passe)
# =============================================================
set -e

echo "=== [1/6] MAJ + outils de base ==="
sudo apt-get update
sudo apt-get install -y git curl gnupg unzip python3 python3-pip python3-venv \
     linux-headers-$(uname -r) dkms build-essential

echo "=== [2/6] VirtualBox (depot Oracle) ==="
wget -qO- https://www.virtualbox.org/download/oracle_vbox_2016.asc | sudo gpg --yes --dearmor -o /usr/share/keyrings/oracle-vbox.gpg
echo "deb [signed-by=/usr/share/keyrings/oracle-vbox.gpg] https://download.virtualbox.org/virtualbox/debian noble contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list
sudo apt-get update
sudo apt-get install -y virtualbox-7.1
sudo usermod -aG vboxusers "$USER"
sudo modprobe vboxdrv 2>/dev/null || sudo /sbin/vboxconfig || true

echo "=== [3/6] Vagrant (depot HashiCorp) ==="
wget -qO- https://apt.releases.hashicorp.com/gpg | sudo gpg --yes --dearmor -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com noble main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update
sudo apt-get install -y vagrant

echo "=== [4/6] Plugins Vagrant ==="
vagrant plugin install vagrant-reload vagrant-vbguest

echo "=== [5/6] Clonage GOAD ==="
cd ~
[ -d GOAD ] || git clone https://github.com/Orange-Cyberdefense/GOAD.git

echo "=== [6/6] Environnement Python GOAD ==="
cd ~/GOAD
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install ansible-core pywinrm

echo ""
echo "============================================"
echo "[+] INSTALLATION TERMINEE"
VBoxManage --version
vagrant --version
echo -n "Module vboxdrv : "; lsmod | grep -q vboxdrv && echo "CHARGE OK" || echo "NON CHARGE (lancer: sudo /sbin/vboxconfig)"
echo "============================================"
