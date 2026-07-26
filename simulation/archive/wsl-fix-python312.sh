#!/usr/bin/env bash
# =============================================================
#  Correctif : GOAD est incompatible avec Python 3.14 (Ubuntu 26.04).
#  Ce script installe Python 3.12 via 'uv' (build standalone, SANS
#  compilation ni sudo) et recree le venv GOAD dessus.
#  A lancer DANS Ubuntu (WSL) :
#     bash /mnt/c/Users/simoh/Desktop/Dataprotect/simulation/wsl-fix-python312.sh
# =============================================================
set -e

echo "==> [1/5] Installation de uv (sans sudo)"
if ! command -v uv >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/uv" ]; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$PATH"
# rendre uv permanent dans le PATH
grep -q '.local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

echo "==> [2/5] Telechargement de Python 3.12"
uv python install 3.12

echo "==> [3/5] Recreation du venv GOAD avec Python 3.12"
cd ~/GOAD
rm -rf .venv
uv venv --python 3.12 .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> [4/5] Installation d'Ansible + pywinrm"
uv pip install ansible pywinrm

echo "==> [5/5] Verification"
python --version

echo ""
echo "============================================================="
echo "[+] CORRECTIF APPLIQUE."
echo "    Relance GOAD (nouvelle session recommandee) :"
echo "      cd ~/GOAD && source .venv/bin/activate && bash goad.sh -t check -l GOAD-Light -p virtualbox"
echo "============================================================="
