#!/usr/bin/env bash
# =============================================================
#  start-wazuh.sh — démarrage à froid des services Wazuh
#  À exécuter DANS la VM Wazuh (192.168.56.51) :  bash start-wazuh.sh
#
#  Redémarre indexer -> manager -> dashboard (dans l'ordre) puis
#  resynchronise le mot de passe de l'API (utilisateur wazuh-wui),
#  lu directement depuis wazuh.yml -> AUCUN secret codé en dur.
# =============================================================

CONFIG="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"

echo "=== [1/4] Redemarrage wazuh-indexer (LONG, 2-5 min, patiente) ==="
sudo systemctl restart wazuh-indexer
echo "    indexer   : $(systemctl is-active wazuh-indexer)"

echo "=== [2/4] Redemarrage wazuh-manager ==="
sudo systemctl restart wazuh-manager
echo "    manager   : $(systemctl is-active wazuh-manager)"

echo "=== [3/4] Redemarrage wazuh-dashboard ==="
sudo systemctl restart wazuh-dashboard
echo "    dashboard : $(systemctl is-active wazuh-dashboard)"

echo "=== [4/4] Resynchronisation du mot de passe API (wazuh-wui) ==="
WUI_PASS=$(sudo awk -F'"' '/password:/{print $2}' "$CONFIG" | tail -1)
TOKEN=""
for i in 1 2 3 4 5 6; do
  TOKEN=$(curl -s -k -u wazuh:wazuh -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true")
  case "$TOKEN" in
    ey*) break ;;
    *) echo "    ... API pas encore prete, nouvelle tentative dans 15s ($i/6)"; sleep 15 ;;
  esac
done
if [ "${TOKEN:0:2}" = "ey" ]; then
  curl -s -k -X PUT "https://127.0.0.1:55000/security/users/2" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"password\": \"$WUI_PASS\"}" | grep -o '"message":[^,}]*' || echo "    resync envoye"
else
  echo "    ATTENTION : l'API ne repond toujours pas. Relance ./start-wazuh.sh dans 1-2 min."
fi

echo ""
echo "=== Etat final ==="
sudo systemctl is-active wazuh-indexer wazuh-manager wazuh-dashboard
echo ""
echo "[+] Termine ! Ouvre le tunnel SSH puis https://localhost:8443"
echo "    (login: admin / ton mot de passe Wazuh)"
