# 🌩️ GOAD sur Azure (VM Linux + VirtualBox)

> **Pourquoi Azure ?** GOAD tourne **dans une VM Linux** → plus de conflit Hyper-V/WinRM (la galère du laptop). Environnement natif Linux = GOAD fiable.
> **Coût :** crédit **$100 Azure for Students**. On **éteint la VM** quand on ne l'utilise pas → ~30 €/mois effectif → dure ~3 mois.

**Légende :** 🧑‍💻 = à faire par toi (portail Azure / SSH) · 📸 = capture pour le rapport.

---

## ⚠️ Règle d'or : ÉTEINDRE la VM après chaque session
Portail Azure → ta VM → **Stop (Deallocate)**. Tu ne paies le calcul **que quand la VM tourne**. Oublier = crédit épuisé en ~2 semaines.

---

## Phase A — Créer la VM Azure 🧑‍💻

1. **Activer Azure for Students** (si pas déjà fait) : https://azure.microsoft.com/free/students — avec ton **email académique** ($100, sans carte bancaire).

2. Portail Azure → **Créer une ressource** → **Machine virtuelle**.

3. **Paramètres de base :**
   | Champ | Valeur |
   |-------|--------|
   | Abonnement | Azure for Students |
   | Groupe de ressources | *Créer* → `rg-goad-lab` |
   | Nom de la VM | `goad-host` |
   | Région | `France Central` (ou `West Europe`) |
   | Image | **Ubuntu Server 22.04 LTS** |
   | Architecture VM | x64 |
   | **Taille** | ⚠️ **Standard_E4s_v3** (4 vCPU, 32 Go) — cliquer *"Voir toutes les tailles"* pour la trouver |
   | Authentification | **Clé publique SSH** |
   | Nom d'utilisateur | `goad` |
   | Paire de clés | *Générer une nouvelle paire* (télécharge le `.pem` → garde-le !) |
   | Ports entrants publics | **SSH (22)** |

   > 🔑 **La taille E4s_v3 est CRUCIALE** : elle supporte la *nested virtualization* (obligatoire pour lancer des VM dans la VM). **Évite la série B** (Bs) qui ne la supporte PAS.

4. **Onglet Disques :**
   - Disque OS : **Premium SSD**.
   - Taille : **128 Go** (les VM GOAD ont besoin de place). *(si non modifiable ici, on le fera en Phase B)*

5. **Vérifier + Créer** → attendre le déploiement (~2-3 min).

📸 **Capture 1 :** la page "Déploiement terminé" + l'**IP publique** de la VM.

---

## Phase B — Préparer la VM 🧑‍💻

1. **Se connecter en SSH** (depuis ton terminal / WSL) :
   ```bash
   chmod 600 goad-host_key.pem
   ssh -i goad-host_key.pem goad@<IP_PUBLIQUE>
   ```

2. **Vérifier la nested virtualization** (doit renvoyer un nombre > 0) :
   ```bash
   grep -c -E 'vmx|svm' /proc/cpuinfo
   ```
   > Si `0` → la taille de VM ne supporte pas la nested virt : recréer en E4s_v3/D8s_v3.

3. **Installer l'outillage** (script fourni : `azure-goad-setup.sh`) :
   ```bash
   # On copiera/collera le script, puis :
   bash azure-goad-setup.sh
   ```
   Il installe : VirtualBox, Vagrant, Ansible, git, python — en **natif Linux**.

📸 **Capture 2 :** `grep -c vmx /proc/cpuinfo` > 0 + versions VirtualBox/Vagrant.

---

## Phase C — Déployer GOAD 🧑‍💻

```bash
cd ~/GOAD
./goad.sh -t install -l GOAD-Light -p virtualbox
```
> Cette fois, **environnement Linux natif** → pas d'Hyper-V, WinRM stable → le déploiement doit **aller au bout** (vagrant + ansible). ⏱️ ~1 h.

📸 **Capture 3 :** le récap final GOAD en vert + `vagrant status` (3 VM `running`).

---

## Phase D — Attaquer & générer des logs 🧑‍💻

Deux options :
- Installer les outils d'attaque **sur la VM Azure** (`pipx install impacket`, netexec, etc.).
- Ou ajouter une **VM Kali** dans le lab.

Puis lancer nos attaques (Kerberoasting, AS-REP…) → générer les logs pour la Phase 3.

---

## 💰 Suivi du crédit
- Portail → **Cost Management** pour suivre la consommation.
- **Deallocate** systématiquement après usage.
- Le disque coûte un peu même VM éteinte (~5-10 €/mois) — normal.

---

## 📸 Récap captures
| # | Capture | Phase |
|---|---------|-------|
| 1 | Déploiement VM + IP publique | A |
| 2 | nested virt OK + versions outils | B |
| 3 | GOAD déployé (récap vert, 3 VM) | C |
