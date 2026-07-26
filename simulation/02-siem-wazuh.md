# 🛡️ Phase 3 — Wazuh (SIEM/EDR) sur le lab GOAD

> **But :** brancher un **SIEM** sur le lab Active Directory pour **collecter les logs** des contrôleurs de domaine et **détecter les attaques** qu'on rejouera en Phase 4. C'est l'équivalent, à l'échelle du lab, du couple **QRadar / Elastic** utilisé au SOC de Dataprotect.

> **Légende :** 🧑‍💻 = action à faire · ✅ = fait · 📸 = capture pour le rapport.

**Déployé le :** 2026-07-17 · **Statut :** ✅ Fonctionnel (3 agents actifs, 100 % coverage).

---

## 1. Pourquoi Wazuh ?

**Wazuh** est une plateforme open-source **SIEM + EDR** (XDR). Pour notre projet elle joue 3 rôles d'un coup :

| Composant | Rôle |
|-----------|------|
| **Wazuh indexer** | Base de données des logs (basée sur OpenSearch) |
| **Wazuh manager** | Moteur qui analyse les logs et applique les **règles de détection** |
| **Wazuh dashboard** | Interface web de visualisation (alertes, agents, événements) |
| **Agents** | Installés sur DC01/DC02/SRV02, ils remontent les **Event Logs Windows** au manager |
| **Règles SOC Fortress** | Jeu de règles de détection prêtes à l'emploi (Kerberoasting, DCSync, etc.) |

GOAD fournit une **extension `wazuh`** qui automatise tout ça.

---

## 2. Architecture (après Phase 3)

```
        VM Azure Linux (Ubuntu 24.04 · Standard_E4s_v3 · 32 Go)
        ┌──────────────────────────────────────────────────────────┐
        │   VirtualBox (natif)                                      │
        │   ┌──────────┐  ┌──────────┐  ┌──────────┐                │
        │   │  DC01    │  │  DC02    │  │  SRV02   │                │
        │   │ .10      │  │ .11      │  │ .22      │                │
        │   │ kingsl.  │  │ winterf. │  │ castelb. │                │
        │   └────┬─────┘  └────┬─────┘  └────┬─────┘                │
        │        │ agent       │ agent       │ agent                │
        │        └─────────────┼─────────────┘                      │
        │                      ▼                                    │
        │              ┌───────────────┐                           │
        │              │  Wazuh  .51    │  ← SIEM (indexer+manager+ │
        │              │  (Ubuntu)      │     dashboard)            │
        │              └───────────────┘                           │
        │              Réseau host-only 192.168.56.0/24             │
        └──────────────────────────────────────────────────────────┘
                              ▲
                     tunnel SSH (port 443 → localhost:8443)
                              │
                        Navigateur du PC → https://localhost:8443
```

| Agent (nom Wazuh) | IP | Machine | Domaine |
|-------------------|-----|---------|---------|
| `kingslanding` | 192.168.56.10 | **DC01** | `sevenkingdoms.local` |
| `winterfell` | 192.168.56.11 | **DC02** | `north.sevenkingdoms.local` |
| `castelblack` | 192.168.56.22 | **SRV02** | membre + MSSQL |

---

## 3. 🧑‍💻 Déploiement de l'extension Wazuh

⚠️ **Important — NE PAS utiliser `-e wazuh` en ligne de commande** : ce flag **relance TOUTE l'install de base** (ad, adcs, servers…) à chaque fois (long et inutile). On utilise la **console interactive** qui installe **seulement** l'extension.

Sur la VM Azure, lab démarré :

```bash
cd ~/GOAD && source .venv/bin/activate
./goad.sh
```

Puis dans la console `goad>` :
```
load fba132-goad-light-virtualbox
install_extension wazuh
```

> ⏳ ~1 h à 1 h 15 : création de la VM Wazuh (`vagrant up`) + installation du serveur + pose des agents.
> 💡 Si l'install **plante en cours de route** (VM Wazuh déjà créée), on **reprend** sans la recréer avec :
> ```
> provision_extension wazuh
> ```

📸 **Capture :** le `PLAY RECAP` final avec `failed=0` sur `dc01/dc02/srv02/wazuh` (`azure-06`… ou dédiée).

---

## 4. 🧑‍💻 Accès au dashboard

Le dashboard écoute en `https://192.168.56.51` (réseau **interne** à la VM Azure). Depuis le PC, on fait un **tunnel SSH**.

**Étape 1 — récupérer le mot de passe admin** (dans la VM Wazuh) :
```bash
ssh vagrant@192.168.56.51           # mot de passe : vagrant
sudo grep -i "password" /opt/wazuh/wazuh-install-output.txt
```
> Le mot de passe de l'utilisateur `admin` du dashboard s'y trouve. 🔒 **Ne jamais committer ce mot de passe.**

**Étape 2 — ouvrir le tunnel** (depuis le PC, PowerShell) :
```powershell
ssh -i C:\chemin\vers\goad-host_key.pem -L 8443:192.168.56.51:443 goad@<IP-Azure>
```
Laisser la fenêtre ouverte.

**Étape 3 — le navigateur :**
`https://localhost:8443` → *Avancé → Continuer* (certificat auto-signé) → login **`admin`** / *(mot de passe de l'étape 1)*.

📸 **Capture `azure-06-wazuh-dashboard.png` :** page **Endpoints** montrant les **3 agents actifs** (100 % coverage) — preuve de la Phase 3.

---

## 5. 🔧 Problèmes rencontrés & solutions (retour d'expérience)

> Le déploiement sur une VM imbriquée (VM dans VM) a demandé plusieurs correctifs. Cette section est un **vrai retour d'expérience d'analyste** — utile pour la soutenance.

| # | Symptôme | Cause | Solution |
|---|----------|-------|----------|
| 1 | `you must install the sshpass program` | Ansible se connecte en SSH par mot de passe à la VM Wazuh, `sshpass` absent | `sudo apt install -y sshpass` sur l'hôte Azure |
| 2 | Dashboard : `disk usage exceeded flood-stage watermark` | Disque de la VM Wazuh saturé à **99 %** (31 Go) → OpenSearch verrouille tout en lecture seule | Agrandir via LVM (espace libre du VG) : `sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv && sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv` → 61 Go |
| 3 | `wazuh-indexer.service: start timed out` | OpenSearch (Java) trop lent à démarrer sur CPU partagé → systemd le tue à 90 s | Augmenter le délai : override `TimeoutStartSec=900` dans `/etc/systemd/system/wazuh-indexer.service.d/` + `daemon-reload` |
| 4 | Dashboard : `Wazuh API ... Offline` / `Invalid credentials` | Mot de passe de l'utilisateur API `wazuh-wui` **désynchronisé** entre le manager et `wazuh.yml` | Le compte admin API par défaut `wazuh:wazuh` fonctionnait encore → `PUT /security/users/2` pour forcer le mot de passe `wazuh-wui` = celui de `wazuh.yml` |
| 5 | `Timeout executing API request` (erreur `3021`) | API surchargée (CPU saturé au moment de la requête) | Relancer la commande (ça passe quand la charge retombe) ; ou libérer du CPU en mettant les VM Windows en pause |
| 6 | `[API version] timeout of 20000ms exceeded` | Même surcharge CPU, non bloquant | Rafraîchir une fois la charge retombée ; ou redimensionner la VM Azure |

### Leçon principale
La quasi-totalité de ces erreurs vient d'un **manque de CPU** : 4 vCPU partagés entre 4 VM (3 Windows + Wazuh/OpenSearch). Pour un fonctionnement fluide, **passer la VM Azure à `Standard_E8s_v3` (8 vCPU / 64 Go)** et allouer plus de RAM/CPU à la VM Wazuh (`VBoxManage modifyvm "GOAD-Light-WAZUH" --memory 8192 --cpus 3`).

---

## 6. ✅ Résultat & suite

- ✅ Serveur Wazuh opérationnel + **3 agents actifs** (100 % coverage).
- ✅ Les Event Logs des DC remontent en temps réel dans le SIEM.

➡️ **Phase 4 :** lancer les attaques (Kerberoasting, DCSync, AS-REP…) depuis Kali/outils et **observer les alertes** que Wazuh génère → base pour la Phase 5 (règles de détection) et la Phase 6 (agent IA).
