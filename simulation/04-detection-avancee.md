# 🛡️ Phase 5 — Audits & règles de détection sur-mesure

> **But :** combler les angles morts identifiés en Phase 4 en (1) activant les catégories d'audit Windows manquantes sur les DC, puis (2) écrivant des règles Wazuh custom qui transforment ces nouveaux événements en alertes.

---

## 🧠 Pourquoi cette phase est nécessaire

Sur les **12 attaques** simulées en Phase 4, **6 sont restées invisibles** dans Wazuh — non pas parce que le SIEM est mauvais, mais parce que les **catégories d'audit Windows** correspondantes n'étaient pas activées sur les contrôleurs de domaine. Sans audit activé, l'action se produit (ex: DCSync réplique tous les hashs) mais **aucun événement n'est écrit** dans le journal Windows → Wazuh n'a rien à lire.

```
Action AD  →  Politique d'audit (activée ou non)  →  Windows Event Log  →  Agent Wazuh
                        ↑
                 C'EST CE QU'ON ACTIVE ICI
```

## 🎯 Catégories d'audit à activer

| Catégorie d'audit | Event(s) généré(s) | Comble l'angle mort de |
|---|---|---|
| **Directory Service Access** | 4662 | [DCSync (06)](attaques/06-dcsync.md), [Énumération (03)](attaques/03-enumeration.md) |
| **Kerberos Authentication Service** | 4768 | [AS-REP Roasting (02)](attaques/02-asrep-roasting.md) |
| **Kerberos Service Ticket Operations** | 4769 | [Kerberoasting (01)](attaques/01-kerberoasting.md) |
| **Certification Services** | 4886 / 4887 | [ADCS ESC1 (08)](attaques/08-adcs-esc1.md) |
| **Process Creation** (+ ligne de commande) | 4688 | [MSSQL RCE (10)](attaques/10-mssql-rce.md) |

**Méthode retenue pour le lab :** `auditpol` en local sur chaque DC (via une session PowerShell distante), plutôt qu'une GPO — plus rapide pour 2 DC, et pédagogiquement équivalent.

```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

À appliquer sur les **2 DC** : `kingslanding` (192.168.56.10, sevenkingdoms) et `winterfell` (192.168.56.11, north).

## 📋 Plan de la phase

1. **Activer les audits** ci-dessus sur les 2 DC.
2. **Rejouer** 2-3 attaques clés (DCSync, Kerberoasting, ADCS ESC1) pour vérifier que les événements remontent désormais dans Wazuh.
3. **Écrire des règles Wazuh custom** (`local_rules.xml`) qui transforment ces événements en alertes exploitables :
   - alerte critique sur toute requête DRS `GetNCChanges` hors des DC légitimes (DCSync)
   - alerte sur les tickets Kerberos chiffrés en RC4 (Kerberoasting)
   - alerte sur toute émission de certificat avec `Enrollee Supplies Subject` (ADCS)
   - alerte sur les processus enfants de `sqlservr.exe` (MSSQL RCE)
4. **Documenter** le avant/après détection pour chaque attaque concernée.

## 🚧 État d'avancement

| Étape | Statut |
|:-----:|--------|
| Activation des audits sur `kingslanding` | ✅ Confirmé |
| Activation des audits sur `winterfell` | ✅ Confirmé |
| Re-test DCSync avec audit + SACL actifs | ✅ Confirmé |
| Règle Wazuh custom — DCSync | ✅ **Détecté** |
| Règles Wazuh custom — autres angles morts | ⬜ À faire |

---

## ✅ Confirmation — `kingslanding` (DC01, sevenkingdoms)

Les 5 catégories cibles sont actives, vérifiées via `auditpol /get /category:*` exécuté directement sur le DC :

```
DS Access
  Directory Service Access                Success and Failure

Account Logon
  Kerberos Service Ticket Operations      Success and Failure
  Kerberos Authentication Service         Success and Failure

Object Access
  Certification Services                  Success and Failure

Detailed Tracking
  Process Creation                        Success
```

La **SACL DCSync** (`Replicating Directory Changes` / `...All` sur `DC=sevenkingdoms,DC=local`) a également été posée avec succès :

![dsacls appliqué avec succès sur kingslanding](screenshots/phase5/phase5-audit-kingslanding-dsacls.png)

### 🛠️ Méthode qui a fonctionné (note technique)

Sur ce lab, les canaux d'exécution distante habituels (**WinRM/evil-winrm**, **atexec**, **psexec**) échouent silencieusement sur `kingslanding` — les commandes rapportent un succès protocolaire mais **n'ont aucun effet réel** sur la machine (confirmé par un test de preuve : `mkdir` via 3 mécanismes différents, aucun n'a créé le dossier). Cause probable : une protection active côté DC (Defender ou équivalent) neutralisant l'exécution distante non-interactive.

**Solution qui a marché :**
1. Rendre un compte de domaine **Domain Admin** via `bloodyAD` (LDAP — le seul canal resté fiable tout au long du projet)
2. Se connecter en **RDP natif** (port 3389, tunnelé en SSH) avec ce compte — session interactive, insensible aux protections qui bloquent l'exécution non-interactive
3. **Uploader le script** d'audit via `smbclient.py` (écriture SMB directe, fiable) plutôt que de taper les commandes à la main
4. **Exécuter une seule ligne courte** dans la session RDP : `powershell -ep bypass -file C:\Windows\Temp\audit.ps1`
5. **Récupérer le résultat** via `smbclient.py get` (pas besoin de repasser par RDP)

> 💡 Cette instabilité de l'exécution distante sur `kingslanding` est elle-même une observation intéressante pour le projet : elle illustre qu'un DC durci peut activement gêner les outils d'attaque/administration à distance — un signal potentiellement détectable en soi (Phase 6).

## ✅ Confirmation — `winterfell` (DC02, north)

Contrairement à `kingslanding`, **`evil-winrm` fonctionne parfaitement sur `winterfell`** (déjà observé lors de l'attaque [Pass-the-Hash (09)](attaques/09-pass-the-hash.md)) — les 5 catégories ont donc été activées directement via WinRM, sans détour :

```
DS Access
  Directory Service Access                Success and Failure

Account Logon
  Kerberos Service Ticket Operations      Success and Failure
  Kerberos Authentication Service         Success and Failure

Object Access
  Certification Services                  Success and Failure

Detailed Tracking
  Process Creation                        Success
```

La SACL DCSync sur `DC=north,DC=sevenkingdoms,DC=local` a également été confirmée posée (`Allow Everyone → Replicating Directory Changes` / `...All` visibles dans la sortie `dsacls`).

### 🔒 Découverte additionnelle : RDP explicitement interdit aux Domain Admins sur winterfell

Contrairement à `kingslanding`, `winterfell` **refuse le RDP à tout compte membre de `Domain Admins`** (`"user account is not authorized for remote login"`, même après ajout au groupe et reconnexion). C'est une **vraie bonne pratique de durcissement** (protéger les comptes Tier-0 du vol d'identifiants via RDP) — ironiquement, elle a compliqué notre propre administration légitime du lab. Contournée en utilisant `evil-winrm` (qui, lui, fonctionne sur ce DC) plutôt que RDP.

> 🎯 **Bilan Phase 5 (activation) : les 2 DC de la forêt sont désormais entièrement audités** sur les 5 catégories ciblées, comblant la base technique des angles morts identifiés en Phase 4 (DCSync, Kerberoasting, AS-REP, ADCS ESC1, MSSQL RCE).

## 🎯 Règle custom #1 — DCSync détecté

### Le piège : DACL ≠ SACL

Première tentative avec `dsacls /G` : **échec silencieux**. `dsacls` ne modifie que la **DACL** (permissions), jamais la **SACL** (audit) — la réplication était déjà autorisée par les trusts existants, donc la commande "réussissait" sans jamais poser la moindre règle d'audit. Aucune Event 4662 n'apparaissait, ni dans Windows ni dans Wazuh.

**Solution correcte** — PowerShell avec le module `ActiveDirectory` et `Get-Acl -Audit` / `Set-Acl` :
```powershell
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$path = "AD:\DC=sevenkingdoms,DC=local"
$acl = Get-Acl -Path $path -Audit
$identity = New-Object System.Security.Principal.NTAccount("Everyone")
$replRight1 = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"   # Replicating Directory Changes
$replRight2 = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # Replicating Directory Changes All
$rule1 = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($identity,"ExtendedRight","Success",$replRight1)
$rule2 = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($identity,"ExtendedRight","Success",$replRight2)
$acl.AddAuditRule($rule1)
$acl.AddAuditRule($rule2)
Set-Acl -Path $path -AclObject $acl
```
Confirmé par `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4662} -MaxEvents 5` : **Windows génère bien l'Event 4662** après un DCSync.

### Le 2ᵉ piège : event reçu par Wazuh ≠ event alerté

Même avec le 4662 bien généré et remonté par l'agent (confirmé absent de la liste d'exclusion `<query>` de `ossec.conf`), **aucune alerte n'apparaissait** dans `wazuh-alerts-*`. Raison : cet index ne contient que les logs qui **matchent une règle** — sans règle dédiée, l'event est reçu par le manager mais jamais indexé comme alerte.

### La règle qui fonctionne

En s'alignant sur la structure des règles Windows par défaut (ex: la règle 60106 qui détecte les logons 4624/4769, chaînée sur `if_sid=60103` = "Windows audit success event") :

```xml
<group name="dcsync,attack,">
  <rule id="100010" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4662$</field>
    <description>Possible DCSync attack detected: AD replication rights used</description>
    <mitre>
      <id>T1003.006</id>
    </mitre>
    <group>dcsync,attack,</group>
  </rule>
</group>
```
*(fichier : `/var/ossec/etc/rules/local_rules.xml` sur la VM Wazuh)*

### Résultat — DCSync rejoué, alerte confirmée

```
rule.id: 100010
eventID: 4662
subjectUserName: tywin.lannister        ← l'attaquant identifié automatiquement
properties: {1131f6aa-...} {1131f6ad-...}  ← droits de réplication détectés
objectServer: DS · operationType: Object Access
```

**Le DCSync (attaque 06), angle mort critique de la Phase 4, est maintenant détecté.** 🟢

![3 hits confirmés : règle 100010 détecte le DCSync de tywin.lannister](screenshots/phase5/phase5-dcsync-rule-detected.png)

> 💡 **Piste d'amélioration :** la règle actuelle matche tout event 4662, y compris la réplication légitime entre DC. Pour affiner (moins de bruit, spécifique à un abus), ajouter un filtre sur `win.eventdata.properties` contenant les GUID de réplication **ET** `win.eventdata.subjectUserName` ne correspondant PAS à un compte machine DC (`$` final) — l'attaquant utilise un compte utilisateur, pas un compte ordinateur.

---

⬅️ Retour à la [simulation des attaques](03-attaques.md)
