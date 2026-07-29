# 📖 Glossaire — Active Directory & Kerberos

> Définitions courtes des termes techniques utilisés dans les fiches d'attaques, pour une lecture autonome du rapport.

---

## Active Directory (AD)

| Terme | Définition |
|---|---|
| **AD** | Annuaire centralisé de Microsoft qui gère utilisateurs, groupes, machines et permissions dans un réseau d'entreprise. |
| **Domaine** | Unité administrative de base d'AD (ex: `sevenkingdoms.local`), avec ses propres comptes et politiques. |
| **Forêt** | Ensemble de domaines liés par des **trusts**, partageant un schéma commun (ex: `sevenkingdoms.local` + `north.sevenkingdoms.local`). |
| **Domaine parent / enfant** | Dans une forêt, un domaine enfant hérite d'un trust automatique avec son parent (relation hiérarchique). |
| **DC (Domain Controller)** | Serveur qui héberge l'annuaire et authentifie les utilisateurs (ex: `kingslanding`, `winterfell`). |
| **SID (Security Identifier)** | Identifiant unique d'un compte ou groupe (ex: `S-1-5-21-...-500` = Administrator). Le suffixe **RID** (`-500`, `-512`...) identifie le compte/groupe dans le domaine. |
| **ACL / ACE** | Liste de contrôle d'accès d'un objet AD ; chaque **ACE** est une permission individuelle (ex: `GenericAll`, `WriteDacl`). |
| **Trust** | Relation de confiance entre deux domaines permettant l'authentification croisée. |
| **SID History / SID Filtering** | Champ transportant les SID hérités d'un compte migré ; le **filtrage** le supprime entre forêts mais **pas** entre domaines d'une même forêt (faille exploitée en [attaque 12](attaques/12-trust-inter-domaine.md)). |

## Kerberos

| Terme | Définition |
|---|---|
| **KDC** | Service du DC qui délivre les tickets Kerberos (authentification). |
| **TGT (Ticket Granting Ticket)** | "Badge maître" obtenu après authentification, signé par le compte **krbtgt**. |
| **TGS (Ticket Granting Service)** | Ticket de service, obtenu avec le TGT, pour accéder à une ressource précise. |
| **krbtgt** | Compte spécial dont le hash sert à signer tous les TGT du domaine — sa compromission permet de forger des tickets ([Golden Ticket](attaques/11-golden-ticket.md)). |
| **SPN (Service Principal Name)** | Identifiant d'un service Kerberos (ex: `MSSQLSvc/...`) ; les comptes de service avec SPN sont ciblés par le [Kerberoasting](attaques/01-kerberoasting.md). |
| **PKINIT** | Extension Kerberos permettant l'authentification par **certificat** plutôt que par mot de passe (exploitée en [ADCS ESC1](attaques/08-adcs-esc1.md)). |
| **Pré-authentification** | Étape optionnelle où le client prouve connaître le mot de passe avant de recevoir un TGT ; désactivée = [AS-REP Roasting](attaques/02-asrep-roasting.md) possible. |

## Protocoles & mécanismes d'attaque

| Terme | Définition |
|---|---|
| **NTLM** | Protocole d'authentification par hash (v1 cassé, v2 plus robuste mais toujours attaquable hors ligne). |
| **Pass-the-Hash (PtH)** | S'authentifier avec le **hash** d'un mot de passe plutôt qu'avec le mot de passe en clair. |
| **DCSync** | Abus du protocole de réplication AD (droits `Replicating Directory Changes`) pour extraire tous les hashs du domaine sans toucher au DC physiquement. |
| **LLMNR / NBT-NS** | Protocoles de résolution de noms de secours (si le DNS échoue) ; un attaquant peut y répondre à la place du vrai serveur ([LLMNR Poisoning](attaques/04-llmnr-poisoning.md)). |
| **ADCS (AD Certificate Services)** | Autorité de certification interne d'AD ; un certificat mal configuré peut permettre l'usurpation d'identité ([ESC1](attaques/08-adcs-esc1.md)). |
| **xp_cmdshell** | Procédure stockée SQL Server permettant d'exécuter des commandes système ([MSSQL RCE](attaques/10-mssql-rce.md)). |

## SIEM & détection

| Terme | Définition |
|---|---|
| **SIEM** | Security Information and Event Management — plateforme centralisant et analysant les logs de sécurité (ici, **Wazuh**). |
| **Event ID** | Identifiant numérique d'un type d'événement Windows (ex: `4624` = connexion réussie, `4662` = accès à un objet AD). |
| **Audit Policy** | Configuration Windows décidant quelles actions génèrent un événement dans les journaux. Sans elle, l'action se produit mais n'est **jamais journalisée**. |
| **Angle mort (blind spot)** | Attaque qui se produit sans générer aucune trace exploitable dans le SIEM (souvent par audit non activé). |
| **Règle de détection** | Logique (Wazuh, Sigma...) qui transforme un ou plusieurs événements en **alerte** exploitable par un analyste. |

---

⬅️ Retour à la [simulation des attaques](03-attaques.md)
