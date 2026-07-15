# 07 — LLMNR / NBT-NS Poisoning (Responder)

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access / Collection |
| **Technique MITRE** | T1557.001 |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Position sur le segment réseau (L2) |
| **Impact** | Élevé (capture de hashes Net-NTLMv2, relais possible) |

---

## 1. Description

Quand la résolution DNS échoue, Windows se rabat sur les protocoles de diffusion **LLMNR** (5355/UDP) et **NBT-NS** (137/UDP) — et fait confiance à **n'importe quelle réponse** du réseau local. Un attaquant (Responder) répond « c'est moi » aux requêtes de résolution, force la victime à s'authentifier vers lui, et **capture le hash Net-NTLMv2**. Ce hash peut être **cassé offline** ou **relayé** (voir fiche 17 NTLM Relay). Le trigger est souvent une faute de frappe de nom de partage.

## 2. Prérequis
- Accès au même segment L2/VLAN que les victimes.
- LLMNR/NBT-NS actifs (défaut Windows).

## 3. Procédure de simulation (lab)

```bash
# Responder — empoisonnement + capture
responder -I eth0 -wF

# Cassage offline du Net-NTLMv2 capturé
hashcat -m 5600 captured.hash rockyou.txt
```

## 4. Télémétrie générée (logs)

Difficile côté DC (attaque L2/endpoint). Sources utiles :
| Source | Event ID | Signification |
|--------|----------|---------------|
| Security (victime) | 4624 / 4625 | Logon/échec NTLM vers l'attaquant |
| Sysmon (victime) | 3 | Connexion réseau vers l'IP de l'attaquant sur 445 |
| NDR / Zeek | — | Trafic LLMNR/NBT-NS anormal, réponses multiples |

**Meilleure détection : réseau (NDR)** — un même hôte répondant à toutes les requêtes LLMNR.

## 5. Détection

### Logique
Détecter les **réponses LLMNR/NBT-NS incohérentes** (un hôte répond pour de nombreux noms) et le pic de Net-NTLM. **Honeypot** : émettre des requêtes LLMNR pour des noms inexistants et alerter si quelqu'un répond.

### Règle Sigma (endpoint honeypot / Sysmon réseau)
```yaml
title: LLMNR/NBT-NS Poisoning - Multiple Name Responses from Single Host
status: experimental
logsource:
    product: zeek
    service: dns
detection:
    selection:
        proto: 'udp'
        dst_port:
            - 5355
            - 137
    condition: selection | count(query) by src_ip > 10
level: high
```

### Traduction SIEM / NDR
- **Elastic :** dashboards sur `zeek` LLMNR ; alerte sur un `src_ip` répondant à > N noms.
- **QRadar / NDR :** flow rule sur réponses LLMNR/NBT-NS massives.

## 6. Contre-mesures / Hardening
- **Désactiver LLMNR** (GPO : *Turn off multicast name resolution*) et **NBT-NS** (DHCP option / registre).
- Segmentation réseau, port security.
- SMB signing (empêche le relais aval).

## 7. Features pour l'agent IA
- Nombre de noms distincts résolus par un même hôte via LLMNR/NBT-NS (feature réseau clé).
- Nouveauté de l'hôte comme « répondeur ».
- Corrélation avec pics d'authentification NTLM vers cet hôte.

## 8. Références
- https://attack.mitre.org/techniques/T1557/001/
- https://github.com/lgandx/Responder
