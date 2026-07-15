# 36 — Timeroasting

| Champ | Valeur |
|-------|--------|
| **Tactique MITRE** | Credential Access |
| **Technique MITRE** | T1558 (adjacent) |
| **Phase kill chain** | Credential Access |
| **CVE** | — |
| **Privilèges requis** | Aucun (non authentifié) |
| **Impact** | Moyen à Élevé (cassage des mots de passe de comptes machine) |

---

## 1. Description

**Timeroasting** abuse l'**authentification NTP étendue de Windows** (MS-SNTP). Le service de temps d'un DC répond aux requêtes NTP en incluant un **MAC calculé à partir du hash du mot de passe du compte machine** dont le RID est fourni — **sans authentification préalable**. L'attaquant énumère les RID, collecte ces MAC, et les **casse hors-ligne** pour retrouver les mots de passe de comptes machine (souvent faibles pour de vieux systèmes, imprimantes, comptes non gérés). Technique récente et discrète (trafic NTP anodin).

## 2. Prérequis
- Accès réseau au service NTP du DC (123/UDP).
- Aucun compte requis.

## 3. Procédure de simulation (lab)

```bash
# Collecte des "hashs" NTP par RID
python3 timeroast.py 10.0.0.10 -o timeroast_hashes.txt

# Cassage offline (mode hashcat dédié)
hashcat -m 31300 timeroast_hashes.txt rockyou.txt
```

## 4. Télémétrie générée (logs)

| Source | Event ID | Signification |
|--------|----------|---------------|
| Réseau / NDR | — | **Rafale de requêtes NTP (123/UDP)** avec des RID variés vers le DC |
| Windows | (peu/pas de log natif) | MS-SNTP n'est généralement pas journalisé côté Security |

**Anomalie clé :** volume anormal de requêtes NTP authentifiées (MS-SNTP) énumérant des RID depuis une seule source → **détection surtout réseau (NDR)**.

## 5. Détection

### Logique
Le service Windows ne journalise quasiment pas MS-SNTP → la détection est **réseau** : repérer une source unique envoyant de nombreuses requêtes NTP « client authentifié » (extension MS-SNTP) au DC, balayant les RID.

### Règle Sigma (NDR / Zeek)
```yaml
title: Timeroasting - Enumeration of Machine RIDs via MS-SNTP
status: experimental
logsource:
    product: zeek
    service: ntp
detection:
    selection:
        dst_port: 123
        proto: 'udp'
        ext_auth: true          # MS-SNTP authenticated client request
    condition: selection | count() by src_ip > 50
    timeframe: 5m
level: medium
```

### Traduction SIEM
- **Elastic :** dashboards sur logs Zeek/NDR NTP ; alerte sur un `src_ip` émettant un fort volume de requêtes MS-SNTP.
- **NDR (Dataprotect) :** signature de balayage NTP authentifié.

## 6. Contre-mesures / Hardening
- **Mots de passe forts de comptes machine** (rotation par défaut 30j — ne pas désactiver).
- Restreindre l'accès NTP entrant sur les DC aux clients légitimes.
- Surveiller/limiter MS-SNTP au niveau réseau.

## 7. Features pour l'agent IA
- Volume de requêtes NTP MS-SNTP par source / fenêtre (feature réseau).
- Diversité des RID sondés (balayage).
- Nouveauté de la source comme client NTP authentifié massif.

## 8. Références
- https://www.secura.com/blog/timeroasting-attacking-trust-accounts-in-active-directory
- https://github.com/SecuraBV/Timeroast
