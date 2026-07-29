# 📊 Spectre de détection — synthèse des 12 attaques

> Vue d'ensemble transversale de la Phase 4 : pour chaque attaque, le statut de détection Wazuh et la leçon qu'elle illustre. Utile pour la soutenance comme résumé exécutif.

---

## 🟢 Détecté (2/12)

| # | Attaque | Signal détecté |
|---|---------|----------------|
| 05 | Password Spraying | Rafale d'Event 4625 (échecs de connexion) |
| 07 | Abus d'ACL | Event 4728 (ajout à Domain Admins) |

**Leçon :** les signaux **volumétriques** (spray) et les **actions sur groupes privilégiés** (ACL) sont bien couverts par les règles Wazuh par défaut.

## 🟡 Partiel / Anomalie détectable (4/12)

| # | Attaque | Ce qui est visible |
|---|---------|---------------------|
| 01 | Kerberoasting | Connexion attaquant vue (alerte niveau 6), mais pas le motif RC4 précis |
| 09 | Pass-the-Hash | Connexions NTLM visibles (4624) mais non alertées |
| 11 | Golden Ticket | Compte forgé inexistant + incohérence nom/SID dans les logons |
| 12 | Abus de trust | Compte forgé `hacker` (RID 500) visible sur le DC parent |

**Leçon :** les tickets **forgés** sont cryptographiquement valides donc invisibles aux règles de signature — mais laissent des **anomalies comportementales** (comptes inexistants, incohérences SID) détectables par une approche IA (Phase 6).

## 🔴 Angle mort (6/12)

| # | Attaque | Pourquoi invisible |
|---|---------|---------------------|
| 02 | AS-REP Roasting | Audit Kerberos (4768) non activé |
| 03 | Énumération | Audit Directory Service Access (4662) non activé |
| 04 | LLMNR Poisoning | Attaque réseau, jamais journalisée côté DC |
| 06 | DCSync | Audit réplication (4662) non activé — **compromission totale invisible** |
| 08 | ADCS ESC1 | Audit ADCS (4886/4887) + Kerberos (4768) non activés — **forêt entière invisible** |
| 10 | MSSQL RCE | Audit création de processus (4688) non activé |

**Leçon centrale du projet :** la majorité des angles morts ne viennent **pas** d'une faiblesse de Wazuh, mais de **catégories d'audit Windows désactivées par défaut**. C'est le constat qui motive la **Phase 5** (activation des audits + règles custom).

---

## 🎯 Conclusion

```
12 attaques  →  2 détectées  +  4 partielles  +  6 angles morts
```

Un SIEM par défaut, même bien déployé, **ne suffit pas** face à un attaquant qui connaît les techniques AD modernes (ADCS, DCSync, forge de tickets). La détection efficace nécessite :
1. **Des audits activés** sur les bonnes catégories (Phase 5)
2. **Des règles custom** ciblant les signatures spécifiques (Phase 5)
3. **Une détection comportementale/IA** pour les anomalies non signature-based (Phase 6)

---

⬅️ Retour à la [simulation des attaques](03-attaques.md)
