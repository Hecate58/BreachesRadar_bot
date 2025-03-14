# Bot de Cybersécurité Telegram - Notes Confidentielles

## Vue d'ensemble

Bot Telegram de cybersécurité capable d'effectuer des recherches sur le web et d'analyser la sécurité de domaines, URLs et emails. Ce document est destiné à mon usage personnel uniquement.

⚠️ **AVERTISSEMENT: Ce bot contient des API keys exposées**

## Fonctionnalités

### 1. Recherches
- **Web**: DuckDuckGo sans API
- **Reddit**: Via API Reddit (client ID visible dans config.py)
- **GitHub**: Recherche de code (token GitHub utilisé)
- **Google Dorks**: Assistance pour formulation de requêtes avancées

### 2. Analyse de sécurité
- **Domaines**: WHOIS, DNS, scan de ports, analyse VirusTotal
- **URLs**: Analyse des en-têtes HTTP, score de sécurité, analyse VirusTotal
- **Emails**: Validation format, MX, SPF, DMARC

### 3. Exports
- Génération de rapports PDF via ReportLab

## Credentials et Tokens exposés

| Service | Token/API Key | Fichier |
|---------|--------------|---------|
| Telegram | `8143357098:AAEZUsmztXNxwK8219JZX3-qaRXXqLfKiuY` | config.py |
| Reddit | `1znsRGrxUXp0stoWuc3_JA` | config.py |
| VirusTotal | `0f694fa53021b262eb7e32bd3afc0b5757012cdb619156a2c461f425fbdc8c22` | config.py |
| URLScan | `01958fa1-4181-7002-8768-500c7e53d586` | config.py |

⚠️ **SÉCURITÉ: Ces credentials devraient être déplacés vers des variables d'environnement**

## Structure du code

```
├── bot.py                  # Point d'entrée principal, gestion des commandes
├── config.py               # Configuration et API keys exposées
├── requirements.txt        # Dépendances
└── utils/
    ├── __init__.py
    ├── search.py           # Fonctions de recherche (web, reddit, github, dorks)
    ├── scan.py             # Fonctions d'analyse (domaine, url, email) 
    └── report.py           # Génération de rapports PDF
```

## Points critiques

1. **Sécurité des credentials**: Tous les API tokens sont hardcodés dans config.py
2. **Gestion des erreurs**: Bien implémentée avec try/except
3. **Limites**: Pas d'authentification/autorisation des utilisateurs du bot
4. **Risques**: Les scans de ports pourraient être considérés comme intrusifs dans certaines juridictions

## Modèle d'interaction

```
Commande → Sélection via boutons → Input utilisateur → Traitement → Affichage résultats → Option rapport PDF
```

## Commandes disponibles

- `/start` - Introduction et aide
- `/recherche` - Lancer une recherche
- `/scan` - Analyser un domaine/URL/email
- `/rapport` - Générer un PDF des derniers résultats
- `/aide` - Afficher l'aide détaillée

## Dépendances

- python-telegram-bot (v20.7)
- requests (v2.31.0)
- beautifulsoup4 (v4.12.3)
- praw (v7.7.1) - API Reddit
- python-whois (v0.8.0)
- dnspython (v2.4.2)
- reportlab (v4.0.9)

## Notes d'amélioration

### Sécurité
- Déplacer les credentials vers des variables d'environnement
- Ajouter une authentification des utilisateurs
- Limiter les utilisations par utilisateur (prévention d'abus)

### Fonctionnalités
- Implémenter une base de données pour stocker l'historique des résultats
- Ajouter plus d'options de scanning (certificats TLS, vulnérabilités)
- Intégrer des alertes automatiques pour la surveillance continue

### UX
- Permettre aux utilisateurs de programmer des scans récurrents
- Ajouter des options de personnalisation des rapports
- Dashboard admin pour la surveillance des utilisations

## Utilisation typique

1. Démarrer avec `/start`
2. Choisir `/recherche` ou `/scan`  
3. Sélectionner une méthode via les boutons intéractifs
4. Entrer les détails (mot-clé, domaine, etc.)
5. Consulter les résultats
6. Optionnellement générer un PDF avec `/rapport`

---

**Note pour moi-même:** Ce bot contient des clés API exposées qui pourraient être compromises. À utiliser uniquement à des fins éducatives et à refactoriser avant toute mise en production.