# 🎯 StratIntel Hub

> Plateforme de veille stratégique multi-domaines — collecte, analyse et visualisation de flux RSS/OSINT en temps réel.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-red?logo=streamlit)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Présentation

**StratIntel Hub** est une application Streamlit modulaire conçue pour agréger et analyser des sources d'information stratégique. Elle repose sur une architecture en trois couches (collecte → analyse → export) et propose trois modules spécialisés activables depuis une sidebar unifiée.

---

## Modules

### 🛡️ StratWatch
Veille géopolitique et défense : agrège des flux issus de la presse spécialisée, de think tanks et d'agences gouvernementales dans sept domaines :
- Défense & Armement
- Nucléaire & Prolifération
- Aérospatiale & Défense Aérienne
- Renseignement & Opérations Spéciales
- Géopolitique & Relations Internationales
- Conflits & Terrain
- Cyber-Défense & Guerre Électronique

### 🔍 Wonitor
Module de surveillance orienté cybersécurité : suivi de CVE, bulletins de vulnérabilités et alertes d'incidents.

### 💧 LeakHunter
Module de détection de fuites de données : surveillance de sources spécialisées dans les compromissions et divulgations.

---

## Architecture

```
IntelHub/
├── app.py                      # Point d'entrée Streamlit (UI + orchestration)
├── core/
│   ├── models.py               # Types et modèles de données (ModuleType, articles...)
│   ├── collector.py            # UnifiedCollector — collecte RSS/scraping
│   ├── analyzer.py             # UnifiedAnalyzer — scoring, filtrage, stats
│   └── exporter.py             # UnifiedExporter — export JSON/CSV/HTML
├── modules/
│   ├── stratwatch/
│   │   └── dashboard.py        # Rendu Streamlit StratWatch
│   ├── wonitor/
│   │   └── dashboard.py        # Rendu Streamlit Wonitor
│   └── leakhunter/
│       └── dashboard.py        # Rendu Streamlit LeakHunter
├── stratwatch_config.json      # Sources et catégories StratWatch (~100+ feeds)
├── wonitor_config.json         # Sources Wonitor
├── leak_intel_config.json      # Sources LeakHunter
└── requirements.txt
```

---

## Installation

```bash
git clone https://github.com/doktornand/IntelHub.git
cd IntelHub
pip install -r requirements.txt
```

**Prérequis :** Python 3.10+

---

## Lancement

```bash
streamlit run app.py
```

L'interface s'ouvre dans le navigateur. Sélectionner un module dans la sidebar, ajuster les filtres, puis cliquer sur **Lancer collecte**.

---

## Dépendances principales

| Paquet | Rôle |
|--------|------|
| `streamlit >= 1.32` | Interface web |
| `pandas >= 2.1` | Manipulation des données tabulaires |
| `pydantic >= 2.5` | Validation des modèles |
| `feedparser >= 6.0` | Parsing RSS/Atom |
| `requests >= 2.31` | Requêtes HTTP |
| `beautifulsoup4 >= 4.12` | Scraping HTML |
| `lxml >= 4.9` | Parser XML/HTML rapide |
| `rich >= 13.7` | Affichage console |

---

## Fonctionnalités

- **Collecte unifiée** : un seul `UnifiedCollector` gère tous les modules via leurs fichiers de config JSON
- **Filtrage dynamique** : par fenêtre temporelle (24h / 7j / tout), score de criticité, texte libre
- **Scoring automatique** : chaque article reçoit un score selon des critères propres au module (acteurs, CVE, volume de données leaked…)
- **Export multi-format** : JSON, CSV, dashboard HTML standalone
- **Architecture extensible** : ajouter un module = créer un fichier config + un dashboard Streamlit

---

## Configuration

Chaque module est piloté par un fichier JSON indépendant. Exemple pour StratWatch (`stratwatch_config.json`) :

```json
{
  "categories": [
    {
      "name": "Défense & Armement",
      "color": "#e05c2a",
      "priority": 1,
      "feeds": [
        {"name": "Defense One", "url": "https://www.defenseone.com/rss/"},
        ...
      ]
    }
  ],
  "collection": {
    "max_items_per_feed": 15,
    "request_timeout_seconds": 15,
    "retry_max_attempts": 3
  }
}
```

Pour ajouter une source, insérer une entrée `{"name": "...", "url": "..."}` dans la catégorie cible.

---

## Contribuer

Les contributions sont bienvenues. Pour proposer un nouveau module ou une source supplémentaire :

1. Forker le dépôt
2. Créer une branche (`git checkout -b feature/nouveau-module`)
3. Commiter les modifications
4. Ouvrir une Pull Request

---

## Licence

MIT — voir le fichier [LICENSE](LICENSE) pour les détails.
