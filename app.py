import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime, timezone, timedelta

import networkx as nx
from pyvis.network import Network
import tempfile

from core.models import ModuleType
from core.collector import UnifiedCollector
from core.analyzer import UnifiedAnalyzer

from modules.stratwatch.dashboard import render_stratwatch
from modules.leakhunter.dashboard import render_leakhunter

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
st.set_page_config(page_title="StratIntel Hub", layout="wide")

# ─────────────────────────────────────────────
# SESSION INIT
# ─────────────────────────────────────────────
def init():
    defaults = dict(
        active_module=ModuleType.WONITOR,
        articles=[],
        analyzer=None,
        config=None,
        collecting=False,
        error=None,
        # Nouveaux paramètres de collecte
        collect_max_items=40,
        collect_timeframe_hours=0,  # 0 = illimité
        collect_critical_only=False,
        collect_enabled_sources=None,  # None = toutes
        collect_min_score=0,
        collect_enable_dedup=True
    )
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init()

# ─────────────────────────────────────────────
# CONFIG LOADER
# ─────────────────────────────────────────────
CONFIG_PATHS = {
    ModuleType.WONITOR: Path("wonitor_config.json"),
    ModuleType.STRATWATCH: Path("stratwatch_config.json"),
    ModuleType.LEAKHUNTER: Path("leak_intel_config.json")
}

def load_config(mod):
    path = CONFIG_PATHS[mod]
    if not path.exists():
        st.error(f"Config manquante : {path}")
        st.stop()
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def get_all_sources_from_config(config):
    """Extrait toutes les sources (nom + catégorie) d'une config"""
    sources = []
    for cat in config.get("categories", []):
        cat_name = cat.get("name", "Sans catégorie")
        for feed in cat.get("feeds", []):
            feed_name = feed.get("name", "Unknown")
            sources.append({
                "name": feed_name,
                "category": cat_name,
                "url": feed.get("url", "")
            })
    return sources

# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.title("⚡ StratIntel")

    mod = st.radio("Module", [m.value for m in ModuleType])

    if mod != st.session_state.active_module.value:
        st.session_state.active_module = ModuleType(mod)
        st.session_state.articles = []
        st.session_state.analyzer = None
        st.rerun()

    st.divider()
    st.markdown("### ⚙️ Paramètres de collecte")

    # Nombre max d'articles
    max_items = st.slider("📦 Max articles", 10, 200, st.session_state.collect_max_items, 10)
    st.session_state.collect_max_items = max_items

    # Filtre temporel
    timeframe_options = {
        "Illimité": 0,
        "24h": 24,
        "48h": 48,
        "7 jours": 168,
        "30 jours": 720
    }
    selected_tf = st.selectbox("⏱️ Profondeur temporelle", list(timeframe_options.keys()))
    st.session_state.collect_timeframe_hours = timeframe_options[selected_tf]

    # Filtre critique
    critical_only = st.checkbox("🔥 Uniquement les alertes critiques", st.session_state.collect_critical_only)
    st.session_state.collect_critical_only = critical_only

    # Score minimum
    min_score = st.slider("🎯 Score minimum (0-100)", 0, 100, st.session_state.collect_min_score, 5)
    st.session_state.collect_min_score = min_score

    # Déduplication
    dedup = st.checkbox("🔁 Déduplication active", st.session_state.collect_enable_dedup)
    st.session_state.collect_enable_dedup = dedup

    st.divider()

    # Sélection des sources (chargée dynamiquement)
    if st.button("📡 Recharger la liste des sources"):
        try:
            cfg = load_config(st.session_state.active_module)
            st.session_state.available_sources = get_all_sources_from_config(cfg)
        except Exception as e:
            st.error(f"Erreur chargement sources: {e}")

    if "available_sources" not in st.session_state:
        try:
            cfg = load_config(st.session_state.active_module)
            st.session_state.available_sources = get_all_sources_from_config(cfg)
        except:
            st.session_state.available_sources = []

    if st.session_state.available_sources:
        with st.expander("📡 Filtrer par sources", expanded=False):
            source_names = [f"{s['category']} › {s['name']}" for s in st.session_state.available_sources]
            selected_sources = st.multiselect(
                "Sources à inclure (vide = toutes)",
                options=source_names,
                default=st.session_state.collect_enabled_sources if st.session_state.collect_enabled_sources else []
            )
            st.session_state.collect_enabled_sources = selected_sources if selected_sources else None

    st.divider()

    # Bouton de lancement
    if st.button("🚀 Lancer collecte", type="primary"):
        st.session_state.collecting = True
        st.session_state.error = None

        with st.status("📡 Collecte en cours...", expanded=True) as status:
            try:
                cfg = load_config(st.session_state.active_module)

                # Application des filtres de collecte à la config
                if st.session_state.collect_enabled_sources:
                    status.write("🎯 Filtrage par sources sélectionnées...")
                    # Filtre les catégories et feeds selon la sélection
                    filtered_cats = []
                    selected_names = set(st.session_state.collect_enabled_sources)
                    for cat in cfg.get("categories", []):
                        cat_name = cat.get("name", "Sans catégorie")
                        filtered_feeds = []
                        for feed in cat.get("feeds", []):
                            feed_name = feed.get("name", "Unknown")
                            label = f"{cat_name} › {feed_name}"
                            if label in selected_names:
                                filtered_feeds.append(feed)
                        if filtered_feeds:
                            filtered_cat = cat.copy()
                            filtered_cat["feeds"] = filtered_feeds
                            filtered_cats.append(filtered_cat)
                    cfg["categories"] = filtered_cats

                # Ajustement du max_items par feed en fonction du max global
                for cat in cfg.get("categories", []):
                    for feed in cat.get("feeds", []):
                        feed["max_items"] = min(
                            feed.get("max_items", st.session_state.collect_max_items),
                            st.session_state.collect_max_items
                        )

                status.write("🔄 Collecte des flux...")
                collector = UnifiedCollector(cfg, st.session_state.active_module)
                raw = collector.collect()

                status.write(f"📦 {len(raw)} items récupérés")

                # Filtrage temporel (si demandé)
                if st.session_state.collect_timeframe_hours > 0:
                    cutoff = datetime.now(timezone.utc) - timedelta(hours=st.session_state.collect_timeframe_hours)
                    raw = [a for a in raw if a.published >= cutoff]
                    status.write(f"⏱️ Filtre temporel: {len(raw)} articles restants")

                analyzer = UnifiedAnalyzer(raw, st.session_state.active_module)

                # Filtrage par score minimum
                if st.session_state.collect_min_score > 0:
                    raw = [a for a in raw if a.score >= st.session_state.collect_min_score]
                    status.write(f"🎯 Score ≥ {st.session_state.collect_min_score}: {len(raw)} articles")

                if st.session_state.collect_critical_only:
                    raw = [a for a in raw if a.is_critical]
                    status.write(f"🔥 Filtre critiques: {len(raw)} articles")

                # Filtrage final (max_items)
                filtered = raw[:st.session_state.collect_max_items]

                # Déduplication
                if st.session_state.collect_enable_dedup and hasattr(analyzer, '_deduplicate'):
                    filtered = analyzer.filter(max_items=st.session_state.collect_max_items)

                st.session_state.articles = filtered
                st.session_state.analyzer = analyzer
                st.session_state.config = cfg
                st.session_state.last_update = datetime.now(timezone.utc)

                # Sauvegarde des erreurs de collecte
                if hasattr(collector, 'collection_errors') and collector.collection_errors:
                    st.session_state.collect_errors = collector.collection_errors[:5]

                status.update(label="✅ Terminé", state="complete")

            except Exception as e:
                st.session_state.error = str(e)
                status.update(label="❌ Erreur", state="error")

        st.session_state.collecting = False
        st.rerun()

    # Affichage des erreurs de collecte
    if st.session_state.get("collect_errors"):
        with st.expander("⚠️ Erreurs de collecte", expanded=False):
            for err in st.session_state.collect_errors:
                st.caption(err)

    # Métadonnées de la dernière collecte
    if st.session_state.get("last_update"):
        st.caption(f"🕐 Dernière collecte: {st.session_state.last_update.strftime('%d/%m %H:%M:%S')} UTC")

# ─────────────────────────────────────────────
# SAFE ZONE
# ─────────────────────────────────────────────
if st.session_state.collecting:
    st.stop()

if st.session_state.error:
    st.error(st.session_state.error)
    st.stop()

if not st.session_state.articles:
    st.info("👈 Lance une collecte depuis la sidebar")
    st.stop()

analyzer = st.session_state.analyzer
arts = st.session_state.articles

if analyzer is None:
    st.warning("Analyzer non initialisé")
    st.stop()

# ─────────────────────────────────────────────
# HEADER SOC
# ─────────────────────────────────────────────
st.title("🛡️ Wonitor SOC Dashboard")

stats = analyzer.generate_stats()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events", len(arts))
c2.metric("Critical", stats.get("critical", 0))
c3.metric("Score avg", f"{sum(a.score for a in arts)//len(arts) if arts else 0}")
c4.metric("CVEs", len(stats.get("top_cves", [])))

st.divider()

# ─────────────────────────────────────────────
# SEVERITY (FIX)
# ─────────────────────────────────────────────
sev = stats.get("by_severity", {})
df_sev = pd.DataFrame(list(sev.items()), columns=["Severity", "Count"])

if not df_sev.empty:
    chart = alt.Chart(df_sev).mark_bar().encode(
        x="Severity",
        y="Count",
        color=alt.Color("Severity", scale=alt.Scale(
            domain=["critical", "high", "medium", "low"],
            range=["#dc2626", "#ea580c", "#ca8a04", "#059669"]
        ))
    )
    st.altair_chart(chart, use_container_width=True)

# ─────────────────────────────────────────────
# CVE TIMELINE
# ─────────────────────────────────────────────
timeline = []

for a in arts:
    for cve in getattr(a, "cves", []):
        timeline.append({
            "time": a.published,
            "cve": cve
        })

df_time = pd.DataFrame(timeline)

if not df_time.empty:
    df_time["time"] = pd.to_datetime(df_time["time"])

    chart = alt.Chart(df_time).mark_line(point=True).encode(
        x="time:T",
        y="count():Q",
        tooltip=["cve"]
    )

    st.subheader("📡 CVE Activity Timeline")
    st.altair_chart(chart, use_container_width=True)

# ─────────────────────────────────────────────
# GRAPH THREAT INTEL
# ─────────────────────────────────────────────
def build_threat_graph(articles):
    G = nx.Graph()

    for a in articles:
        cves = getattr(a, "cves", [])
        actors = getattr(a, "actors", [])
        malwares = getattr(a, "malwares", [])

        if not malwares:
            malwares = [a.source]

        for cve in cves:
            G.add_node(cve, label=cve, color="red", size=20)

            for m in malwares:
                G.add_node(m, label=m, color="purple", size=15)
                G.add_edge(cve, m)

                for act in actors:
                    G.add_node(act, label=act, color="orange", size=15)
                    G.add_edge(m, act)

    return G

def render_graph(G):
    net = Network(height="550px", width="100%", bgcolor="#0e1117", font_color="white")

    for node, data in G.nodes(data=True):
        net.add_node(node, **data)

    for edge in G.edges():
        net.add_edge(edge[0], edge[1])

    net.repulsion(node_distance=120, central_gravity=0.3)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
    net.save_graph(tmp.name)

    with open(tmp.name, "r", encoding="utf-8") as f:
        html = f.read()

    st.subheader("🕸️ Threat Intelligence Graph")
    st.components.v1.html(html, height=600)

G = build_threat_graph(arts)

if len(G.nodes) > 0:
    render_graph(G)
else:
    st.info("Pas assez de données pour générer le graphe.")

# ─────────────────────────────────────────────
# TABLE AVEC LIENS
# ─────────────────────────────────────────────
df = pd.DataFrame([{
    "Titre": a.title,
    "Score": a.score,
    "Sévérité": a.severity.value,
    "Source": a.source,
    "Lien": a.link
} for a in arts])

st.data_editor(
    df,
    column_config={"Lien": st.column_config.LinkColumn("Lien")},
    use_container_width=True,
    hide_index=True
)

# ─────────────────────────────────────────────
# ALERTES
# ─────────────────────────────────────────────
crit = [a for a in arts if a.is_critical][:5]

if crit:
    st.subheader("🚨 Alertes critiques")
    for a in crit:
        st.markdown(f"**[{a.title}]({a.link})**")

# ─────────────────────────────────────────────
# MODULES
# ─────────────────────────────────────────────
mod = st.session_state.active_module

if mod == ModuleType.STRATWATCH:
    render_stratwatch(analyzer, arts, st.session_state.config)

elif mod == ModuleType.LEAKHUNTER:
    render_leakhunter(analyzer, arts, st.session_state.config)
