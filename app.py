import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime, timezone

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
        error=None
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

    if st.button("🚀 Lancer collecte"):
        st.session_state.collecting = True
        st.session_state.error = None

        with st.status("📡 Collecte en cours...", expanded=True) as status:
            try:
                cfg = load_config(st.session_state.active_module)

                status.write("🔄 Collecte des flux...")
                collector = UnifiedCollector(cfg, st.session_state.active_module)
                raw = collector.collect()

                status.write(f"📦 {len(raw)} items récupérés")

                analyzer = UnifiedAnalyzer(raw, st.session_state.active_module)

                status.write("🧠 Analyse...")
                filtered = analyzer.filter(max_items=40)

                st.session_state.articles = filtered
                st.session_state.analyzer = analyzer
                st.session_state.config = cfg
                st.session_state.last_update = datetime.now(timezone.utc)

                status.update(label="✅ Terminé", state="complete")

            except Exception as e:
                st.session_state.error = str(e)
                status.update(label="❌ Erreur", state="error")

        st.session_state.collecting = False
        st.rerun()

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
c3.metric("24h", stats.get("recent_24h", 0))
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
