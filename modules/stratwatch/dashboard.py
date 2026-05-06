# modules/stratwatch/dashboard.py
import streamlit as st
import pandas as pd
from core.models import UnifiedArticle, ModuleType

def render_stratwatch(analyzer, articles, config):
    """Dashboard StratWatch : Acteurs, Théâtres, Flags stratégiques"""
    stats = analyzer.generate_stats()
    
    c1, c2, c3 = st.columns(3)
    c1.metric("⚔ Conflits", stats["module_flags"].get("conflict", 0))
    c2.metric("🚀 Aérospatial", stats["module_flags"].get("aerospace", 0))
    c3.metric("🔍 Intel", sum(1 for a in articles if any(x in f"{a.title} {a.summary}".lower() for x in ["intelligence", "renseignement", "osint", "classified"])))
    
    st.divider()
    
    # Top Acteurs
    st.subheader("🌍 Top Acteurs Géopolitiques")
    actor_counts = {}
    for a in articles:
        for act in a.actors:
            actor_counts[act] = actor_counts.get(act, 0) + 1
    df_actors = pd.DataFrame(sorted(actor_counts.items(), key=lambda x: -x[1])[:8], columns=["Acteur", "Mentions"])
    st.bar_chart(df_actors.set_index("Acteur"), height=200)
    
    # Top Théâtres
    st.subheader("🗺️ Répartition par Théâtre")
    theatre_counts = {}
    for a in articles:
        for th in a.theatres:
            theatre_counts[th] = theatre_counts.get(th, 0) + 1
    df_th = pd.DataFrame(sorted(theatre_counts.items(), key=lambda x: -x[1])[:6], columns=["Théâtre", "Signaux"])
    st.dataframe(df_th, use_container_width=True, height=250, hide_index=True)
    
    # Export Rapport
    if st.button("📋 Générer Rapport STRATINT"):
        with st.spinner("Génération..."):
            md = "# 📊 Rapport STRATINT\n"
            md += f"Généré le : {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}\n\n"
            md += f"Total : {len(articles)} | Critiques : {sum(1 for a in articles if a.is_critical)}\n\n"
            md += "## 🚨 Alertes Prioritaires\n"
            for a in sorted(articles, key=lambda x: -x.score)[:10]:
                md += f"- **[{a.score}]** {a.title} ({a.source})\n"
            st.download_button("⬇️ Télécharger .md", md, file_name="stratint_report.md", mime="text/markdown")