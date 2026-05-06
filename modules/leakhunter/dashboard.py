# modules/leakhunter/dashboard.py
import streamlit as st
import pandas as pd
from collections import Counter
from core.models import UnifiedArticle, ModuleType

def render_leakhunter(analyzer, articles, config):
    """Dashboard LeakHunter : Fuites, PII, Ransomware, Dark Web"""
    stats = analyzer.generate_stats()
    
    st.subheader("💧 Analyse des Fuites de Données")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📦 Leaks détectés", sum(1 for a in articles if a.leak_records))
    c2.metric("🔑 Types PII", len(set(p for a in articles for p in a.pii_types)))
    c3.metric("🌑 Dark Web", sum(1 for a in articles if a.dark_web_mentioned))
    c4.metric("⛓️ Extortion", sum(1 for a in articles if a.extortion_related))
    
    st.divider()
    
    # Top Types PII
    st.subheader("🔓 Données Exposées (PII)")
    pii_counts = Counter()
    for a in articles:
        pii_counts.update(a.pii_types)
    df_pii = pd.DataFrame(pii_counts.most_common(8), columns=["Type de donnée", "Occurrences"])
    st.dataframe(df_pii, use_container_width=True, height=250, hide_index=True)
    
    # Entreprises ciblées
    st.subheader("🏢 Entreprises/Organisations Mentionnées")
    companies = [a.company_mentioned for a in articles if a.company_mentioned]
    if companies:
        comp_counts = Counter(companies)
        df_comp = pd.DataFrame(comp_counts.most_common(6), columns=["Entité", "Citations"])
        st.dataframe(df_comp, use_container_width=True, height=200, hide_index=True)
    else:
        st.info("Aucune entreprise spécifiquement identifiée dans ce lot.")
        
    st.divider()
    
    # Ransomware Focus
    st.subheader("💀 Menaces Ransomware")
    ransom_articles = [a for a in articles if a.ransomware_related]
    if ransom_articles:
        st.warning(f"{len(ransom_articles)} articles liés à des ransomwares actifs")
        for a in ransom_articles[:5]:
            st.caption(f"**{a.title}** | Score: {a.score} | Source: {a.source}")
            if a.leak_records: st.caption(f"Volume: `{a.leak_records}`")
    else:
        st.success("Aucune activité ransomware détectée dans la fenêtre actuelle.")
        
    # Export Leak Report
    if st.button("📋 Exporter Rapport Data Leaks"):
        with st.spinner("Génération..."):
            md = "# 🔓 Rapport Data Leaks\n\n"
            md += f"Articles analysés : {len(articles)}\nFuites confirmées : {sum(1 for a in articles if a.leak_records)}\n\n"
            md += "## 🚨 Fuites Prioritaires\n"
            for a in sorted([x for x in articles if x.leak_records or x.pii_types], key=lambda x: -x.score)[:10]:
                md += f"- **[{a.score}]** {a.title}\n  PII: `{', '.join(a.pii_types[:3])}` | Records: `{a.leak_records}`\n"
            st.download_button("⬇️ Télécharger .md", md, file_name="leak_report.md", mime="text/markdown")