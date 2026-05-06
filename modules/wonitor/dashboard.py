# modules/wonitor/dashboard.py
import streamlit as st
import pandas as pd
from collections import Counter
from core.models import UnifiedArticle, ModuleType

def render_wonitor(analyzer, articles, config):
    """Dashboard Wonitor : CVEs, Sévérité, Exploits, IOCs"""
    stats = analyzer.generate_stats()
    
    st.subheader("🐛 Top CVEs & Vulnérabilités")
    cve_counts = Counter()
    for a in articles:
        cve_counts.update(a.cves)
    df_cves = pd.DataFrame(cve_counts.most_common(10), columns=["CVE", "Occurrences"])
    st.dataframe(df_cves, use_container_width=True, height=300, hide_index=True)
    
    st.divider()
    
    # Distribution Sévérité
    st.subheader("📊 Distribution par Sévérité")
    sev_data = stats.get("by_severity", {})
    df_sev = pd.DataFrame(list(sev_data.items()), columns=["Niveau", "Count"])
    if not df_sev.empty:
        st.bar_chart(df_sev.set_index("Niveau"), color=["#dc2626", "#ea580c", "#ca8a04", "#059669", "#6b7280"][:len(df_sev)], height=250)
        
    st.divider()
    
    # Métriques Exploits / KEV
    c1, c2, c3 = st.columns(3)
    c1.metric("💣 Exploits dispo", sum(1 for a in articles if a.exploit_available))
    c2.metric("🛡️ KEV (CISA)", sum(1 for a in articles if a.in_kev))
    c3.metric("🔗 IOCs bruts", sum(len(a.iocs) for a in articles))
    
    # Export Threat Report
    if st.button("📋 Exporter Threat Report"):
        with st.spinner("Préparation..."):
            md = f"# 🛡️ Threat Intelligence Report\n\nTotal: {len(articles)}\nCritical: {sum(1 for a in articles if a.is_critical)}\n\n"
            md += "## 🔴 Menaces Critiques\n"
            for a in [x for x in articles if x.is_critical][:15]:
                md += f"- **{a.title}** ({a.source})\n  CVEs: `{', '.join(a.cves[:3])}` | Score: {a.score}\n"
            st.download_button("⬇️ Télécharger .md", md, file_name="threat_report.md", mime="text/markdown")