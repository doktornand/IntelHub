# core/exporter.py
import json
import csv
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from core.models import UnifiedArticle, ModuleType
from core.config import ModuleConfig

class UnifiedExporter:
    """Exporteur unifié multi-format pour les articles normalisés"""
    
    def __init__(self, articles: List[UnifiedArticle], config: ModuleConfig, module: ModuleType):
        self.articles = articles
        self.config = config
        self.module = module
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.base_dir = Path(".")
        
    def _resolve_path(self, fmt: str, custom_path: Optional[str] = None) -> Path:
        """Résout le chemin d'export depuis la config ou un chemin personnalisé"""
        if custom_path:
            return Path(custom_path)
        
        cfg_path = self.config.export.paths.get(fmt, f"stratintel_export_{fmt}.{fmt}")
        # Ajoute timestamp si plusieurs exports par jour
        stem = Path(cfg_path).stem
        suffix = Path(cfg_path).suffix
        return self.base_dir / f"{stem}_{self.timestamp}{suffix}"
    
    def _flatten_article(self, art: UnifiedArticle) -> Dict[str, Any]:
        """Aplatissement pour CSV/Markdown avec champs module-aware"""
        row = {
            "published": art.published.strftime("%Y-%m-%d %H:%M:%S"),
            "module": art.module.value,
            "category": art.category,
            "source": art.source,
            "title": art.title,
            "link": art.link,
            "severity": art.severity.value,
            "score": art.score,
            "summary": art.summary[:300] + ("..." if len(art.summary) > 300 else "")
        }
        
        # Champs spécifiques StratWatch
        if self.module == ModuleType.STRATWATCH:
            row["actors"] = "|".join(art.actors[:5])
            row["theatres"] = "|".join(t.upper() for t in art.theatres)
            row["flags"] = " ".join([
                "☢NUCL" if art.nuclear_related else "",
                "⚔CONF" if art.conflict_related else "",
                "🚀AERO" if art.aerospace_related else ""
            ]).strip()
            
        # Champs spécifiques Wonitor
        elif self.module == ModuleType.WONITOR:
            row["cves"] = "|".join(art.cves[:5])
            row["cvss"] = art.cvss_score or ""
            row["exploit"] = "Yes" if art.exploit_available else "No"
            row["kev"] = "Yes" if art.in_kev else "No"
            row["iocs"] = json.dumps(art.iocs) if art.iocs else ""
            
        # Champs spécifiques LeakHunter
        elif self.module == ModuleType.LEAKHUNTER:
            row["leak_records"] = art.leak_records or ""
            row["leak_volume_gb"] = art.leak_volume_gb or ""
            row["pii_types"] = "|".join(art.pii_types)
            row["ransomware"] = "Yes" if art.ransomware_related else "No"
            row["darkweb"] = "Yes" if art.dark_web_mentioned else "No"
            row["company"] = art.company_mentioned or ""
            
        return row

    # ──────────────────────────────────────────────────────────────────
    # EXPORT JSON
    # ──────────────────────────────────────────────────────────────────
    def export_json(self, path: Optional[str] = None) -> str:
        target = self._resolve_path("json", path)
        export_data = {
            "metadata": {
                "module": self.module.value,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_articles": len(self.articles),
                "config_version": getattr(self.config, "app", {}).get("title", "unknown")
            },
            "articles": [art.to_dict() for art in self.articles]
        }
        target.write_text(json.dumps(export_data, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(target)

    # ──────────────────────────────────────────────────────────────────
    # EXPORT CSV
    # ──────────────────────────────────────────────────────────────────
    def export_csv(self, path: Optional[str] = None) -> str:
        target = self._resolve_path("csv", path)
        if not self.articles:
            return str(target)
            
        rows = [self._flatten_article(art) for art in self.articles]
        # Ordre cohérent des colonnes
        col_order = ["published", "severity", "score", "category", "source", "title", "link", "summary"]
        
        # Ajoute les colonnes module-spécifiques
        if self.module == ModuleType.STRATWATCH:
            col_order.extend(["actors", "theatres", "flags"])
        elif self.module == ModuleType.WONITOR:
            col_order.extend(["cves", "cvss", "exploit", "kev", "iocs"])
        elif self.module == ModuleType.LEAKHUNTER:
            col_order.extend(["leak_records", "leak_volume_gb", "pii_types", "ransomware", "darkweb", "company"])
            
        with open(target, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=col_order)
            writer.writeheader()
            writer.writerows(rows)
            
        return str(target)

    # ──────────────────────────────────────────────────────────────────
    # EXPORT HTML (Dashboard interactif unifié)
    # ──────────────────────────────────────────────────────────────────
    def export_html(self, path: Optional[str] = None) -> str:
        target = self._resolve_path("html", path)
        app_title = self.config.app.title
        app_desc = self.config.app.description
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        
        # Stats rapides
        total = len(self.articles)
        critical = sum(1 for a in self.articles if a.is_critical)
        sev_counts = {}
        for a in self.articles:
            sev_counts[a.severity.value] = sev_counts.get(a.severity.value, 0) + 1
            
        # Génération des cartes
        cards_html = ""
        cat_colors = {cat.name: cat.color for cat in self.config.categories}
        
        for art in self.articles:
            color = cat_colors.get(art.category, "#6b7280")
            sev_class = art.severity.value.lower()
            flags_html = self._get_flags_html(art)
            extra_info = self._get_extra_info_html(art)
            
            cards_html += f"""
            <article class="card sev-{sev_class}" data-cat="{art.category}" data-sev="{art.severity.value}" data-score="{art.score}">
              <div class="card-header">
                <span class="badge" style="background:{color}">{art.category}</span>
                <span class="sev-badge sev-{sev_class}">{art.severity.value}</span>
              </div>
              <div class="meta">
                <span class="source">{art.source}</span>
                <span class="date">{art.published.strftime('%d/%m %H:%M')}</span>
              </div>
              <h3><a href="{art.link}" target="_blank" rel="noopener">{art.title}</a></h3>
              <p class="summary">{art.summary}</p>
              {flags_html}
              {extra_info}
              <div class="score-bar"><div class="score-fill" style="width:{art.score}%"></div><span class="score-val">{art.score}</span></div>
            </article>"""
            
        # Boutons filtres
        cat_filters = f'<button class="fbtn active" data-filter="all">Tous <span class="cnt">{total}</span></button>'
        for cat in self.config.categories:
            cnt = sum(1 for a in self.articles if a.category == cat.name)
            cat_filters += f'<button class="fbtn" data-filter="{cat.name}">{cat.name} <span class="cnt">{cnt}</span></button>'
            
        sev_filters = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = sev_counts.get(sev, 0)
            if cnt > 0:
                sev_filters += f'<button class="sfbtn sev-{sev.lower()}" data-sev="{sev}">{sev} ({cnt})</button>'
                
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{app_title}</title>
<style>
:root{{--bg:#0b0f19;--s1:#111827;--s2:#1f2937;--border:#374151;--text:#e5e7eb;--muted:#9ca3af;--accent:#3b82f6;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;--info:#6b7280}}
*{{box-sizing:border-box;margin:0;padding:0}}body{{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;min-height:100vh}}
header{{background:linear-gradient(135deg,#1e3a8a,#0f172a);padding:2rem;border-bottom:1px solid var(--border)}}
header h1{{font-size:1.8rem;font-weight:700}}header p{{color:var(--muted);margin-top:.5rem}}
.stats{{display:flex;gap:1rem;padding:1rem 2rem;background:var(--s1);border-bottom:1px solid var(--border);flex-wrap:wrap}}
.stat{{background:var(--s2);padding:.6rem 1rem;border-radius:6px;border:1px solid var(--border)}}
.stat .lbl{{font-size:.7rem;text-transform:uppercase;color:var(--muted)}}.stat .val{{font-size:1.4rem;font-weight:700;margin-top:.2rem}}
.stat.crit .val{{color:var(--crit)}}
nav{{padding:1rem 2rem;background:var(--s1);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:50;display:flex;flex-wrap:wrap;gap:.5rem}}
.fbtn,.sfbtn{{background:transparent;border:1px solid var(--border);color:var(--muted);padding:.4rem .8rem;border-radius:6px;cursor:pointer;font-size:.8rem;transition:all .2s}}
.fbtn:hover,.fbtn.active,.sfbtn:hover,.sfbtn.active{{background:var(--accent);border-color:var(--accent);color:#fff}}
.sfbtn.sev-critical{{border-color:var(--crit);color:var(--crit)}}.sfbtn.sev-high{{border-color:var(--high);color:var(--high)}}
.sfbtn.sev-medium{{border-color:var(--med);color:var(--med)}}.sfbtn.sev-low{{border-color:var(--low);color:var(--low)}}
.sfbtn.active{{color:#000!important;background:currentColor!important}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1rem;padding:1.5rem 2rem}}
.card{{background:var(--s2);border:1px solid var(--border);border-radius:10px;padding:1.2rem;transition:all .2s}}
.card:hover{{border-color:var(--accent);transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.3)}}
.card-header{{display:flex;align-items:center;gap:.5rem;margin-bottom:.8rem}}
.badge{{font-size:.65rem;padding:.2rem .5rem;border-radius:4px;color:#fff;font-weight:600}}
.sev-badge{{font-size:.6rem;font-weight:700;padding:.15rem .4rem;border-radius:3px;margin-left:auto}}
.sev-critical{{background:#ef444420;color:var(--crit);border:1px solid var(--crit)}}
.sev-high{{background:#f9731620;color:var(--high);border:1px solid var(--high)}}
.sev-medium{{background:#eab30820;color:var(--med);border:1px solid var(--med)}}
.sev-low{{background:#22c55e20;color:var(--low);border:1px solid var(--low)}}
.meta{{display:flex;justify-content:space-between;font-size:.75rem;color:var(--muted);margin-bottom:.5rem}}
.card h3{{font-size:.95rem;font-weight:600;line-height:1.4;margin-bottom:.5rem}}
.card h3 a{{color:var(--text);text-decoration:none}}.card h3 a:hover{{color:var(--accent)}}
.summary{{font-size:.8rem;color:var(--muted);line-height:1.5;margin-bottom:.8rem}}
.flags,.extra{{display:flex;flex-wrap:wrap;gap:.3rem;margin-bottom:.6rem}}
.tag{{font-size:.6rem;padding:.15rem .4rem;border-radius:3px;background:#374151;color:#d1d5db}}
.tag.nucl{{background:#dc262620;color:#ef4444;border:1px solid #ef4444}}
.tag.conf{{background:#ea580c20;color:#f97316;border:1px solid #ea580c}}
.tag.cve{{background:#3b82f620;color:#60a5fa;border:1px solid #3b82f6}}
.tag.leak{{background:#e74c3c20;color:#ef4444;border:1px solid #e74c3c}}
.score-bar{{background:var(--border);height:4px;border-radius:2px;position:relative;margin-top:.5rem}}
.score-fill{{height:100%;border-radius:2px;background:var(--accent)}}
.score-val{{position:absolute;right:0;top:-1rem;font-size:.65rem;color:var(--muted)}}
.card.hidden{{display:none}}
footer{{text-align:center;padding:1.5rem;color:var(--muted);font-size:.75rem;border-top:1px solid var(--border)}}
</style>
</head>
<body>
<header><h1>⚡ {app_title}</h1><p>{app_desc} · {now_str}</p></header>
<div class="stats">
  <div class="stat"><div class="lbl">Total</div><div class="val">{total}</div></div>
  <div class="stat crit"><div class="lbl">Critiques</div><div class="val">{critical}</div></div>
  <div class="stat"><div class="lbl">Module</div><div class="val">{self.module.value.upper()}</div></div>
</div>
<nav>
  <input type="text" id="search" placeholder="🔍 Rechercher..." style="background:var(--s2);border:1px solid var(--border);color:var(--text);padding:.4rem .8rem;border-radius:6px;width:200px">
  {cat_filters}
</nav>
<div style="padding:.5rem 2rem;display:flex;gap:.5rem;flex-wrap:wrap;background:var(--bg);border-bottom:1px solid var(--border)">
  <button class="sfbtn active" data-sev="all">Tout</button>{sev_filters}
</div>
<main class="grid" id="grid">{cards_html}</main>
<footer>{app_title} v1.0 · StratIntel Hub</footer>
<script>
(function(){{
  const cards=Array.from(document.querySelectorAll('.card')),grid=document.getElementById('grid'),search=document.getElementById('search');
  let fCat='all',fSev='all',q='';
  function apply(){{let n=0;cards.forEach(c=>{{const ok=c.dataset.cat===fCat||fCat==='all'&&c.dataset.sev===fSev||fSev==='all';const txt=(c.querySelector('h3')?.textContent||'')+(c.querySelector('.summary')?.textContent||'');const s=!q||txt.toLowerCase().includes(q);c.classList.toggle('hidden',!(ok&&s));if(ok&&s)n++}});}}
  document.querySelectorAll('.fbtn').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('active'));b.classList.add('active');fCat=b.dataset.filter;apply()}});
  document.querySelectorAll('.sfbtn').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.sfbtn').forEach(x=>x.classList.remove('active'));b.classList.add('active');fSev=b.dataset.sev;apply()}});
  search.oninput=e=>{{q=e.target.value.toLowerCase();apply()}};
  apply();
}})();
</script>
</body>
</html>"""
        target.write_text(html, encoding="utf-8")
        return str(target)

    # ──────────────────────────────────────────────────────────────────
    # EXPORT MARKDOWN (Rapport structuré)
    # ──────────────────────────────────────────────────────────────────
    def export_markdown(self, path: Optional[str] = None) -> str:
        target = self._resolve_path("md", path)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        
        md = f"# 📊 Rapport {self.config.app.title}\nGénéré le : `{now}`\n\n"
        
        # Résumé exécutif
        md += "## 📈 Résumé\n"
        md += f"- **Total articles** : {len(self.articles)}\n"
        md += f"- **Critiques** : {sum(1 for a in self.articles if a.is_critical)}\n"
        md += f"- **Score moyen** : {sum(a.score for a in self.articles)/max(len(self.articles),1):.1f}/100\n\n"
        
        # Stats module-aware
        md += "## 🎯 Indicateurs Clés\n"
        if self.module == ModuleType.STRATWATCH:
            actors = {}
            for a in self.articles: actors.update({act: actors.get(act,0)+1 for act in a.actors})
            md += f"- **Acteurs top** : {', '.join([f'{k}({v})' for k,v in sorted(actors.items(), key=lambda x:-x[1])[:5]])}\n"
        elif self.module == ModuleType.WONITOR:
            cves = {}
            for a in self.articles: cves.update({c: cves.get(c,0)+1 for c in a.cves})
            md += f"- **CVEs critiques** : {', '.join([f'{k}({v})' for k,v in sorted(cves.items(), key=lambda x:-x[1])[:5]])}\n"
        elif self.module == ModuleType.LEAKHUNTER:
            leaks = [a for a in self.articles if a.leak_records]
            md += f"- **Fuites détectées** : {len(leaks)}\n"
        md += "\n"
        
        # Alertes prioritaires
        md += "## 🚨 Alertes Prioritaires (Score ≥ 75)\n"
        high = sorted([a for a in self.articles if a.score >= 75], key=lambda x: -x.score)[:15]
        if high:
            for a in high:
                md += f"### [{a.score}/100] `{a.severity.value}` {a.title}\n"
                md += f"- Source : `{a.source}` | Date : `{a.published.strftime('%d/%m %H:%M')}`\n"
                md += f"- [Lien]({a.link})\n"
                md += f"- Résumé : {a.summary}\n"
                if a.actors: md += f"- Acteurs : {', '.join(a.actors[:4])}\n"
                if a.cves: md += f"- CVEs : `{', '.join(a.cves[:3])}`\n"
                if a.leak_records: md += f"- Fuite : `{a.leak_records}`\n"
                md += "\n"
        else:
            md += "*Aucune alerte prioritaire détectée.*\n"
            
        target.write_text(md, encoding="utf-8")
        return str(target)

    # ──────────────────────────────────────────────────────────────────
    # UTILITAIRES INTERNES
    # ──────────────────────────────────────────────────────────────────
    def _get_flags_html(self, art: UnifiedArticle) -> str:
        tags = []
        if art.nuclear_related: tags.append('<span class="tag nucl">☢ NUCL</span>')
        if art.conflict_related: tags.append('<span class="tag conf">⚔ CONF</span>')
        if art.cves: tags.append('<span class="tag cve">🐛 CVEs</span>')
        if art.ransomware_related: tags.append('<span class="tag leak">💀 RANSOM</span>')
        if art.dark_web_mentioned: tags.append('<span class="tag">🌑 DARKWEB</span>')
        return f'<div class="flags">{"".join(tags)}</div>' if tags else ""
        
    def _get_extra_info_html(self, art: UnifiedArticle) -> str:
        parts = []
        if art.actors: parts.append(f'<span class="tag">👥 {", ".join(art.actors[:3])}</span>')
        if art.cves: parts.append(f'<span class="tag">🔍 {", ".join(art.cves[:3])}</span>')
        if art.leak_records: parts.append(f'<span class="tag leak">📊 {art.leak_records}</span>')
        return f'<div class="extra">{"".join(parts)}</div>' if parts else ""

    # ──────────────────────────────────────────────────────────────────
    # EXPORT MULTIPLE
    # ──────────────────────────────────────────────────────────────────
    def export_all(self) -> Dict[str, str]:
        """Exporte dans tous les formats configurés"""
        results = {}
        if not self.articles: return results
        
        for fmt in self.config.export.paths:
            try:
                if fmt == "json": results["json"] = self.export_json()
                elif fmt == "csv": results["csv"] = self.export_csv()
                elif fmt == "html": results["html"] = self.export_html()
            except Exception as e:
                results[f"{fmt}_error"] = str(e)
        return results