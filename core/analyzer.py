# core/analyzer.py
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from collections import Counter
import pandas as pd
from core.models import ModuleType, UnifiedArticle, Severity

class UnifiedAnalyzer:
    """Analyseur unifié avec enrichissement spécifique par module"""
    
    def __init__(self, articles: List[UnifiedArticle], module: ModuleType):
        self.articles = articles
        self.module = module
        self._enrich_all()

    def _enrich_all(self):
        for art in self.articles:
            if self.module == ModuleType.STRATWATCH:
                self._enrich_stratwatch(art)
            elif self.module == ModuleType.WONITOR:
                self._enrich_wonitor(art)
            elif self.module == ModuleType.LEAKHUNTER:
                self._enrich_leakhunter(art)

    # ──────────────────────────────────────────────────────────────────
    # ENRICHISSEMENTS SPÉCIFIQUES
    # ──────────────────────────────────────────────────────────────────
    def _enrich_stratwatch(self, art: UnifiedArticle):
        text = f"{art.title} {art.summary}".lower()
        words = set(re.findall(r'\b[\w\-]+\b', text))

        art.nuclear_related = bool({'nuclear', 'nucléaire', 'icbm', 'slbm', 'warhead', 'plutonium', 'enrichment'} & words)
        art.conflict_related = bool({'airstrike', 'frappe', 'offensive', 'casualties', 'invasion', 'drone strike', 'frontline'} & words)
        art.aerospace_related = bool({'launch', 'satellite', 'orbit', 'rocket', 'space debris', 'asat', 'starlink'} & words)

        # Détection acteurs
        actors_map = {
            'russia': 'Russia', 'russie': 'Russia', 'ukraine': 'Ukraine', 'china': 'China', 'chine': 'China',
            'iran': 'Iran', 'israel': 'Israel', 'israël': 'Israel', 'usa': 'USA', 'united states': 'USA',
            'nato': 'NATO', 'otan': 'NATO', 'france': 'France', 'germany': 'Germany', 'hamas': 'Hamas',
            'hezbollah': 'Hezbollah', 'wagner': 'Wagner'
        }
        art.actors = list(set(v for k, v in actors_map.items() if k in text))[:6]

        # Score STRATINT
        score = 20
        if art.nuclear_related: score += 25
        if art.conflict_related: score += 20
        if art.aerospace_related: score += 15
        score += len(art.actors) * 5
        
        art.score = min(score, 100)
        art.severity = self._score_to_severity(art.score, ['FLASH', 'URGENT', 'IMPORTANT', 'WATCH', 'INFO'])

    def _enrich_wonitor(self, art: UnifiedArticle):
        text_up = f"{art.title} {art.summary}".upper()
        
        # Extraction CVE
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', text_up)
        art.cves = list(set(cves))
        
        # Détection sévérité cyber
        if any(x in text_up for x in ['CRITICAL', 'CRITIQUE', 'RCE', '0DAY', 'ZERO-DAY', 'ACTIVELY EXPLOITED']):
            art.severity = Severity.CRITICAL
            art.score = 95
        elif any(x in text_up for x in ['HIGH', 'HAUTE', 'IMPORTANT', 'URGENT']):
            art.severity = Severity.HIGH
            art.score = 75
        elif any(x in text_up for x in ['MEDIUM', 'MOYENNE', 'MODERATE']):
            art.severity = Severity.MEDIUM
            art.score = 50
        else:
            art.severity = Severity.LOW
            art.score = 25

        if art.cves: art.score += 10
        art.score = min(art.score, 100)

    def _enrich_leakhunter(self, art: UnifiedArticle):
        text = f"{art.title} {art.summary}".lower()
        text_up = text.upper()

        art.ransomware_related = bool({'ransomware', 'lockbit', 'blackcat', 'alphv', 'clop', 'akira'} & set(text.split()))
        art.dark_web_mentioned = bool({'dark web', 'darkweb', '.onion', 'underground forum'} & {text})
        art.extortion_related = bool({'extortion', 'double extortion', 'data auction', 'blackmail'} & {text})

        # Détection PII / Volume
        if re.search(r'(password|credential|email|phone|ssn|passport|credit card)', text):
            art.pii_types = re.findall(r'(password|email|ssn|passport|credit card)', text)
        
        vol_match = re.search(r'(\d[\d,.]*)\s*(million|billion|k|m|b)', text)
        if vol_match: art.leak_volume_gb = vol_match.group(0)

        # Risk Score
        score = 20
        if art.ransomware_related: score += 20
        if art.dark_web_mentioned: score += 15
        if art.extortion_related: score += 15
        if art.pii_types: score += 10
        if vol_match: score += 10
        art.score = min(score, 100)
        art.severity = self._score_to_severity(art.score, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])

    # ──────────────────────────────────────────────────────────────────
    # UTILITAIRES & STATS
    # ──────────────────────────────────────────────────────────────────
    def _score_to_severity(self, score: int, levels: List[str]) -> Severity:
        """Map un score 0-100 vers l'enum Severity"""
        if score >= 85: return Severity(levels[0])
        if score >= 65: return Severity(levels[1])
        if score >= 45: return Severity(levels[2])
        return Severity(levels[-1])

    def generate_stats(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        stats = {
            "total": len(self.articles),
            "critical": sum(1 for a in self.articles if a.is_critical),
            "by_severity": Counter(a.severity.value for a in self.articles),
            "by_category": Counter(a.category for a in self.articles),
            "by_source": Counter(a.source for a in self.articles),
            "top_actors": [],
            "top_cves": [],
            "recent_24h": 0,
            "module_flags": {}
        }

        for a in self.articles:
            if (now - a.published) <= timedelta(hours=24):
                stats["recent_24h"] += 1

        if self.module == ModuleType.STRATWATCH:
            stats["top_actors"] = Counter(act for a in self.articles for act in a.actors).most_common(8)
            stats["module_flags"] = {
                "nuclear": sum(1 for a in self.articles if a.nuclear_related),
                "conflict": sum(1 for a in self.articles if a.conflict_related),
                "aerospace": sum(1 for a in self.articles if a.aerospace_related)
            }
        elif self.module == ModuleType.WONITOR:
            stats["top_cves"] = Counter(cve for a in self.articles for cve in a.cves).most_common(10)
        elif self.module == ModuleType.LEAKHUNTER:
            stats["module_flags"] = {
                "ransomware": sum(1 for a in self.articles if a.ransomware_related),
                "leaks": sum(1 for a in self.articles if a.leak_volume_gb or a.pii_types),
                "darkweb": sum(1 for a in self.articles if a.dark_web_mentioned)
            }
        return stats

    def to_dataframe(self) -> pd.DataFrame:
        """Prépare un DataFrame propre pour Streamlit"""
        rows = []
        for a in self.articles:
            rows.append({
                "Date": a.published.strftime("%d/%m %H:%M"),
                "Sévérité": a.severity.value,
                "Score": a.score,
                "Catégorie": a.category,
                "Source": a.source,
                "Titre": a.title,
                "Lien": a.link,
                "Acteurs": ", ".join(a.actors[:3]) if a.actors else "-",
                "CVEs": ", ".join(a.cves[:3]) if a.cves else "-",
                "Flags": self._get_flags(a)
            })
        return pd.DataFrame(rows)

    def _get_flags(self, art: UnifiedArticle) -> str:
        flags = []
        if art.nuclear_related: flags.append("☢️")
        if art.conflict_related: flags.append("⚔️")
        if art.ransomware_related: flags.append("💀")
        if art.dark_web_mentioned: flags.append("🌑")
        if art.cves: flags.append(f"🐛{len(art.cves)}")
        return " ".join(flags)

    def filter(self, max_items: int = None, critical_only: bool = False, time_filter: str = "Tout") -> List[UnifiedArticle]:
        res = self.articles
        if critical_only:
            res = [a for a in res if a.is_critical]
        
        if time_filter != "Tout":
            hours = {"24h": 24, "7j": 168, "30j": 720}.get(time_filter, 0)
            if hours:
                cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
                res = [a for a in res if a.published >= cutoff]
                
        if max_items:
            res = res[:max_items]
        return res