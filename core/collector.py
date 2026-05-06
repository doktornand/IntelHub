# core/collector.py
import re
import hashlib
import feedparser
import requests
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.models import UnifiedArticle

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

class UnifiedCollector:
    """Collecteur RSS défensif avec journalisation des erreurs et compatibilité Dict/DotDict"""
    
    def __init__(self, config, module, max_items: int = 15, timeout: int = 12):
        self.config = config
        self.module = module
        self.max_items = max_items
        self.timeout = timeout
        self.session = requests.Session()
        
        # Extraction sécurisée de l'User-Agent (fonctionne avec dict ou DotDict)
        app_cfg = config.get("app", {}) if isinstance(config, dict) else getattr(config, "app", {})
        ua = app_cfg.get("user_agent", "Mozilla/5.0 (StratIntel Hub/1.0)")
        self.session.headers.update({"User-Agent": ua, "Accept": "application/rss+xml, */*"})
        
        self.collection_errors = []

    def collect(self) -> List[UnifiedArticle]:
        feeds_with_cat = self._flatten_feeds()
        if not feeds_with_cat:
            self.collection_errors.append("⚠ Aucune catégorie ou flux trouvé dans la configuration.")
            return []

        articles = []
        max_workers = min(len(feeds_with_cat), 6)  # Évite les rate-limits
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self._fetch_feed, feed, cat_name): (feed, cat_name)
                for feed, cat_name in feeds_with_cat
            }
            for future in as_completed(future_map):
                feed, cat_name = future_map[future]
                try:
                    results = future.result()
                    articles.extend(results)
                except Exception as e:
                    self.collection_errors.append(f"❌ {feed.get('name', 'Unknown')} : {str(e)}")

        # Déduplication & tri
        return self._deduplicate_and_sort(articles)

    def _flatten_feeds(self) -> List[Tuple]:
        cats = self.config.get("categories", []) if isinstance(self.config, dict) else getattr(self.config, "categories", [])
        if not cats: return []
        flat = []
        for cat in cats:
            cat_name = cat.get("name", "Sans catégorie") if isinstance(cat, dict) else getattr(cat, "name", "Sans catégorie")
            feeds = cat.get("feeds", []) if isinstance(cat, dict) else getattr(cat, "feeds", [])
            for feed in feeds:
                flat.append((feed, cat_name))
        return flat

    def _fetch_feed(self, feed, category_name: str) -> List[UnifiedArticle]:
        articles = []
        feed_name = feed.get("name", "Unknown") if isinstance(feed, dict) else getattr(feed, "name", "Unknown")
        feed_url = feed.get("url", "") if isinstance(feed, dict) else getattr(feed, "url", "")
        
        if not feed_url.startswith("http"):
            return articles

        try:
            resp = self.session.get(feed_url, timeout=self.timeout)
            resp.raise_for_status()
            
            parsed = feedparser.parse(resp.content)
            if not parsed.entries:
                self.collection_errors.append(f"⚠ {feed_name} : Flux vide ou invalide")
                return []

            limit = feed.get("max_items") or self.max_items
            for entry in parsed.entries[:limit]:
                art = self._parse_entry(entry, feed_name, category_name)
                if art: articles.append(art)
                
        except requests.exceptions.Timeout:
            self.collection_errors.append(f"⏱ {feed_name} : Timeout")
        except requests.exceptions.HTTPError as e:
            self.collection_errors.append(f"🚫 {feed_name} : HTTP {e.response.status_code}")
        except Exception as e:
            self.collection_errors.append(f"💥 {feed_name} : {type(e).__name__}")
            
        return articles

    def _parse_entry(self, entry, source: str, category: str) -> Optional[UnifiedArticle]:
        title = re.sub(r'<[^>]+>', '', str(getattr(entry, 'title', '')).strip())
        if not title: return None
        
        link = str(getattr(entry, 'link', '')).strip()
        raw_sum = getattr(entry, 'summary', getattr(entry, 'description', ''))
        summary = re.sub(r'<[^>]+>', '', str(raw_sum).strip())[:600]
        published = self._parse_date(entry)

        return UnifiedArticle(
            module=self.module, category=category, source=source,
            title=title, link=link, published=published, summary=summary,
            content_hash=hashlib.md5(title.lower().encode()).hexdigest()[:12]
        )

    def _parse_date(self, entry) -> datetime:
        for attr in ("published_parsed", "updated_parsed", "created_parsed"):
            t = getattr(entry, attr, None)
            if t:
                try: return datetime(*t[:6], tzinfo=timezone.utc)
                except: pass
        return datetime.now(timezone.utc)

    def _deduplicate_and_sort(self, articles: List[UnifiedArticle]) -> List[UnifiedArticle]:
        seen, unique = set(), []
        for art in articles:
            if art.content_hash not in seen:
                seen.add(art.content_hash)
                unique.append(art)
        unique.sort(key=lambda a: a.published, reverse=True)
        return unique
