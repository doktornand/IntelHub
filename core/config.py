# core/config.py — VERSION CORRIGÉE
import json
from pathlib import Path
from typing import Dict, Any, Optional

# ── IMPORT MANQUANT AJOUTÉ ──
from core.models import ModuleType
# ────────────────────────────

from pydantic import BaseModel, Field, validator

class FeedConfig(BaseModel):
    name: str
    url: str
    priority: str = "normal"  # critical, high, normal, low
    max_items: Optional[int] = None

class CategoryConfig(BaseModel):
    name: str
    color: str = "#888888"
    priority: int = 2
    feeds: list[FeedConfig] = Field(default_factory=list)
    
    @validator('color')
    def validate_color(cls, v):
        if not v.startswith('#') or len(v) != 7:
            raise ValueError("Couleur doit être au format #RRGGBB")
        return v.upper()

class AppConfig(BaseModel):
    title: str
    description: str
    user_agent: str = "Mozilla/5.0 (StratIntel Hub/1.0)"

class CollectionConfig(BaseModel):
    max_items_per_feed: int = 15
    request_timeout_seconds: int = 15
    retry_on_timeout: bool = True
    retry_max_attempts: int = 3
    deduplicate: bool = True
    scraping_enabled: bool = True
    leak_focused_mode: bool = False

class ExportConfig(BaseModel):
    default_format: str = "html"
    paths: Dict[str, str] = Field(default_factory=lambda: {
        "json": "export.json",
        "csv": "export.csv", 
        "html": "dashboard.html"
    })

class ModuleConfig(BaseModel):
    app: AppConfig
    collection: CollectionConfig
    export: ExportConfig
    categories: list[CategoryConfig]
    _comment: Optional[str] = None

class ConfigManager:
    """Gestionnaire centralisé des configurations"""
    
    CONFIG_MAP = {
        ModuleType.STRATWATCH: "stratwatch_config.json",
        ModuleType.WONITOR: "wonitor_config.json",
        ModuleType.LEAKHUNTER: "leak_intel_config.json"
    }
    
    @classmethod
    def load(cls, module: ModuleType, config_path: Optional[Path] = None) -> ModuleConfig:
        """Charge et valide la configuration d'un module"""
        path = config_path or Path(cls.CONFIG_MAP[module])
        
        if not path.exists():
            raise FileNotFoundError(f"Config introuvable: {path}")
        
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        
        # Nettoyage des clés (gestion des espaces dans vos JSON)
        cleaned = cls._clean_keys(raw)
        
        return ModuleConfig(**cleaned)
    
    @staticmethod
    def _clean_keys(d: Dict) -> Dict:
        """Nettoie les clés avec espaces (compatibilité avec vos configs)"""
        if isinstance(d, dict):
            return {k.strip(): ConfigManager._clean_keys(v) for k, v in d.items()}
        elif isinstance(d, list):
            return [ConfigManager._clean_keys(item) for item in d]
        return d
    
    @classmethod
    def get_feeds(cls, module: ModuleType, category_name: Optional[str] = None) -> list[FeedConfig]:
        """Récupère les feeds d'un module, optionnellement filtrés par catégorie"""
        cfg = cls.load(module)
        if category_name:
            for cat in cfg.categories:
                if cat.name == category_name:
                    return cat.feeds
            return []
        return [feed for cat in cfg.categories for feed in cat.feeds]