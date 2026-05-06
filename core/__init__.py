# core/__init__.py
"""
StratIntel Hub — Package Core
Exposition propre des modules pour des imports simplifiés.
"""

from .models import ModuleType, Severity, UnifiedArticle
from .config import ConfigManager, ModuleConfig, FeedConfig, CategoryConfig
from .collector import UnifiedCollector
from .analyzer import UnifiedAnalyzer
from .exporter import UnifiedExporter

__all__ = [
    "ModuleType", "Severity", "UnifiedArticle",
    "ConfigManager", "ModuleConfig", "FeedConfig", "CategoryConfig",
    "UnifiedCollector", "UnifiedAnalyzer", "UnifiedExporter"
]