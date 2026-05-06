# core/models.py
"""
Modèles de données unifiés pour la veille multi-spectre.
Définit les enums et la dataclass centralisée partagée par tous les modules.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import hashlib
import re


class ModuleType(Enum):
    """Types de modules de veille"""
    STRATWATCH = "stratwatch"
    WONITOR = "wonitor"
    LEAKHUNTER = "leakhunter"


class Severity(Enum):
    """Niveaux de sévérité normalisés"""
    FLASH = "FLASH"
    CRITICAL = "CRITICAL"
    URGENT = "URGENT"
    HIGH = "HIGH"
    IMPORTANT = "IMPORTANT"
    MEDIUM = "MEDIUM"
    WATCH = "WATCH"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class UnifiedArticle:
    """
    Modèle unifié d'article/événement de veille.
    Contient tous les champs communs + les champs spécifiques à chaque domaine.
    """
    
    # ── Champs obligatoires communs ──
    module: ModuleType
    category: str
    source: str
    title: str
    link: str
    published: datetime
    summary: str
    
    # ── Scoring & priorisation ──
    severity: Severity = Severity.INFO
    score: int = 0  # 0-100
    priority: int = 5  # 1-10 pour tri manuel
    
    # ── Flags StratWatch (Géo/Def) ──
    nuclear_related: bool = False
    conflict_related: bool = False
    aerospace_related: bool = False
    actors: List[str] = field(default_factory=list)
    weapon_systems: List[str] = field(default_factory=list)
    theatres: List[str] = field(default_factory=list)
    
    # ── Flags Wonitor (Cyber) ──
    cves: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    in_kev: bool = False
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    
    # ── Flags LeakHunter (Data Leaks) ──
    ransomware_related: bool = False
    leak_records: Optional[str] = None
    leak_volume_gb: Optional[str] = None
    pii_types: List[str] = field(default_factory=list)
    dark_web_mentioned: bool = False
    extortion_related: bool = False
    company_mentioned: Optional[str] = None
    
    # ── Méta ──
    content_hash: str = ""
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Génère le hash de déduplication si non fourni"""
        if not self.content_hash:
            norm = re.sub(r'\W+', '', f"{self.title}{self.source}".lower())[:100]
            self.content_hash = hashlib.md5(norm.encode()).hexdigest()[:12]
    
    @property
    def is_critical(self) -> bool:
        return self.severity in (Severity.FLASH, Severity.CRITICAL, Severity.URGENT)
    
    @property
    def module_label(self) -> str:
        labels = {
            ModuleType.STRATWATCH: "⚡ StratWatch",
            ModuleType.WONITOR: "🛡️ Wonitor",
            ModuleType.LEAKHUNTER: "🔓 LeakHunter"
        }
        return labels.get(self.module, self.module.value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Sérialisation normalisée pour exports JSON/Streamlit"""
        return {
            "module": self.module.value,
            "category": self.category,
            "source": self.source,
            "title": self.title,
            "link": self.link,
            "published": self.published.isoformat(),
            "summary": self.summary,
            "severity": self.severity.value,
            "score": self.score,
            "priority": self.priority,
            "is_critical": self.is_critical,
            "flags": {
                "strategic": {
                    "nuclear": self.nuclear_related,
                    "conflict": self.conflict_related,
                    "aerospace": self.aerospace_related,
                    "actors": self.actors,
                    "theatres": self.theatres,
                },
                "cyber": {
                    "cves": self.cves,
                    "cvss": self.cvss_score,
                    "exploit": self.exploit_available,
                    "kev": self.in_kev,
                    "iocs": self.iocs,
                },
                "leaks": {
                    "ransomware": self.ransomware_related,
                    "records": self.leak_records,
                    "volume_gb": self.leak_volume_gb,
                    "pii": self.pii_types,
                    "darkweb": self.dark_web_mentioned,
                    "extortion": self.extortion_related,
                    "company": self.company_mentioned,
                }
            },
            "tags": self.tags,
        }