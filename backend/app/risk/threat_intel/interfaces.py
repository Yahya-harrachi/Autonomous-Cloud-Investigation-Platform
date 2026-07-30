"""
Abstract interfaces for threat intelligence providers
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ThreatIntelResult:
    """Result from a threat intelligence lookup"""
    indicator_type: str          # "ip", "domain", "hash"
    indicator_value: str         # "203.0.113.1"
    provider: str                # "abuseipdb", "virustotal"
    
    # Risk signals
    confidence: int              # 0-100
    is_malicious: bool
    risk_modifier: float         # 1.0 to 3.0
    
    # Additional info
    categories: list = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    
    expires_at: datetime = field(default_factory=datetime.utcnow)
    cached_at: datetime = field(default_factory=datetime.utcnow)


class ThreatIntelProvider(ABC):
    """Abstract base class for all threat intelligence providers"""
    
    @abstractmethod
    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        pass