"""
Threat Intelligence Manager - Simplified (No Cache)
"""
import os
import logging
from typing import List, Optional, Dict, Any

from .interfaces import ThreatIntelProvider, ThreatIntelResult
from .providers.abuseipdb_provider import AbuseIPDBProvider

logger = logging.getLogger(__name__)


class ThreatIntelManager:
    """
    Orchestrates threat intelligence lookups across providers.
    """
    
    def __init__(self):
        self.providers: List[ThreatIntelProvider] = []
        self._register_providers()
    
    def _register_providers(self) -> None:
        """Register all available providers"""
        try:
            # ✅ Directly get API key from environment
            api_key = os.getenv("ABUSEIPDB_API_KEY", "")
            logger.info(f"ABUSEIPDB_API_KEY from env: {api_key[:10] if api_key else 'NOT SET'}...")
            
            if api_key:
                abuseipdb = AbuseIPDBProvider(api_key=api_key)
                if abuseipdb.is_available():
                    self.providers.append(abuseipdb)
                    logger.info("✅ Registered AbuseIPDB provider")
                else:
                    logger.warning("⚠️ AbuseIPDB not available")
            else:
                logger.warning("⚠️ AbuseIPDB API key not configured")
        except Exception as e:
            logger.warning(f"⚠️ Failed to register AbuseIPDB: {e}")
    
    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Look up an IP address across all providers."""
        if not ip:
            return None
        
        # Skip private IPs
        if self._is_private_ip(ip):
            return None
        
        # Check all providers
        for provider in self.providers:
            try:
                result = provider.lookup_ip(ip)
                if result:
                    return result
            except Exception as e:
                logger.error(f"Error in provider {provider.get_provider_name()}: {e}")
        
        return None
    
    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Get IP reputation summary."""
        result = self.lookup_ip(ip)
        
        if not result:
            return {
                "checked": False,
                "is_malicious": False,
                "modifier": 1.0,
                "confidence": 0,
                "provider": None,
                "categories": [],
                "details": {},
            }
        
        return {
            "checked": True,
            "is_malicious": result.is_malicious,
            "modifier": result.risk_modifier,
            "confidence": result.confidence,
            "provider": result.provider,
            "categories": result.categories,
            "details": result.details,
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        if not ip:
            return True
        
        private_ranges = [
            "10.",
            "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "127.",
            "169.254.",
            "::1",
        ]
        
        for prefix in private_ranges:
            if ip.startswith(prefix):
                return True
        
        return False