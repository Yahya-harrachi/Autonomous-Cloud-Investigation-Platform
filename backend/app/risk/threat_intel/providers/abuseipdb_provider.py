"""
AbuseIPDB Threat Intelligence Provider
"""
import logging
import requests
from datetime import datetime, timedelta
from typing import Optional

from ..interfaces import ThreatIntelProvider, ThreatIntelResult
from ....core.config import settings

logger = logging.getLogger(__name__)


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    AbuseIPDB threat intelligence provider.
    """
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or getattr(settings, "ABUSEIPDB_API_KEY", "")
        self._available = bool(self.api_key)
        
        if not self._available:
            logger.warning("AbuseIPDB API key not configured")
        else:
            logger.info(f"AbuseIPDB API key configured: {self.api_key[:10]}...")
    
    def get_provider_name(self) -> str:
        return "abuseipdb"
    
    def is_available(self) -> bool:
        return self._available
    
    def lookup_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check an IP address against AbuseIPDB."""
        if not self._available:
            return None
        
        # Skip private IPs
        if self._is_private_ip(ip):
            return None
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                },
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                timeout=10,
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_response(ip, data)
            else:
                logger.warning(f"AbuseIPDB error {response.status_code}: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB request failed for {ip}: {e}")
            return None
    
    def _parse_response(self, ip: str, data: dict) -> ThreatIntelResult:
        raw_data = data.get("data", {})
        confidence_score = raw_data.get("abuseConfidenceScore", 0)
        is_malicious = confidence_score >= 50
        
        # Risk modifier based on confidence
        if confidence_score >= 90:
            risk_modifier = 2.5
        elif confidence_score >= 75:
            risk_modifier = 2.0
        elif confidence_score >= 50:
            risk_modifier = 1.5
        elif confidence_score >= 25:
            risk_modifier = 1.2
        else:
            risk_modifier = 1.0
        
        categories = []
        for report in raw_data.get("reports", []):
            category = report.get("category", {})
            if category:
                categories.append(category)
        
        return ThreatIntelResult(
            indicator_type="ip",
            indicator_value=ip,
            provider="abuseipdb",
            confidence=confidence_score,
            is_malicious=is_malicious,
            risk_modifier=risk_modifier,
            categories=list(set(categories))[:10],
            details={
                "country_code": raw_data.get("countryCode"),
                "isp": raw_data.get("isp"),
                "domain": raw_data.get("domain"),
                "total_reports": raw_data.get("totalReports", 0),
                "last_reported_at": raw_data.get("lastReportedAt"),
            },
            expires_at=datetime.utcnow() + timedelta(hours=24),
            cached_at=datetime.utcnow(),
        )
    
    def _is_private_ip(self, ip: str) -> bool:
        if not ip:
            return True
        
        private_ranges = [
            "10.", "192.168.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
            "172.29.", "172.30.", "172.31.", "127.", "169.254.", "::1"
        ]
        
        for prefix in private_ranges:
            if ip.startswith(prefix):
                return True
        
        return False