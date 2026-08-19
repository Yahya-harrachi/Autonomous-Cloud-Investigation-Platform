# app/evidence/enrichers/threat_intelligence.py
"""
Threat Intelligence Enricher - Adds threat intelligence to evidence
"""
import httpx
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from app.core.config import settings

logger = logging.getLogger(__name__)


class ThreatIntelligenceEnricher:
    """
    Enriches evidence with threat intelligence data from AbuseIPDB.
    """
    
    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    async def check_ip(self, ip_address: str, max_age_days: int = 30) -> Optional[Dict[str, Any]]:
        """
        Check an IP address against AbuseIPDB.
        
        Args:
            ip_address: The IP address to check
            max_age_days: Maximum age of reports in days
            
        Returns:
            Dict with threat intelligence data or None
        """
        if not self.api_key:
            logger.warning("⚠️ No AbuseIPDB API key configured")
            return None
        
        if not ip_address or ip_address == 'unknown':
            return None
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.base_url}/check",
                    params={
                        'ipAddress': ip_address,
                        'maxAgeInDays': max_age_days,
                        'verbose': True
                    },
                    headers={
                        'Key': self.api_key,
                        'Accept': 'application/json'
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_response(data, ip_address)
                elif response.status_code == 429:
                    logger.warning(f"⚠️ Rate limited by AbuseIPDB for IP: {ip_address}")
                    return None
                else:
                    logger.warning(f"⚠️ AbuseIPDB API error: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ Error checking IP with AbuseIPDB: {e}")
            return None
    
    def _parse_response(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Parse AbuseIPDB response."""
        result = data.get('data', {})
        
        return {
            'ip': ip_address,
            'abuse_score': result.get('abuseConfidenceScore', 0),
            'total_reports': result.get('totalReports', 0),
            'is_malicious': result.get('abuseConfidenceScore', 0) >= 50,
            'is_suspicious': 25 <= result.get('abuseConfidenceScore', 0) < 50,
            'country_code': result.get('countryCode'),
            'country_name': result.get('countryName'),
            'isp': result.get('isp'),
            'domain': result.get('domain'),
            'usage_type': result.get('usageType'),
            'last_reported_at': result.get('lastReportedAt'),
            'reports': result.get('reports', [])[:5],  # Last 5 reports
            'report_summary': self._summarize_reports(result.get('reports', []))
        }
    
    def _summarize_reports(self, reports: list) -> Dict[str, int]:
        """Summarize report categories."""
        summary = {}
        for report in reports:
            categories = report.get('categories', [])
            for category in categories:
                summary[category] = summary.get(category, 0) + 1
        return summary
    
    async def enrich_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an event with threat intelligence.
        
        Args:
            event_data: The event data to enrich
            
        Returns:
            Enriched event data with threat_intel field
        """
        # Extract IP address from event
        source_ip = event_data.get('source_ip') or event_data.get('actor_ip')
        
        if not source_ip or source_ip == 'unknown':
            event_data['threat_intel'] = None
            return event_data
        
        # Check IP against AbuseIPDB
        threat_data = await self.check_ip(source_ip)
        
        if threat_data:
            event_data['threat_intel'] = threat_data
            logger.info(f"✅ Threat intelligence added for IP {source_ip}")
            logger.info(f"   Score: {threat_data.get('abuse_score')}/100")
            logger.info(f"   Reports: {threat_data.get('total_reports')}")
        else:
            event_data['threat_intel'] = None
        
        return event_data
    
    def get_threat_level(self, score: int) -> str:
        """Get threat level based on AbuseIPDB score."""
        if score >= 75:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 25:
            return 'medium'
        elif score > 0:
            return 'low'
        return 'clean'
    
    def get_threat_emoji(self, score: int) -> str:
        """Get emoji based on threat level."""
        if score >= 75:
            return '🔴'
        elif score >= 50:
            return '🟠'
        elif score >= 25:
            return '🟡'
        elif score > 0:
            return '🔵'
        return '🟢'