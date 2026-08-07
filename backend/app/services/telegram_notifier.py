"""
Telegram Notifier - Sends incident notifications via Telegram Bot
"""
import httpx
import logging
from typing import Optional
from datetime import datetime

from ..domain.models.incident import Incident

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Send incident notifications to Telegram"""
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{bot_token}"
    
    async def send_incident_alert(self, incident: Incident) -> bool:
        """
        Send incident notification via Telegram with clean SOC-friendly format
        """
        
        # Priority emojis and colors
        priority_config = {
            "CRITICAL": {"emoji": "🚨", "badge": "🔴 CRITICAL", "border": "‼️"},
            "HIGH": {"emoji": "⚠️", "badge": "🟠 HIGH", "border": "❗"},
            "MEDIUM": {"emoji": "📌", "badge": "🟡 MEDIUM", "border": "➡️"},
            "LOW": {"emoji": "ℹ️", "badge": "🟢 LOW", "border": "ℹ️"}
        }
        
        priority_info = priority_config.get(incident.priority.value, priority_config["MEDIUM"])
        
        # Get metadata
        metadata = incident.metadata or {}
        severity_score = metadata.get('severity_score', 'N/A')
        severity_reason = metadata.get('reason', 'N/A')
        event_name = metadata.get('event_name', 'N/A')
        actor = metadata.get('actor', 'N/A')
        source_ip = metadata.get('source_ip', 'N/A')
        region = metadata.get('region', 'N/A')
        
        # Build clean message
        message = f"""
    

    *📋 INCIDENT SUMMARY*

    *🎯 Title:* `{incident.title}`
    *📊 Priority:* {priority_info['emoji']} *{incident.priority.value.upper()}*
    *📌 Status:* `{incident.status.value.upper()}`
    *🔗 Source:* `{incident.source_type}`

    *🔍 KEY DETAILS*

    • *Event:* `{event_name}`
    • *Actor:* `{actor}`
    • *Source IP:* `{source_ip}`
    • *Region:* `{region}`

    *📈 SEVERITY*

    • *Score:* `{severity_score}/100`
    • *Reason:* `{severity_reason[:150]}{'...' if len(severity_reason) > 150 else ''}`

    *🏷️ Tags:* `{', '.join(incident.tags) if incident.tags else 'None'}`

    *🕐 Time:* `{incident.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`

    *🔗 View:* `http://localhost:3000/incidents/{incident.id}`
    """
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.api_url}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": message,
                        "parse_mode": "Markdown",
                        "disable_web_page_preview": True
                    }
                )
                response.raise_for_status()
                logger.info(f"✅ Telegram notification sent for incident {incident.id}")
                return True
                
        except Exception as e:
            logger.error(f"❌ Failed to send Telegram notification: {e}")
            return False
    
    async def send_test_message(self) -> bool:
        """
        Send a test message to verify the bot is working
        
        Returns:
            True if successful, False otherwise
        """
        message = """
🚀 *ACIP Telegram Notifier Test*

✅ Your Telegram bot is configured correctly!
📡 Ready to send incident notifications.

*Time:* {timestamp}
        """.format(timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.api_url}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": message,
                        "parse_mode": "Markdown"
                    }
                )
                response.raise_for_status()
                logger.info("✅ Test message sent successfully!")
                return True
        except Exception as e:
            logger.error(f"❌ Failed to send test message: {e}")
            return False