"""
Test full incident creation with Telegram notification
"""
import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.incident_creator import IncidentCreator
from app.domain.models.event import NormalizedEvent
from datetime import datetime
import uuid

async def test_full_flow():
    """Test incident creation with Telegram notification"""
    print("🔍 Testing full incident flow...")
    
    # Create a sample normalized event
    event = NormalizedEvent(
        event_id=f"test-{uuid.uuid4().hex[:8]}",
        event_name="ConsoleLogin",
        provider="aws",
        provider_type="cloudtrail",
        severity="CRITICAL",
        severity_score=95,
        severity_reason="Root user login from unknown IP address with failed MFA attempts",
        actor="root",
        actor_type="Root",
        actor_ip="203.0.113.45",
        region="us-east-1",
        resource="arn:aws:iam::123456789012:user/root",
        timestamp=datetime.utcnow(),
        tags=["security", "critical", "unauthorized"]
    )
    
    print(f"📝 Created test event: {event.event_name}")
    print(f"   Severity: {event.severity} (Score: {event.severity_score})")
    
    # Process with incident creator
    creator = IncidentCreator()
    incident = creator.process_event(event)
    
    if incident:
        print(f"✅ Incident created: {incident.id}")
        print(f"   Title: {incident.title}")
        print(f"   Priority: {incident.priority.value}")
        print(f"📱 Check your Telegram @AciipBot for the notification!")
    else:
        print("❌ Incident not created")

if __name__ == "__main__":
    asyncio.run(test_full_flow())