# tests/test_cloudtrail_collector.py
"""
Test script for CloudTrail Collector
"""
import asyncio
import sys
import os
from pathlib import Path
import uuid
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.evidence.collectors.cloudtrail_collector import CloudTrailCollector
from app.domain.models.incident import Incident, IncidentStatus, IncidentPriority
from app.core.database import SessionLocal
from app.models.incident import IncidentModel


async def test_cloudtrail_collector():
    """Test the CloudTrail collector with a real incident"""
    print("=" * 60)
    print("🔍 TESTING CLOUDTRAIL COLLECTOR")
    print("=" * 60)
    
    # Create a mock incident with normalized event data
    mock_incident = Incident(
        id="inc-test123",
        title="[CRITICAL] AttachUserPolicy by test-user",
        description="Test incident for CloudTrail collector",
        status=IncidentStatus.PENDING,
        priority=IncidentPriority.CRITICAL,
        source_type="aws_cloudtrail",
        source_event_id="test-event-123",
        normalized_event={
            "event_id": "test-123",
            "event_name": "AttachUserPolicy",
            "timestamp": datetime.utcnow().isoformat(),
            "actor": "test-user",
            "actor_type": "IAMUser",
            "actor_ip": "192.168.1.1",
            "region": "us-east-1",
            "provider": "aws",
            "provider_type": "cloudtrail",
            "request_parameters": {
                "userName": "suspicious-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "severity_score": 95,
            "severity_reason": "Critical IAM policy attachment"
        },
        created_at=datetime.utcnow(),
        tags=["test", "iam", "privilege-escalation"],
        metadata={"severity_score": 95},
        evidence_ids=[],
        evidence_count=0
    )
    
    print(f"📋 Incident: {mock_incident.id}")
    print(f"   Title: {mock_incident.title}")
    print(f"   Event: {mock_incident.normalized_event['event_name']}")
    print(f"   Actor: {mock_incident.normalized_event['actor']}")
    print()
    
    # Initialize collector
    collector = CloudTrailCollector()
    print(f"📡 Collector: {collector.collector_name}")
    print(f"   Type: {collector.get_artifact_type()}")
    print(f"   Source: {collector.get_source()}")
    print()
    
    # Collect evidence
    print("⏳ Collecting evidence...")
    artifact = await collector.collect(mock_incident)
    
    if artifact:
        print()
        print("=" * 60)
        print("✅ EVIDENCE COLLECTED SUCCESSFULLY!")
        print("=" * 60)
        print(f"Artifact ID: {artifact.id}")
        print(f"Type: {artifact.artifact_type}")
        print(f"Status: {artifact.collection_status}")
        print(f"Source: {artifact.source}")
        print(f"Collector: {artifact.collector}")
        
        if artifact.collection_status == "FAILED":
            print(f"❌ Error: {artifact.error_message}")
        else:
            # Show summary
            content = artifact.content
            summary = content.get('summary', {})
            timeline = content.get('timeline', [])
            
            print()
            print("📊 Collection Summary:")
            print(f"   Total Events: {summary.get('total_events', 0)}")
            print(f"   Unique Actors: {', '.join(summary.get('unique_actors', []))}")
            print(f"   Event Types: {', '.join(summary.get('event_types', []))}")
            print(f"   Timeline Events: {len(timeline)}")
            
            print()
            print("🕐 Timeline:")
            for i, event in enumerate(timeline[:5]):  # Show first 5
                marker = "🚨" if event.get('is_trigger') else "  "
                print(f"   {marker} {event.get('event_time')} - {event.get('event_name')} by {event.get('actor')}")
            
            if len(timeline) > 5:
                print(f"   ... and {len(timeline) - 5} more events")
            
            # Show hash
            print()
            print(f"🔐 SHA-256: {artifact.hash}")
            print(f"✅ Integrity: {artifact.integrity_verified}")
    else:
        print("❌ No artifact created")
    
    print()
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_cloudtrail_collector())