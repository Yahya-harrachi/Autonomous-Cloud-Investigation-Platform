# tests/test_evidence_integration.py
"""
Test evidence collection integration with incident creator
"""
import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.domain.models.event import NormalizedEvent
from app.services.incident_creator import IncidentCreator
from app.core.database import SessionLocal
from app.models.incident import IncidentModel
from app.models.evidence import EvidenceArtifact
from app.evidence.collectors.base import parse_incident_id


async def test_evidence_integration():
    """Test that evidence is collected when incident is created"""
    print("=" * 60)
    print("🔍 TESTING EVIDENCE INTEGRATION")
    print("=" * 60)
    
    # Create a test event with ALL required fields
    event = NormalizedEvent(
        # ===== REQUIRED FIELDS =====
        event_id="test-123",
        provider="aws",
        provider_type="cloudtrail",
        event_type="AwsApiCall",
        event_name="AttachUserPolicy",
        event_description="User policy attachment by test-user",
        event_category="Management",
        actor="test-user",
        actor_type="IAMUser",
        resource="arn:aws:iam::123456789012:user/suspicious-user",
        resource_type="User",
        action="AttachUserPolicy",
        result="Success",
        severity="CRITICAL",
        severity_score=95,
        severity_reason="Critical IAM policy attachment - AdministratorAccess",
        timestamp=datetime.utcnow(),
        
        # ===== OPTIONAL FIELDS =====
        actor_arn="arn:aws:iam::123456789012:user/test-user",
        actor_ip="192.168.1.1",
        region="us-east-1",
        account_id="123456789012",
        threat_intel=None,
        
        # ===== CONTEXT FIELDS =====
        hour=datetime.utcnow().hour,
        day_of_week=datetime.utcnow().strftime("%A"),
        is_read_only=False,
        
        # ===== DICT FIELDS =====
        resource_details={
            "userName": "suspicious-user",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        },
        action_details={
            "policyName": "AdministratorAccess",
            "policyType": "Managed"
        },
        result_details={
            "message": "Policy attached successfully"
        },
        metadata={
            "identity_type": "IAMUser",
            "source": "cloudtrail"
        },
        raw_event={},
        
        # ===== LIST FIELDS =====
        tags=["test", "iam", "privilege-escalation", "critical"],
        related_events=[]
    )
    
    print(f"📝 Test Event:")
    print(f"   Name: {event.event_name}")
    print(f"   Severity: {event.severity} (Score: {event.severity_score})")
    print(f"   Actor: {event.actor}")
    print(f"   Resource: {event.resource}")
    print()
    
    # Create incident
    print("🚀 Creating incident...")
    creator = IncidentCreator()
    incident = creator.process_event(event)
    
    if incident:
        print()
        print("=" * 60)
        print("✅ INCIDENT CREATED!")
        print("=" * 60)
        print(f"ID: {incident.id}")
        print(f"Title: {incident.title}")
        print(f"Priority: {incident.priority.value}")
        print(f"Status: {incident.status.value}")
        
        # Give evidence collection time to complete
        print("\n⏳ Waiting for evidence collection to complete...")
        await asyncio.sleep(5)
        
        # Check database for evidence
        print("\n📊 Checking for evidence artifacts...")
        db = SessionLocal()
        try:
            # Parse incident ID to UUID
            incident_uuid = parse_incident_id(incident.id)
            print(f"   Incident UUID: {incident_uuid}")
            
            artifacts = db.query(EvidenceArtifact).filter(
                EvidenceArtifact.incident_id == incident_uuid
            ).all()
            
            if artifacts:
                print(f"   ✅ Found {len(artifacts)} evidence artifacts")
                
                for artifact in artifacts:
                    print(f"\n   📦 Artifact: {artifact.id}")
                    print(f"      Type: {artifact.artifact_type}")
                    print(f"      Status: {artifact.collection_status}")
                    print(f"      Collector: {artifact.collector}")
                    
                    if artifact.collection_status == "FAILED":
                        print(f"      ❌ Error: {artifact.error_message}")
                    elif artifact.collection_status == "COMPLETED":
                        content = artifact.content
                        summary = content.get('summary', {})
                        timeline = content.get('timeline', [])
                        print(f"      Events: {summary.get('total_events', 0)}")
                        print(f"      Timeline: {len(timeline)} events")
                        print(f"      Hash: {artifact.hash[:40]}...")
                        
                        # Show first 3 timeline events
                        if timeline:
                            print(f"\n      📅 Timeline (first 3):")
                            for i, event in enumerate(timeline[:3]):
                                marker = "🚨" if event.get('is_trigger') else "  "
                                print(f"         {marker} {event.get('event_time', 'N/A')} - {event.get('event_name', 'Unknown')}")
            else:
                print("   ℹ️ No evidence artifacts found yet (collection may still be running)")
                
        except Exception as e:
            print(f"❌ Error checking artifacts: {e}")
            import traceback
            traceback.print_exc()
        finally:
            db.close()
        
        print()
        print("=" * 60)
    else:
        print("❌ No incident created")
    
    print()
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_evidence_integration())