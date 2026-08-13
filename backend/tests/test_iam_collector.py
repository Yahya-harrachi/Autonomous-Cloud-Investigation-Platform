# tests/test_iam_collector.py
"""
Test script for IAM Collector
"""
import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.evidence.collectors.iam_collector import IAMCollector
from app.domain.models.incident import Incident, IncidentStatus, IncidentPriority


async def test_iam_collector():
    """Test the IAM collector with a real incident"""
    print("=" * 60)
    print("🔍 TESTING IAM COLLECTOR")
    print("=" * 60)
    
    # Create a mock incident with a real IAM user
    # Replace 'your-iam-username' with an actual IAM user in your AWS account
    test_username = "yahya-harrachi"  # ⚠️ REPLACE THIS
    
    mock_incident = Incident(
        id="inc-test-iam",
        title=f"[CRITICAL] AttachUserPolicy by {test_username}",
        description="Test incident for IAM collector",
        status=IncidentStatus.PENDING,
        priority=IncidentPriority.CRITICAL,
        source_type="aws_cloudtrail",
        source_event_id="test-event-iam-123",
        normalized_event={
            "event_id": "test-iam-123",
            "event_name": "AttachUserPolicy",
            "timestamp": datetime.utcnow().isoformat(),
            "actor": test_username,
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
        tags=["test", "iam"],
        metadata={"severity_score": 95},
        evidence_ids=[],
        evidence_count=0
    )
    
    print(f"📋 Incident: {mock_incident.id}")
    print(f"   Title: {mock_incident.title}")
    print(f"   Actor: {test_username}")
    print()
    
    # Initialize collector
    collector = IAMCollector()
    print(f"📡 Collector: {collector.collector_name}")
    print(f"   Type: {collector.get_artifact_type()}")
    print(f"   Source: {collector.get_source()}")
    print()
    
    # Collect evidence
    print("⏳ Collecting IAM evidence...")
    artifact = await collector.collect(mock_incident)
    
    if artifact:
        print()
        print("=" * 60)
        print("✅ IAM EVIDENCE COLLECTED SUCCESSFULLY!")
        print("=" * 60)
        print(f"Artifact ID: {artifact.id}")
        print(f"Type: {artifact.artifact_type}")
        print(f"Status: {artifact.collection_status}")
        print(f"Source: {artifact.source}")
        print(f"Collector: {artifact.collector}")
        
        if artifact.collection_status == "FAILED":
            print(f"❌ Error: {artifact.error_message}")
        else:
            content = artifact.content
            summary = content.get('summary', {})
            user_data = content.get('user', {})
            
            print()
            print("📊 Collection Summary:")
            print(f"   👤 User: {user_data.get('user_name', 'N/A')}")
            print(f"   🆔 User ID: {user_data.get('user_id', 'N/A')}")
            print(f"   📅 Created: {user_data.get('create_date', 'N/A')}")
            print(f"   🔐 MFA Active: {user_data.get('mfa_active', False)}")
            print(f"   📋 Attached Policies: {summary.get('total_attached_policies', 0)}")
            print(f"   📝 Inline Policies: {summary.get('total_inline_policies', 0)}")
            print(f"   👥 Groups: {summary.get('total_groups', 0)}")
            print(f"   🔑 Access Keys: {summary.get('total_access_keys', 0)}")
            print()
            print(f"🔐 SHA-256: {artifact.hash[:40]}...")
            print(f"✅ Integrity: {artifact.integrity_verified}")
    else:
        print("❌ No artifact created")
    
    print()
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_iam_collector())