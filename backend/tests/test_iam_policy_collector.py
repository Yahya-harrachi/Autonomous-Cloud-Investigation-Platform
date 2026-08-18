# tests/test_iam_policy_collector.py
"""
Test script for IAM Policy Collector
"""
import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.evidence.collectors.iam_policy_collector import IAMPolicyCollector
from app.domain.models.incident import Incident, IncidentStatus, IncidentPriority


async def test_iam_policy_collector():
    """Test the IAM Policy collector with a real incident."""
    print("=" * 60)
    print("🔍 TESTING IAM POLICY COLLECTOR")
    print("=" * 60)
    
    # Create a mock incident with a real policy ARN
    test_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # Real AWS managed policy
    
    mock_incident = Incident(
        id="inc-test-policy",
        title=f"[CRITICAL] AttachUserPolicy with {test_policy_arn}",
        description="Test incident for IAM Policy collector",
        status=IncidentStatus.PENDING,
        priority=IncidentPriority.CRITICAL,
        source_type="aws_cloudtrail",
        source_event_id="test-event-policy-123",
        normalized_event={
            "event_id": "test-policy-123",
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
                "policyArn": test_policy_arn
            },
            "severity_score": 95,
            "severity_reason": "Critical IAM policy attachment"
        },
        created_at=datetime.utcnow(),
        tags=["test", "iam", "policy"],
        metadata={"severity_score": 95},
        evidence_ids=[],
        evidence_count=0
    )
    
    print(f"📋 Incident: {mock_incident.id}")
    print(f"   Title: {mock_incident.title}")
    print(f"   Policy ARN: {test_policy_arn}")
    print()
    
    collector = IAMPolicyCollector()
    print(f"📡 Collector: {collector.collector_name}")
    print(f"   Type: {collector.get_artifact_type()}")
    print(f"   Source: {collector.get_source()}")
    print()
    
    print("⏳ Collecting IAM Policy evidence...")
    artifact = await collector.collect(mock_incident)
    
    if artifact:
        print()
        print("=" * 60)
        print("✅ IAM POLICY EVIDENCE COLLECTED SUCCESSFULLY!")
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
            policies = content.get('policies', [])
            security_analysis = content.get('security_analysis', {})
            
            print()
            print("📊 Collection Summary:")
            print(f"   Total Policies: {summary.get('total_policies', 0)}")
            print(f"   High Risk Findings: {len(security_analysis.get('high_risk_findings', []))}")
            print(f"   Medium Risk Findings: {len(security_analysis.get('medium_risk_findings', []))}")
            print(f"   Low Risk Findings: {len(security_analysis.get('low_risk_findings', []))}")
            
            if policies:
                print()
                print("📋 Policies Collected:")
                for policy in policies:
                    print(f"   - {policy.get('policy_name')}")
                    print(f"     ARN: {policy.get('arn')}")
                    print(f"     Attachments: {policy.get('attachment_count', 0)}")
                    print(f"     Admin Access: {policy.get('summary', {}).get('has_administrator_access', False)}")
            
            # Show security findings
            high_risk = security_analysis.get('high_risk_findings', [])
            if high_risk:
                print()
                print("🔴 HIGH RISK FINDINGS:")
                for finding in high_risk:
                    print(f"   - {finding.get('description')}")
                    print(f"     Recommendation: {finding.get('recommendation')}")
            
            print()
            print(f"🔐 SHA-256: {artifact.hash[:40]}...")
            print(f"✅ Integrity: {artifact.integrity_verified}")
    else:
        print("❌ No artifact created")
    
    print()
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_iam_policy_collector())