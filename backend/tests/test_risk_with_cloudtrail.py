"""
Test Risk Engine with Real CloudTrail Data
Using the REAL normalizer (not duplicated logic)
"""
import sys
import os
import json
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.risk import RiskEngine
from app.infrastructure.clients.aws_client import AWSClient
from app.infrastructure.connectors.cloudtrail_connector import CloudTrailConnector
from app.infrastructure.normalizers.aws_normalizer import AWSNormalizer
from app.domain.models.event import RawEvent


def get_cloudtrail_events(count: int = 5):
    """Fetch real CloudTrail events from AWS"""
    try:
        aws_client = AWSClient()
        connector = CloudTrailConnector(aws_client)
        events = connector.fetch_events(max_results=count)
        return events
    except Exception as e:
        print(f"❌ Error fetching CloudTrail events: {e}")
        return []


def run_test():
    """Run the risk engine test with real CloudTrail data"""
    print("\n" + "="*70)
    print("🔍 TESTING RISK ENGINE WITH REAL CLOUDTRAIL DATA")
    print("="*70)
    
    # Step 1: Fetch real CloudTrail events
    print("\n📥 Fetching CloudTrail events...")
    raw_events = get_cloudtrail_events(count=5)
    
    if not raw_events:
        print("❌ No CloudTrail events found.")
        return
    
    print(f"✅ Fetched {len(raw_events)} CloudTrail events")
    
    # Step 2: Use the REAL normalizer
    print("\n🔄 Normalizing events using REAL AWSNormalizer...")
    normalizer = AWSNormalizer()
    normalized_events = []
    
    for event in raw_events:
        try:
            # Parse the timestamp
            event_time = event.get("EventTime", "")
            if event_time:
                try:
                    # Handle ISO format with Z
                    timestamp = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                except ValueError:
                    # Fallback to current time
                    timestamp = datetime.now(timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)
            
            # Create RawEvent with proper datetime
            raw_event = RawEvent(
                source="aws",
                provider="cloudtrail",
                event_type=event.get("EventName", "unknown"),
                data=event,
                timestamp=timestamp,
                received_at=datetime.now(timezone.utc),
            )
            
            # Use the REAL normalizer
            normalized = normalizer.normalize(raw_event)
            normalized_events.append(normalized)
            print(f"  ✅ Normalized: {normalized.event_name}")
            
        except Exception as e:
            print(f"  ❌ Error normalizing event: {e}")
    
    print(f"\n✅ Normalized {len(normalized_events)} events")
    
    if not normalized_events:
        print("❌ No events were normalized. Exiting.")
        return
    
    # Step 3: Run Risk Engine
    print("\n📊 Running Risk Engine...")
    engine = RiskEngine()
    
    for i, event in enumerate(normalized_events, 1):
        print(f"\n{'='*70}")
        print(f"Event #{i}: {event.event_name}")
        print(f"{'='*70}")
        
        # Convert to dict for risk engine
        event_dict = event.to_dict()
        
        # Add identity_type to the dict for the risk engine
        if hasattr(event, 'metadata') and event.metadata:
            event_dict['identity_type'] = event.metadata.get('identity_type', 'unknown')
        
        # Assess risk
        assessment = engine.assess_event(event_dict)
        
        # Print results
        print(f"Risk Score: {assessment.risk_score}/100")
        print(f"Risk Level: {assessment.risk_level.display_name()}")
        
        print("\nContributions:")
        for c in assessment.contributions:
            print(f"  [{c.factor.value}] {c.description}: +{c.contribution}")
            print(f"    -> {c.reasoning}")
        
        print("\nFull Reasoning:")
        print(assessment.get_reasoning())
        print("-"*70)


if __name__ == "__main__":
    run_test()