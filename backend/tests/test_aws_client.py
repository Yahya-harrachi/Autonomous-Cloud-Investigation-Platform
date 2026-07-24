"""
Test AWS Client
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.infrastructure.clients.aws_client import AWSClient


def test_aws_client():
    """Test AWS Client"""
    print("\n" + "="*60)
    print("TESTING AWS CLIENT")
    print("="*60)
    
    # 1. Initialize client
    print("\n1️⃣ Initializing AWS Client...")
    client = AWSClient()
    print("   ✅ AWS Client initialized")
    
    # 2. Test credentials
    print("\n2️⃣ Testing AWS credentials...")
    valid = client.test_credentials()
    if valid:
        print("   ✅ Credentials are valid!")
    else:
        print("   ❌ Credentials are invalid!")
        return False
    
    # 3. Get account ID
    print("\n3️⃣ Getting AWS Account ID...")
    account_id = client.get_account_id()
    print(f"   ✅ Account ID: {account_id}")
    
    # 4. Get CloudTrail client
    print("\n4️⃣ Getting CloudTrail client...")
    cloudtrail = client.get_client("cloudtrail")
    print(f"   ✅ CloudTrail client: {cloudtrail}")
    
    # 5. Test CloudTrail API call
    print("\n5️⃣ Testing CloudTrail API call...")
    try:
        response = cloudtrail.lookup_events(MaxResults=5)
        events = response.get("Events", [])
        print(f"   ✅ Found {len(events)} CloudTrail events")
        if events:
            print(f"   📝 First event: {events[0].get('EventName', 'Unknown')}")
    except Exception as e:
        print(f"   ❌ Error calling CloudTrail: {e}")
        return False
    
    print("\n" + "="*60)
    print("✅ ALL TESTS PASSED!")
    print("="*60)
    return True


if __name__ == "__main__":
    test_aws_client()