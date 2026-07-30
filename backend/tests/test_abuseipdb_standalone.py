"""
Standalone test for AbuseIPDB API
"""
import os
import sys
import requests
from dotenv import load_dotenv

# Add the backend directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
load_dotenv()

def test_abuseipdb():
    """Test AbuseIPDB API directly"""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    if not api_key:
        print("❌ ABUSEIPDB_API_KEY not found in .env file")
        return False
    
    print(f"✅ API Key found: {api_key[:10]}...")
    
    test_ips = ["8.8.8.8", "1.1.1.1", "203.0.113.1"]
    
    headers = {"Key": api_key, "Accept": "application/json"}
    
    for ip in test_ips:
        print(f"\n🔍 Checking IP: {ip}")
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers=headers,
                timeout=10,
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("data", {})
                print(f"   ✅ Confidence: {result.get('abuseConfidenceScore', 0)}%")
                print(f"   ✅ Total Reports: {result.get('totalReports', 0)}")
            else:
                print(f"   ❌ Error: {response.text}")
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
    
    return True


def test_threat_intel_manager():
    """Test the ThreatIntelManager directly"""
    print("\n" + "="*60)
    print("TESTING THREATINTELMANAGER")
    print("="*60)
    
    try:
        from app.risk.threat_intel import ThreatIntelManager
        manager = ThreatIntelManager()
        
        print(f"✅ ThreatIntelManager initialized")
        print(f"   Providers: {[p.get_provider_name() for p in manager.providers]}")
        
        result = manager.get_ip_reputation("8.8.8.8")
        print(f"\n🔍 Result for 8.8.8.8:")
        print(f"   {result}")
        
        result = manager.get_ip_reputation("1.1.1.1")
        print(f"\n🔍 Result for 1.1.1.1:")
        print(f"   {result}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        import traceback
        traceback.print_exc()
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("="*60)
    print("ABUSEIPDB STANDALONE TEST")
    print("="*60)
    
    test_abuseipdb()
    test_threat_intel_manager()