"""
Simple console receiver that prints events with beautiful formatting
"""
import json
from datetime import datetime
from typing import List
from ...domain.models.event import RawEvent

class ConsoleReceiver:
    """Receives events and prints them beautifully to console"""
    
    # Colors for terminal
    COLORS = {
        "aws": "\033[94m",      # Blue
        "azure": "\033[96m",    # Cyan
        "gcp": "\033[92m",      # Green
        "reset": "\033[0m",     # Reset
        "yellow": "\033[93m",
        "red": "\033[91m"
    }
    
    def __init__(self):
        self.events: List[RawEvent] = []
        self.received_count = 0
    
    def receive(self, event: RawEvent) -> None:
        """Print event with beautiful formatting"""
        color = self.COLORS.get(event.source, self.COLORS["reset"])
        reset = self.COLORS["reset"]
        
        print("\n" + "="*70)
        print(f"{color}📩 EVENT RECEIVED #{self.received_count + 1}{reset}")
        print("="*70)
        
        # Source info
        print(f"{self.COLORS['yellow']}Source:{reset} {event.source.upper()}")
        print(f"{self.COLORS['yellow']}Provider:{reset} {event.provider}")
        print(f"{self.COLORS['yellow']}Event Type:{reset} {event.event_type}")
        print(f"{self.COLORS['yellow']}Timestamp:{reset} {event.timestamp.isoformat()}")
        print(f"{self.COLORS['yellow']}Received at:{reset} {event.received_at.isoformat()}")
        
        # Show key fields based on source
        print(f"\n{self.COLORS['yellow']}Key Fields:{reset}")
        print("-" * 50)
        
        if event.source == "aws":
            self._print_aws_keys(event.data)
        elif event.source == "azure":
            self._print_azure_keys(event.data)
        elif event.source == "gcp":
            self._print_gcp_keys(event.data)
        
        # Full JSON (truncated if too long)
        print(f"\n{self.COLORS['yellow']}Full Event Data:{reset}")
        print("-" * 50)
        json_str = json.dumps(event.data, indent=2)
        if len(json_str) > 2000:
            json_str = json_str[:2000] + "\n... (truncated)"
        print(json_str)
        
        print("="*70 + "\n")
        
        # Store event
        self.events.append(event)
        self.received_count += 1
    
    def _print_aws_keys(self, data: dict):
        """Print AWS-specific key fields"""
        if "eventName" in data:
            print(f"  Event Name: {data['eventName']}")
        if "eventSource" in data:
            print(f"  Event Source: {data['eventSource']}")
        if "awsRegion" in data:
            print(f"  Region: {data['awsRegion']}")
        if "userIdentity" in data:
            user = data["userIdentity"]
            if "userName" in user:
                print(f"  User: {user['userName']}")
            if "type" in user:
                print(f"  User Type: {user['type']}")
        if "sourceIPAddress" in data:
            print(f"  Source IP: {data['sourceIPAddress']}")
        if "responseElements" in data:
            resp = data["responseElements"]
            if "keyId" in resp:
                print(f"  Key ID: {resp['keyId']}")
    
    def _print_azure_keys(self, data: dict):
        """Print Azure-specific key fields"""
        if "caller" in data:
            print(f"  Caller: {data['caller']}")
        if "operationName" in data:
            if isinstance(data["operationName"], dict) and "localizedValue" in data["operationName"]:
                print(f"  Operation: {data['operationName']['localizedValue']}")
        if "eventName" in data:
            if isinstance(data["eventName"], dict) and "localizedValue" in data["eventName"]:
                print(f"  Event: {data['eventName']['localizedValue']}")
        if "level" in data:
            print(f"  Level: {data['level']}")
        if "resourceGroupName" in data:
            print(f"  Resource Group: {data['resourceGroupName']}")
        if "properties" in data and "status" in data["properties"]:
            print(f"  Status: {data['properties']['status']}")
    
    def _print_gcp_keys(self, data: dict):
        """Print GCP-specific key fields"""
        if "protoPayload" in data:
            payload = data["protoPayload"]
            if "serviceName" in payload:
                print(f"  Service: {payload['serviceName']}")
            if "methodName" in payload:
                print(f"  Method: {payload['methodName']}")
            if "authenticationInfo" in payload:
                auth = payload["authenticationInfo"]
                if "principalEmail" in auth:
                    print(f"  User: {auth['principalEmail']}")
            if "requestMetadata" in payload:
                req = payload["requestMetadata"]
                if "callerIp" in req:
                    print(f"  Source IP: {req['callerIp']}")
        if "severity" in data:
            print(f"  Severity: {data['severity']}")
        if "resource" in data and "type" in data["resource"]:
            print(f"  Resource Type: {data['resource']['type']}")
    
    def get_all(self) -> List[RawEvent]:
        """Get all received events"""
        return self.events
    
    def get_latest(self) -> RawEvent:
        """Get the most recent event"""
        if not self.events:
            return None
        return self.events[-1]
    
    def clear(self) -> None:
        """Clear all events"""
        self.events.clear()
        self.received_count = 0