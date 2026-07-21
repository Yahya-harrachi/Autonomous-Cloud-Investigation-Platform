from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional

@dataclass
class RawEvent:
    """A raw event from any cloud provider"""
    source: str              # "aws", "azure", "gcp", "mock"
    provider: str            # Specific service: "cloudtrail", "activity_logs"
    event_type: str          # "ConsoleLogin", "EC2Launch"
    data: Dict[str, Any]     # The full event data
    timestamp: datetime
    received_at: datetime
    raw_json: Optional[str] = None  # Original JSON string for reference