"""
Domain models for events.
These are pure Python objects with NO external dependencies.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum


class EventSourceType(str, Enum):
    """All supported event source types"""
    MOCK = "mock"
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_GUARDDUTY = "aws_guardduty"
    AWS_S3 = "aws_s3"
    AWS_IAM = "aws_iam"
    AZURE_ACTIVITY = "azure_activity"
    GCP_AUDIT = "gcp_audit"
    WEBHOOK = "webhook"


@dataclass
class RawEvent:
    """A raw event from any source"""
    source: str
    provider: str
    event_type: str
    data: Dict[str, Any]
    timestamp: datetime
    received_at: datetime
    raw_json: Optional[str] = None


@dataclass
class NormalizedEvent:
    """
    ACIP Internal Event Model - RICH version.
    Contains EVERYTHING needed for investigation.
    
    ORDER MATTERS: All required fields first, optional fields with defaults last.
    """
    # ===== REQUIRED FIELDS (No defaults) =====
    event_id: str
    provider: str
    provider_type: str
    event_type: str
    event_name: str
    event_description: str
    event_category: str
    actor: str
    actor_type: str
    resource: str
    resource_type: str
    action: str
    result: str
    severity: str
    severity_score: int
    severity_reason: str
    timestamp: datetime
    
    # ===== OPTIONAL FIELDS (With defaults) =====
    actor_arn: Optional[str] = None
    actor_ip: Optional[str] = None
    region: Optional[str] = None
    account_id: Optional[str] = None
    
    # ===== DICT FIELDS (With defaults) =====
    resource_details: Dict[str, Any] = field(default_factory=dict)
    action_details: Dict[str, Any] = field(default_factory=dict)
    result_details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_event: Dict[str, Any] = field(default_factory=dict)
    
    # ===== LIST FIELDS (With defaults) =====
    tags: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/display"""
        return {
            "event_id": self.event_id,
            "provider": self.provider,
            "provider_type": self.provider_type,
            "event_type": self.event_type,
            "event_name": self.event_name,
            "event_description": self.event_description,
            "event_category": self.event_category,
            "actor": self.actor,
            "actor_type": self.actor_type,
            "actor_arn": self.actor_arn,
            "actor_ip": self.actor_ip,
            "resource": self.resource,
            "resource_type": self.resource_type,
            "resource_details": self.resource_details,
            "action": self.action,
            "action_details": self.action_details,
            "result": self.result,
            "result_details": self.result_details,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "severity_reason": self.severity_reason,
            "timestamp": self.timestamp.isoformat(),
            "region": self.region,
            "account_id": self.account_id,
            "tags": self.tags,
            "related_events": self.related_events,
            "metadata": self.metadata
        }
    
    @property
    def display_summary(self) -> str:
        """Human readable summary"""
        return f"[{self.severity}] {self.actor} → {self.action} {self.resource_type} ({self.result})"
    
    @property
    def is_high_severity(self) -> bool:
        return self.severity in ["CRITICAL", "HIGH"]