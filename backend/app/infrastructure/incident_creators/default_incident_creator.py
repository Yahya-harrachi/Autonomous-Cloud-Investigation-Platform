"""
Default incident creator with decision engine
"""
import uuid
from datetime import datetime
from typing import List
from ...domain.models.event import NormalizedEvent
from ...domain.models.incident import Incident, IncidentStatus, IncidentPriority
from ...domain.interfaces.incident_creator import IncidentCreator


class DefaultIncidentCreator(IncidentCreator):
    """
    Default incident creator with rule-based decision engine.
    
    Decision Rules (in order):
    1. Severity CRITICAL or HIGH → Create incident
    2. Security-sensitive actions → Create incident
    3. Multiple related events → Create incident (future)
    4. Otherwise → No incident (store as observation)
    """
    
    # Security-sensitive event types that always create incidents
    SECURITY_SENSITIVE_EVENTS = [
        "attach_policy",
        "detach_policy",
        "create_user",
        "create_role",
        "delete_user",
        "delete_role",
        "security_group_modify",
        "bucket_policy_change",
        "console_login",  # Unusual login patterns
        "unauthorized_login",
        "crypto_mining",
        "port_scan",
        "dos_attack",
        "privilege_escalation"
    ]
    
    # Severity mapping
    SEVERITY_TO_PRIORITY = {
        "CRITICAL": IncidentPriority.CRITICAL,
        "HIGH": IncidentPriority.HIGH,
        "MEDIUM": IncidentPriority.MEDIUM,
        "LOW": IncidentPriority.LOW,
        "INFO": IncidentPriority.LOW
    }
    
    def should_create_incident(self, normalized_event: NormalizedEvent) -> bool:
        """
        Decision engine: Should this event become an incident?
        """
        # Rule 1: Severity check
        if normalized_event.severity in ["CRITICAL", "HIGH"]:
            return True
        
        # Rule 2: Security-sensitive actions
        if normalized_event.event_type in self.SECURITY_SENSITIVE_EVENTS:
            return True
        
        # Rule 3: Check for suspicious tags
        if "suspicious_ip" in normalized_event.tags:
            return True
        if "privilege_escalation" in normalized_event.tags:
            return True
        
        # Default: No incident
        return False
    
    def get_decision_reason(self, normalized_event: NormalizedEvent) -> str:
        """
        Return the reason why an incident was or wasn't created.
        """
        if normalized_event.severity in ["CRITICAL", "HIGH"]:
            return f"Severity is {normalized_event.severity} - requires investigation"
        
        if normalized_event.event_type in self.SECURITY_SENSITIVE_EVENTS:
            return f"Security-sensitive action: {normalized_event.event_type}"
        
        if "suspicious_ip" in normalized_event.tags:
            return "Event from suspicious IP address"
        
        if "privilege_escalation" in normalized_event.tags:
            return "Privilege escalation detected"
        
        return f"Routine event (severity: {normalized_event.severity}) - no incident needed"
    
    def create_incident(self, normalized_event: NormalizedEvent) -> Incident:
        """
        Create an incident from a normalized event.
        """
        # Generate title
        title = self._generate_title(normalized_event)
        
        # Generate description
        description = self._generate_description(normalized_event)
        
        # Determine priority from severity
        priority = self.SEVERITY_TO_PRIORITY.get(
            normalized_event.severity,
            IncidentPriority.MEDIUM
        )
        
        # Generate tags
        tags = self._generate_tags(normalized_event)
        
        # Prepare metadata
        metadata = {
            "provider": normalized_event.provider,
            "provider_type": normalized_event.provider_type,
            "event_type": normalized_event.event_type,
            "region": normalized_event.region,
            "account_id": normalized_event.account_id,
            "source_ip": normalized_event.actor_ip,
            "decision_reason": self.get_decision_reason(normalized_event)
        }
        
        # Create incident
        return Incident(
            id=f"inc-{uuid.uuid4().hex[:12]}",
            title=title,
            description=description,
            status=IncidentStatus.PENDING,
            priority=priority,
            source_type=f"{normalized_event.provider}_{normalized_event.provider_type}",
            source_event_id=normalized_event.event_id,
            normalized_event=normalized_event.to_dict(),
            created_at=datetime.utcnow(),
            updated_at=None,
            resolved_at=None,
            assigned_to=None,
            assigned_team=None,
            tags=tags,
            metadata=metadata,
            evidence_count=0,
            evidence_ids=[]
        )
    
    def _generate_title(self, event: NormalizedEvent) -> str:
        """
        Generate a human-readable incident title.
        """
        # Use event_name if available
        if hasattr(event, 'event_name') and event.event_name:
            return f"{event.severity}: {event.event_name} by {event.actor}"
        
        # Build from components
        action = event.action
        resource_type = event.resource_type
        actor = event.actor
        
        titles = {
            "attach": f"Suspicious Policy Attachment by {actor}",
            "create": f"New {resource_type} Created by {actor}",
            "delete": f"{resource_type} Deleted by {actor}",
            "modify": f"{resource_type} Modified by {actor}",
            "authenticate": f"Unusual Login from {actor}",
            "detected": f"Security Finding: {event.event_type}"
        }
        
        return titles.get(event.action, f"{event.event_type} by {actor}")
    
    def _generate_description(self, event: NormalizedEvent) -> str:
        """
        Generate a detailed incident description.
        """
        parts = []
        
        # Basic info
        parts.append(f"An incident was detected from {event.provider.upper()}.")
        
        # What happened
        if hasattr(event, 'event_description') and event.event_description:
            parts.append(event.event_description)
        else:
            parts.append(f"Event Type: {event.event_type}")
        
        # Actor
        parts.append(f"Actor: {event.actor} ({event.actor_type})")
        
        # Resource
        parts.append(f"Resource: {event.resource} ({event.resource_type})")
        
        # Additional context
        if event.region:
            parts.append(f"Region: {event.region}")
        
        if event.actor_ip:
            parts.append(f"Source IP: {event.actor_ip}")
        
        # Severity
        parts.append(f"Severity: {event.severity} (Score: {event.severity_score})")
        
        # Reason
        parts.append(f"Reason: {self.get_decision_reason(event)}")
        
        return " ".join(parts)
    
    def _generate_tags(self, event: NormalizedEvent) -> List[str]:
        """
        Generate tags for the incident.
        """
        tags = []
        
        # Provider tags
        tags.append(event.provider)
        tags.append(event.provider_type)
        
        # Severity tag
        tags.append(event.severity.lower())
        
        # Action tag
        tags.append(event.action)
        
        # Security-sensitive
        if event.event_type in self.SECURITY_SENSITIVE_EVENTS:
            tags.append("security_sensitive")
        
        # Add any existing tags from the event
        if hasattr(event, 'tags') and event.tags:
            tags.extend(event.tags)
        
        # Remove duplicates
        return list(set(tags))