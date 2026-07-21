"""
Azure Activity Log Normalizer
Converts Azure Activity Log events to ACIP format
"""
import uuid
from datetime import datetime
from typing import Dict, Any, List
from .base import Normalizer
from ...domain.models.event import RawEvent, NormalizedEvent


class AzureNormalizer(Normalizer):
    """Normalizes Azure Activity Log events to ACIP Internal format"""
    
    def get_provider(self) -> str:
        return "azure"
    
    def can_normalize(self, raw_event: RawEvent) -> bool:
        return raw_event.source == "azure"
    
    def normalize(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize Azure Activity Log event with FULL context"""
        data = raw_event.data
        
        # ===== WHAT HAPPENED =====
        event_name_obj = data.get("eventName", {})
        event_type = event_name_obj.get("value", "unknown").lower().replace(" ", "_")
        event_name_human = event_name_obj.get("localizedValue", "Azure Activity")
        
        # Build description
        operation = data.get("operationName", {}).get("localizedValue", "unknown")
        resource_group = data.get("resourceGroupName", "unknown")
        event_description = f"{operation} on resource group {resource_group}"
        event_category = data.get("category", {}).get("value", "Administrative").lower()
        
        # ===== WHO =====
        actor = data.get("caller", "unknown")
        actor_type = "user" if "@" in actor else "service"
        actor_arn = None  # Azure doesn't have ARN
        actor_ip = None   # Azure doesn't provide IP in activity logs
        
        # ===== WHAT RESOURCE =====
        resource_name = data.get("resourceGroupName", "unknown")
        resource_type = data.get("resourceType", {}).get("value", "unknown")
        resource_details = {
            "resource_id": data.get("properties", {}).get("resourceId"),
            "resource_group": resource_name,
            "subscription_id": data.get("subscriptionId"),
            "tenant_id": data.get("tenantId")
        }
        
        # ===== WHAT WAS DONE =====
        action = self._determine_action(event_type)
        action_details = {
            "operation": operation,
            "authorization": data.get("authorization", {}),
            "request_id": data.get("properties", {}).get("requestId")
        }
        
        # ===== RESULT =====
        status = data.get("properties", {}).get("status", "unknown")
        result = "success" if status.lower() == "succeeded" else "failure" if status.lower() == "failed" else "pending"
        result_details = {
            "status": status,
            "submission_timestamp": data.get("submissionTimestamp")
        }
        
        # ===== SEVERITY =====
        level = data.get("level", "Informational")
        severity, score, reason = self._determine_severity(level, data)
        
        # ===== TIMING =====
        timestamp = datetime.fromisoformat(data.get("eventTimestamp", "").replace("Z", "+00:00"))
        region = None  # Azure region is in resource ID
        account_id = data.get("subscriptionId")
        
        # ===== TAGS =====
        tags = self._generate_tags(level, status)
        
        # ===== METADATA =====
        metadata = {
            "correlation_id": data.get("correlationId"),
            "event_data_id": data.get("eventDataId"),
            "operation_id": data.get("operationId"),
            "tenant_id": data.get("tenantId"),
            "description": data.get("description")
        }
        
        return NormalizedEvent(
            # ===== REQUIRED FIELDS =====
            event_id=f"acip-{uuid.uuid4().hex[:12]}",
            provider="azure",
            provider_type="activity_logs",
            event_type=event_type,
            event_name=event_name_human,
            event_description=event_description,
            event_category=event_category,
            actor=actor,
            actor_type=actor_type,
            resource=resource_name,
            resource_type=resource_type,
            action=action,
            result=result,
            severity=severity,
            severity_score=score,
            severity_reason=reason,
            timestamp=timestamp,
            
            # ===== OPTIONAL FIELDS =====
            actor_arn=actor_arn,
            actor_ip=actor_ip,
            region=region,
            account_id=account_id,
            
            # ===== DICT FIELDS =====
            resource_details=resource_details,
            action_details=action_details,
            result_details=result_details,
            metadata=metadata,
            raw_event=data,
            
            # ===== LIST FIELDS =====
            tags=tags,
            related_events=[]
        )
    
    def _determine_action(self, event_type: str) -> str:
        """Determine action type from event"""
        if "create" in event_type:
            return "create"
        elif "delete" in event_type:
            return "delete"
        elif "update" in event_type or "modify" in event_type:
            return "modify"
        elif "assign" in event_type or "role" in event_type:
            return "assign"
        else:
            return "modify"
    
    def _determine_severity(self, level: str, data: Dict) -> tuple:
        """Determine severity with reasoning"""
        if level == "Critical":
            return "CRITICAL", 10, "Azure Critical level event - immediate attention required"
        elif level == "Error":
            return "HIGH", 7, "Azure Error level event - operation failed"
        elif level == "Warning":
            return "MEDIUM", 4, "Azure Warning level event - requires review"
        else:
            return "LOW", 1, "Routine Azure informational event"
    
    def _generate_tags(self, level: str, status: str) -> List[str]:
        """Generate tags for the event"""
        tags = []
        
        if level == "Critical":
            tags.append("critical")
        if status.lower() == "failed":
            tags.append("failure")
        if status.lower() == "succeeded":
            tags.append("success")
        
        return tags