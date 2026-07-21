"""
GCP Audit Log Normalizer
Converts GCP Audit Log events to ACIP format
"""
import uuid
from datetime import datetime
from typing import Dict, Any, List
from .base import Normalizer
from ...domain.models.event import RawEvent, NormalizedEvent


class GCPNormalizer(Normalizer):
    """Normalizes GCP Audit Log events to ACIP Internal format"""
    
    def get_provider(self) -> str:
        return "gcp"
    
    def can_normalize(self, raw_event: RawEvent) -> bool:
        return raw_event.source == "gcp"
    
    def normalize(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize GCP Audit Log event with FULL context"""
        data = raw_event.data
        
        # Extract from protoPayload
        payload = data.get("protoPayload", {})
        
        # ===== WHAT HAPPENED =====
        service_name = payload.get("serviceName", "unknown")
        method_name = payload.get("methodName", "unknown")
        event_type = method_name.replace("v1.", "").replace(".", "_")
        
        event_name_human = f"{service_name.split('.')[0].upper()} {method_name.split('.')[-1]}"
        event_description = f"GCP {service_name} operation: {method_name}"
        event_category = "management"
        
        # ===== WHO =====
        auth = payload.get("authenticationInfo", {})
        actor = auth.get("principalEmail", "unknown")
        actor_type = "service_account" if ".iam.gserviceaccount.com" in actor else "user"
        actor_arn = None  # GCP doesn't have ARN
        actor_ip = payload.get("requestMetadata", {}).get("callerIp")
        
        # ===== WHAT RESOURCE =====
        resource_name = payload.get("resourceName", "unknown")
        resource_type = data.get("resource", {}).get("type", "unknown")
        resource_details = {
            "project_id": data.get("resource", {}).get("labels", {}).get("project_id"),
            "zone": data.get("resource", {}).get("labels", {}).get("zone")
        }
        
        # ===== WHAT WAS DONE =====
        action = self._determine_action(method_name)
        action_details = {
            "service_name": service_name,
            "method_name": method_name,
            "request": payload.get("request", {})
        }
        
        # ===== RESULT =====
        response = payload.get("response", {})
        result = "success" if response and response.get("status") == "DONE" else "pending"
        result_details = {"response": response} if response else {}
        
        # ===== SEVERITY =====
        gcp_severity = data.get("severity", "INFO")
        severity, score, reason = self._determine_severity(gcp_severity, method_name)
        
        # ===== TIMING =====
        timestamp = datetime.fromisoformat(data.get("timestamp", "").replace("Z", "+00:00"))
        region = None  # GCP region is in resource name
        account_id = data.get("resource", {}).get("labels", {}).get("project_id")
        
        # ===== TAGS =====
        tags = self._generate_tags(gcp_severity, method_name)
        
        # ===== METADATA =====
        metadata = {
            "insert_id": data.get("insertId"),
            "log_name": data.get("logName"),
            "operation_id": data.get("operation", {}).get("id"),
            "receive_timestamp": data.get("receiveTimestamp")
        }
        
        return NormalizedEvent(
            # ===== REQUIRED FIELDS =====
            event_id=f"acip-{uuid.uuid4().hex[:12]}",
            provider="gcp",
            provider_type="audit_logs",
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
    
    def _determine_action(self, method_name: str) -> str:
        """Determine action type from method name"""
        if "insert" in method_name or "create" in method_name:
            return "create"
        elif "delete" in method_name:
            return "delete"
        elif "update" in method_name or "set" in method_name:
            return "modify"
        elif "start" in method_name:
            return "start"
        elif "stop" in method_name:
            return "stop"
        else:
            return "modify"
    
    def _determine_severity(self, severity: str, method_name: str) -> tuple:
        """Determine severity with reasoning"""
        if severity == "CRITICAL":
            return "CRITICAL", 10, "GCP Critical severity - immediate action required"
        elif severity == "ERROR":
            return "HIGH", 7, "GCP Error severity - operation failed"
        elif severity == "WARNING":
            return "MEDIUM", 4, "GCP Warning severity - requires review"
        else:
            # Check for sensitive operations
            if "iam" in method_name or "policy" in method_name:
                return "HIGH", 7, "GCP IAM/policy change - security sensitive"
            elif "compute" in method_name and "insert" in method_name:
                return "MEDIUM", 4, "GCP compute instance creation - requires review"
            else:
                return "LOW", 1, "Routine GCP informational event"
    
    def _generate_tags(self, severity: str, method_name: str) -> List[str]:
        """Generate tags for the event"""
        tags = []
        
        if severity in ["CRITICAL", "ERROR"]:
            tags.append("critical")
        if "iam" in method_name or "policy" in method_name:
            tags.append("security_change")
        if "compute" in method_name:
            tags.append("compute")
        if "storage" in method_name:
            tags.append("storage")
        
        return tags