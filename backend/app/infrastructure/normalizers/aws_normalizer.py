"""
AWS Event Normalizer - RICH version
Converts AWS events to ACIP format with FULL context
"""
import uuid
from datetime import datetime
from typing import Dict, Any, List
from .base import Normalizer
from ...domain.models.event import RawEvent, NormalizedEvent


class AWSNormalizer(Normalizer):
    """Normalizes AWS events to ACIP Internal format - RICH version"""
    
    def get_provider(self) -> str:
        return "aws"
    
    def can_normalize(self, raw_event: RawEvent) -> bool:
        return raw_event.source == "aws"
    
    def normalize(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize AWS event with FULL context"""
        data = raw_event.data
        
        if raw_event.provider == "cloudtrail":
            return self._normalize_cloudtrail(raw_event)
        elif raw_event.provider == "guardduty":
            return self._normalize_guardduty(raw_event)
        elif raw_event.provider == "s3_events":
            return self._normalize_s3(raw_event)
        elif raw_event.provider == "iam":
            return self._normalize_iam(raw_event)
        else:
            return self._normalize_generic_aws(raw_event)
    
    def _normalize_iam(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize IAM event with FULL context"""
        data = raw_event.data

        event_name = data.get("eventName", "unknown")

        # ===== WHAT HAPPENED =====
        event_type = self._map_event_type(event_name)
        event_name_human = self._get_human_event_name(event_name)
        event_description = self._get_event_description(event_name, data)
        event_category = "management"

        # ===== WHO =====
        user = data.get("userIdentity", {})
        actor = user.get("userName", "unknown")
        actor_type = "user" if "userName" in user else "service"
        actor_arn = user.get("arn")
        actor_ip = data.get("sourceIPAddress")

        # ===== WHAT RESOURCE =====
        resources = data.get("resources", [])
        resource_obj = resources[0] if resources else {}
        resource = resource_obj.get("ARN", "unknown")
        resource_type = resource_obj.get("type", "unknown").replace("AWS::", "")
        resource_details = self._extract_resource_details(data)

        # ===== WHAT WAS DONE =====
        action = self._determine_action(event_name)
        action_details = {
        "request_parameters": data.get("requestParameters", {}),
        "request_id": data.get("eventID")
        }

        # ===== RESULT =====
        response = data.get("responseElements", {})
        result = "success" if response else "pending"
        result_details = {"response": response} if response else {"note": "No response elements"}

        # ===== SEVERITY =====
        severity, score, reason = self._determine_severity(event_name, data)

        # ===== TIMING =====
        timestamp = datetime.fromisoformat(data.get("eventTime", "").replace("Z", "+00:00"))
        region = data.get("awsRegion")
        account_id = data.get("recipientAccountId")

        # ===== TAGS =====
        tags = self._generate_tags(event_name, data)

        # ===== METADATA =====
        metadata = {
        "user_agent": data.get("userAgent"),
        "event_source": data.get("eventSource"),
        "management_event": data.get("managementEvent", False),
        "read_only": data.get("readOnly", False)
        }

        return NormalizedEvent(
        # ===== REQUIRED FIELDS (All must be provided) =====
        event_id=f"acip-{uuid.uuid4().hex[:12]}",
        provider="aws",
        provider_type="iam",
        event_type=event_type,
        event_name=event_name_human,
        event_description=event_description,
        event_category=event_category,
        actor=actor,
        actor_type=actor_type,
        resource=resource,
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
    
    def _normalize_cloudtrail(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize CloudTrail event with FULL context"""
        data = raw_event.data
        event_name = data.get("eventName", "unknown")
        
        # Similar to IAM but with CloudTrail specifics
        # Extract all relevant fields...
        
        # For brevity, using generic normalization
        return self._normalize_iam(raw_event)
    
    def _normalize_s3(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize S3 event with FULL context"""
        data = raw_event.data
        records = data.get("Records", [{}])[0]
        event_name = records.get("eventName", "unknown")
        
        # Extract S3-specific details
        s3 = records.get("s3", {})
        bucket = s3.get("bucket", {})
        obj = s3.get("object", {})
        
        resource = f"s3://{bucket.get('name', 'unknown')}/{obj.get('key', 'unknown')}"
        resource_type = "S3 Object"
        resource_details = {
            "bucket": bucket.get("name"),
            "object_key": obj.get("key"),
            "size": obj.get("size"),
            "e_tag": obj.get("eTag"),
            "version_id": obj.get("versionId")
        }
        
        # Build rich event
        return NormalizedEvent(
            event_id=f"acip-{uuid.uuid4().hex[:12]}",
            provider="aws",
            provider_type="s3_events",
            event_type=event_name.lower(),
            event_name=f"S3 {event_name}",
            event_description=f"Object {event_name.lower()} in bucket {bucket.get('name')}",
            event_category="data_plane",
            actor=records.get("userIdentity", {}).get("principalId", "unknown"),
            actor_type="service",
            actor_arn=None,
            actor_ip=records.get("requestParameters", {}).get("sourceIPAddress"),
            resource=resource,
            resource_type=resource_type,
            resource_details=resource_details,
            action=event_name.lower().replace("object", ""),
            action_details={"user_agent": records.get("userAgent")},
            result="success",
            result_details={"request_id": records.get("responseElements", {}).get("x-amz-request-id")},
            severity="LOW",
            severity_score=1,
            severity_reason="S3 object operations are routine and low risk",
            timestamp=datetime.fromisoformat(records.get("eventTime", "").replace("Z", "+00:00")),
            region=records.get("awsRegion"),
            account_id=None,
            tags=[],
            related_events=[],
            metadata={"configuration_id": s3.get("configurationId")},
            raw_event=data
        )
    
    # ===== HELPER METHODS =====
    
    def _map_event_type(self, event_name: str) -> str:
        """Map AWS event name to normalized event type"""
        mapping = {
            "AttachUserPolicy": "attach_policy",
            "DetachUserPolicy": "detach_policy",
            "CreateUser": "create_user",
            "DeleteUser": "delete_user",
            "CreateRole": "create_role",
            "DeleteRole": "delete_role",
            "ConsoleLogin": "console_login",
            "CreateKeyPair": "create_key_pair",
            "AuthorizeSecurityGroupIngress": "security_group_modify",
        }
        return mapping.get(event_name, event_name.lower())
    
    def _get_human_event_name(self, event_name: str) -> str:
        """Get human readable event name"""
        names = {
            "AttachUserPolicy": "IAM Policy Attached",
            "DetachUserPolicy": "IAM Policy Detached",
            "CreateUser": "IAM User Created",
            "DeleteUser": "IAM User Deleted",
            "CreateRole": "IAM Role Created",
            "DeleteRole": "IAM Role Deleted",
            "ConsoleLogin": "Console Login",
            "CreateKeyPair": "Key Pair Created",
            "AuthorizeSecurityGroupIngress": "Security Group Modified"
        }
        return names.get(event_name, event_name.replace("_", " ").title())
    
    def _get_event_description(self, event_name: str, data: Dict) -> str:
        """Generate a rich description"""
        user = data.get("userIdentity", {}).get("userName", "unknown")
        resources = data.get("resources", [])
        resource = resources[0].get("ARN", "unknown") if resources else "unknown"
        
        descriptions = {
            "AttachUserPolicy": f"User {user} attached a policy to {resource}",
            "DetachUserPolicy": f"User {user} detached a policy from {resource}",
            "CreateUser": f"User {user} created a new IAM user",
            "DeleteUser": f"User {user} deleted an IAM user",
            "ConsoleLogin": f"User {user} logged into AWS Console from {data.get('sourceIPAddress', 'unknown')}"
        }
        return descriptions.get(event_name, f"{event_name} by {user}")
    
    def _determine_action(self, event_name: str) -> str:
        """Determine the action type"""
        if event_name.startswith("Create"):
            return "create"
        elif event_name.startswith("Delete"):
            return "delete"
        elif event_name.startswith("Attach"):
            return "attach"
        elif event_name.startswith("Detach"):
            return "detach"
        elif "Login" in event_name:
            return "authenticate"
        else:
            return "modify"
    
    def _extract_resource_details(self, data: Dict) -> Dict:
        """Extract all resource details"""
        resources = data.get("resources", [])
        if not resources:
            return {}
        
        return {
            "arn": resources[0].get("ARN"),
            "type": resources[0].get("type"),
            "account_id": resources[0].get("accountId"),
            "region": resources[0].get("region")
        }
    
    def _determine_severity(self, event_name: str, data: Dict) -> tuple:
        """Determine severity with reasoning"""
        # CRITICAL: Privilege escalation, security policy changes
        if event_name in ["AttachUserPolicy", "CreateRole"]:
            return "CRITICAL", 10, f"{event_name} can lead to privilege escalation"
        
        # HIGH: User/role creation, security group modifications
        elif event_name in ["CreateUser", "AuthorizeSecurityGroupIngress"]:
            return "HIGH", 7, f"{event_name} requires security review"
        
        # MEDIUM: Deletions, key pair creation
        elif event_name in ["DeleteUser", "CreateKeyPair"]:
            return "MEDIUM", 4, f"{event_name} changes IAM configuration"
        
        # LOW: Routine operations
        else:
            return "LOW", 1, "Routine IAM operation"
    
    def _generate_tags(self, event_name: str, data: Dict) -> List[str]:
        """Generate tags for the event"""
        tags = []
        
        # Check for suspicious IP
        ip = data.get("sourceIPAddress", "")
        if ip and ip.startswith("192.168"):
            tags.append("internal_ip")
        
        # Check for high severity operations
        if event_name in ["AttachUserPolicy", "CreateRole"]:
            tags.append("privilege_escalation")
        
        # Check management events
        if data.get("managementEvent", False):
            tags.append("management_event")
        
        return tags
    
    def _normalize_guardduty(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize GuardDuty finding with FULL context"""
        data = raw_event.data
        
        return NormalizedEvent(
            event_id=f"acip-{uuid.uuid4().hex[:12]}",
            provider="aws",
            provider_type="guardduty",
            event_type=data.get("type", "unknown").lower(),
            event_name="GuardDuty Finding",
            event_description=data.get("description", "Security finding from GuardDuty"),
            event_category="security",
            actor=data.get("service", {}).get("action", {}).get("awsApiCallAction", {}).get("api", "unknown"),
            actor_type="api_call",
            actor_arn=None,
            actor_ip=None,
            resource=data.get("resource", {}).get("instanceDetails", {}).get("instanceId", "unknown"),
            resource_type="EC2 Instance",
            resource_details=data.get("resource", {}),
            action="detected",
            action_details={"finding_type": data.get("type")},
            result="alert",
            result_details={"severity": data.get("severity")},
            severity=self._gd_severity_to_acip(data.get("severity", 0)),
            severity_score=data.get("severity", 5),
            severity_reason="GuardDuty finding requires immediate attention",
            timestamp=datetime.fromisoformat(data.get("updatedAt", "").replace("Z", "+00:00")),
            region=data.get("region"),
            account_id=data.get("accountId"),
            tags=["security_finding", "guardduty"],
            related_events=[],
            metadata={
                "finding_id": data.get("id"),
                "title": data.get("title"),
                "count": data.get("service", {}).get("count", 1)
            },
            raw_event=data
        )
    
    def _gd_severity_to_acip(self, gd_severity: int) -> str:
        """Convert GuardDuty severity to ACIP severity"""
        if gd_severity >= 8:
            return "CRITICAL"
        elif gd_severity >= 6:
            return "HIGH"
        elif gd_severity >= 4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _normalize_generic_aws(self, raw_event: RawEvent) -> NormalizedEvent:
        """Fallback normalization for unknown AWS events"""
        data = raw_event.data
        
        return NormalizedEvent(
            event_id=f"acip-{uuid.uuid4().hex[:12]}",
            provider="aws",
            provider_type="unknown",
            event_type="unknown",
            event_name="Unknown AWS Event",
            event_description="AWS event that could not be fully normalized",
            event_category="unknown",
            actor=data.get("userIdentity", {}).get("userName", "unknown"),
            actor_type="unknown",
            actor_arn=data.get("userIdentity", {}).get("arn"),
            actor_ip=data.get("sourceIPAddress"),
            resource="unknown",
            resource_type="unknown",
            resource_details={},
            action="unknown",
            action_details={},
            result="unknown",
            result_details={},
            severity="INFO",
            severity_score=0,
            severity_reason="Unknown event type",
            timestamp=raw_event.timestamp,
            region=data.get("awsRegion"),
            account_id=data.get("recipientAccountId"),
            tags=[],
            related_events=[],
            metadata={"note": "Generic AWS normalization - review raw event"},
            raw_event=data
        )