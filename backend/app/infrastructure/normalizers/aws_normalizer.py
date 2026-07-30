"""
AWS Event Normalizer - Complete Version
Converts AWS events to ACIP format with FULL context for Risk Engine
"""
import json
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from .base import Normalizer
from ...domain.models.event import RawEvent, NormalizedEvent

logger = logging.getLogger(__name__)


class AWSNormalizer(Normalizer):
    """Normalizes AWS events to ACIP Internal format with complete context"""
    
    def get_provider(self) -> str:
        return "aws"
    
    def can_normalize(self, raw_event: RawEvent) -> bool:
        return raw_event.source == "aws"
    
    def normalize(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize AWS event with FULL context"""
        data = raw_event.data
        
        # Determine provider type from raw event
        provider_type = raw_event.provider
        
        # GuardDuty has different structure
        if provider_type == "guardduty" or data.get("service"):
            return self._normalize_guardduty(raw_event)
        
        # CloudTrail events (most common)
        if provider_type == "cloudtrail" or data.get("eventName"):
            return self._normalize_cloudtrail(raw_event)
        
        # S3 events
        if provider_type == "s3_events" or data.get("Records"):
            return self._normalize_s3(raw_event)
        
        # Fallback
        return self._normalize_generic_aws(raw_event)
    
    # ================================================================
    # CLOUDTRAIL NORMALIZER (Main)
    # ================================================================
    
    def _normalize_cloudtrail(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize AWS CloudTrail event with complete context"""
        try:
            data = raw_event.data
            
            # Extract the CloudTrailEvent JSON (nested)
            cloudtrail_event = data.get("CloudTrailEvent", {})
            if isinstance(cloudtrail_event, str):
                try:
                    cloudtrail_event = json.loads(cloudtrail_event)
                except json.JSONDecodeError:
                    cloudtrail_event = {}
            
            event_data = cloudtrail_event if cloudtrail_event else data
            
            # ===== BASIC EVENT INFO =====
            event_name = data.get("eventName", data.get("EventName", "unknown"))
            event_source = data.get("eventSource", data.get("EventSource", "unknown"))
            event_id = data.get("eventID", data.get("EventId", str(uuid.uuid4())))
            
            # ===== IDENTITY INFORMATION =====
            user_identity = event_data.get("userIdentity", {})
            identity_type = user_identity.get("type", "unknown").lower()
            
            actor_type_map = {
                "root": "root",
                "iamuser": "user",
                "assumedrole": "assumed_role",
                "federateduser": "federated_user",
                "awsservice": "service_account",
                "unknown": "unknown",
            }
            actor_type = actor_type_map.get(identity_type, "unknown")
            
            actor = user_identity.get("userName")
            if not actor or actor == "null":
                actor = user_identity.get("principalId", "unknown")
                if identity_type == "awsservice":
                    actor = user_identity.get("invokedBy", "unknown")
                elif identity_type == "assumedrole":
                    arn = user_identity.get("arn", "")
                    if "/" in arn:
                        actor = arn.split("/")[-1] if arn else "unknown"
                    else:
                        actor = user_identity.get("principalId", "unknown").split(":")[-1] if user_identity.get("principalId") else "unknown"
            
            actor_arn = user_identity.get("arn")
            actor_ip = event_data.get("sourceIPAddress") or data.get("sourceIPAddress")
            
            # ===== RESOURCE INFORMATION =====
            resources = data.get("resources", []) or event_data.get("resources", [])
            resource_name = "unknown"
            resource_type = "unknown"
            resource_details = {}
            
            if resources:
                for res in resources:
                    res_type = res.get("type", res.get("ResourceType", "")).lower()
                    res_name = res.get("ARN", res.get("ResourceName", ""))
                    if res_name and res_name != "unknown":
                        resource_name = res_name
                        resource_type = res_type
                        resource_details = {
                            "arn": res_name,
                            "type": res_type,
                            "account_id": res.get("accountId", res.get("AccountId")),
                            "region": res.get("region", res.get("Region")),
                        }
                        break
                
                if resource_name == "unknown":
                    resource_name = resources[0].get("ARN", resources[0].get("ResourceName", "unknown"))
                    resource_type = resources[0].get("type", resources[0].get("ResourceType", "unknown"))
            
            # ===== REQUEST AND RESPONSE =====
            request_params = data.get("requestParameters", event_data.get("requestParameters", {}))
            response_elements = data.get("responseElements", event_data.get("responseElements", {}))
            
            is_read_only = data.get("readOnly", event_data.get("readOnly", False))
            if isinstance(is_read_only, str):
                is_read_only = is_read_only.lower() == "true"
            
            # ===== TIMING - FIXED =====
            event_time = data.get("eventTime", data.get("EventTime", ""))
            
            if event_time:
                try:
                    if isinstance(event_time, datetime):
                        timestamp = event_time
                    elif isinstance(event_time, str):
                        clean_time = event_time.replace("Z", "+00:00")
                        timestamp = datetime.fromisoformat(clean_time)
                    else:
                        timestamp = raw_event.timestamp
                except Exception:
                    timestamp = raw_event.timestamp
            else:
                timestamp = raw_event.timestamp
            
            # ===== REGION AND ACCOUNT =====
            region = data.get("awsRegion", data.get("AwsRegion", event_data.get("awsRegion")))
            account_id = data.get("recipientAccountId", data.get("AccountId", event_data.get("accountId")))
            
            # ===== SEVERITY =====
            severity, severity_score, severity_reason = self._determine_severity_context(
                event_name=event_name,
                identity_type=identity_type,
                actor_ip=actor_ip,
                request_params=request_params,
                is_read_only=is_read_only,
                data=data,
            )
            
            # ===== EVENT CATEGORY =====
            event_category = "management"
            if "data" in str(request_params) or "s3" in str(event_source):
                event_category = "data_plane"
            if identity_type == "awsservice":
                event_category = "system"
            
            # ===== ACTION =====
            action = self._determine_action(event_name)
            
            # ===== TAGS =====
            tags = self._generate_enhanced_tags(
                event_name=event_name,
                identity_type=identity_type,
                actor_ip=actor_ip,
                request_params=request_params,
                is_read_only=is_read_only,
                data=data,
            )
            
            # ===== METADATA =====
            metadata = {
                "identity_type": identity_type,
                "user_identity": user_identity,
                "event_source": event_source,
                "event_id": event_id,
                "user_agent": event_data.get("userAgent") or data.get("userAgent"),
                "invoked_by": user_identity.get("invokedBy"),
                "session_context": user_identity.get("sessionContext", {}),
                "request_id": data.get("requestID", event_data.get("requestID")),
                "is_read_only": is_read_only,
                "management_event": data.get("managementEvent", event_data.get("managementEvent", False)),
                "event_category": event_category,
                "raw_cloudtrail_event": cloudtrail_event,
            }
            
            # ===== BUILD NORMALIZED EVENT =====
            return NormalizedEvent(
                event_id=f"acip-{uuid.uuid4().hex[:12]}",
                provider="aws",
                provider_type="cloudtrail",
                event_type=self._map_event_type(event_name),
                event_name=event_name,
                event_description=self._generate_description(
                    event_name=event_name,
                    actor=actor,
                    resource_name=resource_name,
                    identity_type=identity_type,
                ),
                event_category=event_category,
                actor=actor,
                actor_type=actor_type,
                actor_arn=actor_arn,
                actor_ip=actor_ip,
                resource=resource_name,
                resource_type=resource_type,
                resource_details=resource_details,
                action=action,
                action_details={"request_parameters": request_params},
                result="success" if response_elements else "pending",
                result_details={"response": response_elements} if response_elements else {},
                severity=severity,
                severity_score=severity_score,
                severity_reason=severity_reason,
                timestamp=timestamp,
                region=region,
                account_id=account_id,
                tags=tags,
                related_events=[],
                metadata=metadata,
                raw_event=data,
            )
            
        except Exception as e:
            logger.error(f"❌ FATAL ERROR in _normalize_cloudtrail: {e}")
            import traceback
            traceback.print_exc()
            raise
    
  
    # ================================================================
    # S3 NORMALIZER
    # ================================================================
    
    def _normalize_s3(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize AWS S3 event with complete context"""
        data = raw_event.data
        records = data.get("Records", [{}])[0]
        
        event_name = records.get("eventName", "unknown")
        event_source = records.get("eventSource", "s3.amazonaws.com")
        
        # S3 bucket and object
        s3 = records.get("s3", {})
        bucket = s3.get("bucket", {})
        obj = s3.get("object", {})
        
        bucket_name = bucket.get("name", "unknown")
        object_key = obj.get("key", "unknown")
        
        resource = f"s3://{bucket_name}/{object_key}"
        resource_type = "S3 Object"
        
        # User identity
        user = records.get("userIdentity", {})
        actor = user.get("principalId", "unknown")
        actor_type = "service"
        
        # Source IP
        actor_ip = records.get("requestParameters", {}).get("sourceIPAddress")
        
        # Timestamp
        timestamp = datetime.fromisoformat(records.get("eventTime", "").replace("Z", "+00:00"))
        
        # Region
        region = records.get("awsRegion")
        
        # Severity (S3 events are typically low risk)
        severity = "LOW"
        severity_score = 1
        severity_reason = "S3 object operation - routine"
        
        # Determine if this is a high-risk S3 operation
        if "Delete" in event_name:
            severity = "MEDIUM"
            severity_score = 4
            severity_reason = "S3 object deletion - potential data loss"
        elif "Put" in event_name:
            severity = "LOW"
            severity_score = 1
            severity_reason = "S3 object upload - routine"
        
        return NormalizedEvent(
            event_id=f"acip-{uuid.uuid4().hex[:12]}",
            provider="aws",
            provider_type="s3_events",
            event_type=event_name.lower(),
            event_name=f"S3 {event_name}",
            event_description=f"{event_name} on s3://{bucket_name}/{object_key}",
            event_category="data_plane",
            actor=actor,
            actor_type=actor_type,
            actor_arn=None,
            actor_ip=actor_ip,
            resource=resource,
            resource_type=resource_type,
            resource_details={
                "bucket": bucket_name,
                "object_key": object_key,
                "size": obj.get("size"),
                "e_tag": obj.get("eTag"),
                "version_id": obj.get("versionId"),
            },
            action=event_name.lower().replace("object", ""),
            action_details={"user_agent": records.get("userAgent")},
            result="success",
            result_details={"request_id": records.get("responseElements", {}).get("x-amz-request-id")},
            severity=severity,
            severity_score=severity_score,
            severity_reason=severity_reason,
            timestamp=timestamp,
            region=region,
            account_id=None,
            tags=["s3", "data_operation"],
            related_events=[],
            metadata={"configuration_id": s3.get("configurationId")},
            raw_event=data,
        )
    
    # ================================================================
    # GENERIC AWS NORMALIZER (Fallback)
    # ================================================================
    
    def _normalize_generic_aws(self, raw_event: RawEvent) -> NormalizedEvent:
        """Fallback normalization for unknown AWS events"""
        data = raw_event.data
        
        # Try to extract basic info
        user_identity = data.get("userIdentity", {})
        actor = user_identity.get("userName", "unknown")
        event_name = data.get("eventName", data.get("EventName", "unknown"))
        
        return NormalizedEvent(
            event_id=f"acip-{uuid.uuid4().hex[:12]}",
            provider="aws",
            provider_type="unknown",
            event_type=event_name.lower(),
            event_name=event_name,
            event_description=f"AWS event: {event_name}",
            event_category="unknown",
            actor=actor,
            actor_type="unknown",
            actor_arn=user_identity.get("arn"),
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
            severity_reason="Unknown AWS event type",
            timestamp=raw_event.timestamp,
            region=data.get("awsRegion"),
            account_id=data.get("recipientAccountId"),
            tags=[],
            related_events=[],
            metadata={"note": "Generic AWS normalization - review raw event"},
            raw_event=data,
        )
    
    # ================================================================
    # HELPER METHODS
    # ================================================================
    
    def _determine_severity_context(
        self,
        event_name: str,
        identity_type: str,
        actor_ip: Optional[str],
        request_params: Dict,
        is_read_only: bool,
        data: Dict,
    ) -> tuple:
        """
        Context-aware severity determination for Risk Engine.
        """
        try:
            # 1. Event Type Base Score
            event_scores = {
                "DeleteTrail": 40,
                "StopLogging": 40,
                "AttachUserPolicy": 40,
                "AttachRolePolicy": 35,
                "PutBucketPolicy": 35,
                "CreateUser": 30,
                "CreateRole": 30,
                "DeleteUser": 25,
                "DeleteRole": 25,
                "AuthorizeSecurityGroupIngress": 35,
                "RevokeSecurityGroupIngress": 25,
                "ConsoleLogin": 20,
                "AssumeRole": 15,
                "CreateKeyPair": 10,
                "RunInstances": 20,
                "TerminateInstances": 25,
                "CreateBucket": 10,
                "DeleteBucket": 20,
                "CreateAccessKey": 25,
                "DeleteAccessKey": 20,
                "GetCallerIdentity": 5,
                "ListImages": 5,
                "DescribeSpotFleetRequests": 5,
                "ListVoiceConnectors": 5,
                "ListTopicRules": 5,
                "DescribeReplicationSubnetGroups": 5,
                "LookupEvents": 5,
            }
            
            # Get base score
            base_score = event_scores.get(event_name, 5)
            
            # ✅ FORCE INTEGER
            try:
                base_score = int(base_score)
            except (TypeError, ValueError):
                base_score = 5
            
            # 2. Identity Modifier
            identity_modifiers = {
                "root": 2.0,
                "assumedrole": 1.5,
                "federateduser": 1.3,
                "user": 1.0,
                "service_account": 0.8,
                "unknown": 1.0,
            }
            modifier = identity_modifiers.get(identity_type, 1.0)
            
            # ✅ FORCE FLOAT
            try:
                modifier = float(modifier)
            except (TypeError, ValueError):
                modifier = 1.0
            
            # 3. Read-only
            if is_read_only:
                modifier *= 0.7
            
            # 4. Public IP
            if actor_ip and not (
                actor_ip.startswith("192.168.") or
                actor_ip.startswith("10.") or
                actor_ip.startswith("172.16.") or
                actor_ip == "127.0.0.1" or
                ".amazonaws.com" in actor_ip or
                ".amazonaws" in actor_ip
            ):
                modifier *= 1.3
            
            # 5. Off-hours
            try:
                event_time = data.get("eventTime", "")
                if event_time:
                    dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                    hour = dt.hour
                    if hour < 6 or hour > 22:
                        modifier *= 1.5
            except Exception:
                pass
            
            # ✅ CALCULATE FINAL SCORE
            final_score = int(base_score * modifier)
            final_score = max(0, min(100, final_score))
            
            # ✅ FORCE INTEGER FOR SEVERITY_SCORE
            severity_score = int(final_score)
            
            # Determine severity
            if final_score >= 70:
                severity = "CRITICAL"
            elif final_score >= 50:
                severity = "HIGH"
            elif final_score >= 30:
                severity = "MEDIUM"
            elif final_score >= 10:
                severity = "LOW"
            else:
                severity = "INFO"
            
            return severity, severity_score, f"Base: {base_score} | Modifier: {modifier:.1f}x → Score: {severity_score}"
            
        except Exception as e:
            logger.error(f"Error in severity calculation: {e}")
            # ✅ Return valid types
            return "LOW", 0, f"Error: {str(e)}"
    
    def _generate_enhanced_tags(
        self,
        event_name: str,
        identity_type: str,
        actor_ip: Optional[str],
        request_params: Dict,
        is_read_only: bool,
        data: Dict,
    ) -> List[str]:
        """Generate enhanced tags for Risk Engine"""
        tags = []
        
        # Event type tags
        if "Delete" in event_name or "Stop" in event_name:
            tags.append("destructive")
        if "Attach" in event_name or "Create" in event_name:
            tags.append("privilege_change")
        if "Login" in event_name or "AssumeRole" in event_name:
            tags.append("authentication")
        
        # Identity tags
        if identity_type == "root":
            tags.append("root_user")
        elif identity_type == "assumedrole":
            tags.append("assumed_role")
        
        # Risk tags
        if actor_ip and not (
            actor_ip.startswith("192.168.") or
            actor_ip.startswith("10.") or
            actor_ip.startswith("172.16.") or
            actor_ip == "127.0.0.1"
        ):
            tags.append("public_ip")
        
        # Read-only
        if is_read_only:
            tags.append("read_only")
        else:
            tags.append("write_operation")
        
        # Management event
        if data.get("managementEvent", False):
            tags.append("management_event")
        
        return list(set(tags))
    
    def _generate_description(
        self,
        event_name: str,
        actor: str,
        resource_name: str,
        identity_type: str,
    ) -> str:
        """Generate a rich description"""
        parts = []
        parts.append(f"Event: {event_name}")
        parts.append(f"Actor: {actor} ({identity_type})")
        parts.append(f"Resource: {resource_name}")
        return " | ".join(parts)
    
    def _determine_action(self, event_name: str) -> str:
        """Determine the action type"""
        if event_name.startswith("Create"):
            return "create"
        elif event_name.startswith("Delete") or event_name.startswith("Terminate"):
            return "delete"
        elif event_name.startswith("Attach"):
            return "attach"
        elif event_name.startswith("Detach"):
            return "detach"
        elif "Login" in event_name or "AssumeRole" in event_name:
            return "authenticate"
        elif "Modify" in event_name or "Update" in event_name:
            return "modify"
        elif "Put" in event_name or "Set" in event_name:
            return "write"
        elif "Get" in event_name or "List" in event_name or "Describe" in event_name:
            return "read"
        else:
            return "modify"
    
    def _map_event_type(self, event_name: str) -> str:
        """Map AWS event name to normalized event type"""
        mapping = {
            "AttachUserPolicy": "attach_policy",
            "DetachUserPolicy": "detach_policy",
            "AttachRolePolicy": "attach_policy",
            "DetachRolePolicy": "detach_policy",
            "CreateUser": "create_user",
            "DeleteUser": "delete_user",
            "CreateRole": "create_role",
            "DeleteRole": "delete_role",
            "ConsoleLogin": "console_login",
            "AssumeRole": "assume_role",
            "CreateKeyPair": "create_key_pair",
            "DeleteKeyPair": "delete_key_pair",
            "AuthorizeSecurityGroupIngress": "security_group_modify",
            "RevokeSecurityGroupIngress": "security_group_modify",
            "RunInstances": "run_instances",
            "TerminateInstances": "terminate_instances",
            "CreateBucket": "create_bucket",
            "DeleteBucket": "delete_bucket",
            "PutBucketPolicy": "put_bucket_policy",
            "DeleteBucketPolicy": "delete_bucket_policy",
            "CreateAccessKey": "create_access_key",
            "DeleteAccessKey": "delete_access_key",
            "DeleteTrail": "delete_trail",
            "StopLogging": "stop_logging",
            "StartLogging": "start_logging",
            "UpdateTrail": "update_trail",
        }
        return mapping.get(event_name, event_name.lower())
    
    def _gd_severity_to_acip(self, gd_severity: int) -> str:
        """Convert GuardDuty severity (0-10) to ACIP severity"""
        if gd_severity >= 8:
            return "CRITICAL"
        elif gd_severity >= 6:
            return "HIGH"
        elif gd_severity >= 4:
            return "MEDIUM"
        elif gd_severity >= 1:
            return "LOW"
        else:
            return "INFO"