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
from ...risk.threat_intel import ThreatIntelManager


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
            
            # ===== TIMING =====
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
            
            # ===== THREAT INTELLIGENCE =====
            threat_intel = self._get_threat_intel(actor_ip)
            
            # ===== SEVERITY (WITH THREAT INTEL) =====
            severity, severity_score, severity_reason = self._determine_severity_context(
                event_name=event_name,
                identity_type=identity_type,
                actor_ip=actor_ip,
                request_params=request_params,
                is_read_only=is_read_only,
                data=data,
                threat_intel=threat_intel,
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
                threat_intel=threat_intel,
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
                threat_intel=threat_intel,
                raw_event=data,
            )
            
        except Exception as e:
            logger.error(f"❌ FATAL ERROR in _normalize_cloudtrail: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    # ================================================================
    # GUARDDUTY NORMALIZER
    # ================================================================
    
    
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
        
        # ===== THREAT INTELLIGENCE =====
        threat_intel = self._get_threat_intel(actor_ip)
        
        # Severity (S3 events are typically low risk)
        severity = "LOW"
        severity_score = 1
        severity_reason = "S3 object operation - routine"
        
        # Determine if this is a high-risk S3 operation
        if "Delete" in event_name:
            severity = "MEDIUM"
            severity_score = 4
            severity_reason = "S3 object deletion - potential data loss"
            
            # Increase severity if malicious IP
            if threat_intel and threat_intel.get("is_malicious", False):
                severity = "HIGH"
                severity_score = 50
                severity_reason = "S3 object deletion from malicious IP"
                
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
            threat_intel=threat_intel,
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
        
        # ===== THREAT INTELLIGENCE =====
        actor_ip = data.get("sourceIPAddress")
        threat_intel = self._get_threat_intel(actor_ip)
        
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
            actor_ip=actor_ip,
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
            threat_intel=threat_intel,
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
        threat_intel: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """
        Context-aware severity determination for Risk Engine.
        """
        try:
            reasons = []
            
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
            reasons.append(f"Event: {event_name} (base: {base_score})")
            
            # FORCE INTEGER
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
            reasons.append(f"Identity: {identity_type} ({modifier}x)")
            
            # FORCE FLOAT
            try:
                modifier = float(modifier)
            except (TypeError, ValueError):
                modifier = 1.0
            
            # 3. Read-only
            if is_read_only:
                modifier *= 0.7
                reasons.append("Read-only operation (0.7x)")
            
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
                reasons.append("Public IP (1.3x)")
            
            # 5. Off-hours
            try:
                event_time = data.get("eventTime", "")
                if event_time:
                    dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                    hour = dt.hour
                    if hour < 6 or hour > 22:
                        modifier *= 1.5
                        reasons.append("Off-hours activity (1.5x)")
            except Exception:
                pass

            # ===== 6. THREAT INTELLIGENCE =====
            if threat_intel and threat_intel.get("checked", False):
                modifier *= threat_intel["modifier"]
                is_malicious = threat_intel.get("is_malicious", False)
                confidence = threat_intel.get("confidence", 0)
                categories = threat_intel.get("categories", [])
                
                if is_malicious:
                    reasons.append(f"Malicious IP (AbuseIPDB: {confidence}%, categories: {', '.join(categories[:3])}) - {threat_intel['modifier']}x")
                elif confidence > 50:
                    reasons.append(f"Suspicious IP (AbuseIPDB: {confidence}%) - {threat_intel['modifier']}x")
            
            # CALCULATE FINAL SCORE
            final_score = int(base_score * modifier)
            final_score = max(0, min(100, final_score))
            
            # FORCE INTEGER FOR SEVERITY_SCORE
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
            
            # Build the severity reason with all factors
            severity_reason = f"Base: {base_score} | Modifier: {modifier:.1f}x | Score: {severity_score} | Factors: {', '.join(reasons)}"
            
            return severity, severity_score, severity_reason
            
        except Exception as e:
            logger.error(f"Error in severity calculation: {e}")
            return "LOW", 0, f"Error: {str(e)}"

    def _get_threat_intel(self, actor_ip: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Get threat intelligence for an IP address.
        Returns None if no threat intel available.
        """
        logger.info(f"🔍 _get_threat_intel called with actor_ip: {actor_ip}")
        
        if not actor_ip:
            logger.info("   ❌ actor_ip is None or empty")
            return {
                "checked": False,
                "is_malicious": False,
                "reason": "No IP address provided",
            }
        
        # Skip private IPs
        if self._is_private_ip(actor_ip):
            logger.info(f"   ❌ {actor_ip} is private/internal")
            return {
                "checked": False,
                "is_malicious": False,
                "reason": "Private/internal IP - threat intel not applicable",
            }
        
        # Skip domain names (not IP addresses)
        if self._is_domain_name(actor_ip):
            logger.info(f"   ❌ {actor_ip} is a domain name")
            return {
                "checked": False,
                "is_malicious": False,
                "reason": f"Domain name '{actor_ip}' - threat intel requires IP address",
            }
        
        logger.info(f"   ✅ {actor_ip} is a valid public IP, checking threat intel...")
        
        try:
            manager = ThreatIntelManager()
            logger.info("   ✅ ThreatIntelManager imported successfully")
            
            result = manager.get_ip_reputation(actor_ip)
            logger.info(f"   ✅ Threat intel result: {result}")
            
            if result and result.get("checked", False):
                logger.info("   ✅ Threat intel found!")
                return {
                    "checked": True,
                    "is_malicious": result.get("is_malicious", False),
                    "provider": result.get("provider"),
                    "confidence": result.get("confidence", 0),
                    "modifier": result.get("modifier", 1.0),
                    "categories": result.get("categories", []),
                    "details": result.get("details", {}),
                }
            else:
                logger.info("   ❌ Threat intel result returned 'checked': False")
                
        except ImportError as e:
            logger.error(f"   ❌ Import error: {e}")
        except Exception as e:
            logger.error(f"   ❌ Threat intel lookup failed: {e}")
            import traceback
            traceback.print_exc()
        
        return {
            "checked": False,
            "is_malicious": False,
            "reason": "No threat intelligence available or lookup failed",
        }


    def _is_domain_name(self, value: str) -> bool:
        """
        Check if a string is a domain name (not an IP address).
        
        Examples:
        - "resource-explorer-2.amazonaws.com" → True (domain)
        - "8.8.8.8" → False (IP address)
        - "203.0.113.1" → False (IP address)
        """
        if not value:
            return True
        
        # Check if it's an IP address (contains only numbers and dots)
        parts = value.split(".")
        
        # If it has 4 parts and all are numbers, it's an IP
        if len(parts) == 4:
            for part in parts:
                if not part.isdigit():
                    return True  # Contains non-digit, so it's a domain
            return False  # All digits, so it's an IP
        
        # If it has 6 parts with colons, it's IPv6
        if ":" in value:
            return False
        
        # Otherwise, it's a domain name
        return True

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal or a domain name"""
        if not ip:
            return True
        
        # Domain names are not IPs
        if "." in ip and not all(part.isdigit() for part in ip.split(".") if part):
            return True
        
        private_ranges = [
            "10.",
            "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "127.",
            "169.254.",
            "::1",
        ]
        
        for prefix in private_ranges:
            if ip.startswith(prefix):
                return True
        
        return False

    def _generate_enhanced_tags(
        self,
        event_name: str,
        identity_type: str,
        actor_ip: Optional[str],
        request_params: Dict,
        is_read_only: bool,
        data: Dict,
        threat_intel: Optional[Dict[str, Any]] = None,
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
        
        # Threat intelligence tags
        if threat_intel and threat_intel.get("checked", False):
            if threat_intel.get("is_malicious", False):
                tags.append("malicious_ip")
            if threat_intel.get("confidence", 0) >= 75:
                tags.append("high_confidence_threat")
        
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