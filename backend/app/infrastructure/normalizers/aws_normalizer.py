"""
AWS Event Normalizer - CloudTrail Only
Converts AWS CloudTrail events to ACIP format with FULL context for Risk Engine
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
    """Normalizes AWS CloudTrail events to ACIP Internal format"""
    
    def get_provider(self) -> str:
        return "aws"
    
    def can_normalize(self, raw_event: RawEvent) -> bool:
        return raw_event.source == "aws"
    
    def normalize(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalize AWS CloudTrail event with FULL context"""
        data = raw_event.data
        
        # Only handle CloudTrail events
        if raw_event.provider == "cloudtrail" or data.get("eventName"):
            return self._normalize_cloudtrail(raw_event)
        
        # Fallback for unknown AWS events
        return self._normalize_generic_aws(raw_event)
    
    # ================================================================
    # CLOUDTRAIL NORMALIZER
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
                        clean_time = event_time
                        if " " in clean_time and "T" not in clean_time:
                            clean_time = clean_time.replace(" ", "T")
                        if "+" in clean_time:
                            timestamp = datetime.fromisoformat(clean_time)
                        else:
                            clean_time = clean_time.replace("Z", "+00:00")
                            timestamp = datetime.fromisoformat(clean_time)
                    else:
                        timestamp = raw_event.timestamp
                except Exception as e:
                    logger.warning(f"Could not parse timestamp '{event_time}': {e}")
                    timestamp = raw_event.timestamp
            else:
                timestamp = raw_event.timestamp
            
            # ✅ EXTRACT HOUR AND DAY OF WEEK
            hour = timestamp.hour if timestamp else 0
            day_of_week = timestamp.strftime("%A").lower() if timestamp else "unknown"
            
            # ===== REGION AND ACCOUNT =====
            region = data.get("awsRegion", data.get("AwsRegion", event_data.get("awsRegion")))
            account_id = data.get("recipientAccountId", data.get("AccountId", event_data.get("accountId")))
            
            # ===== THREAT INTELLIGENCE =====
            threat_intel = self._get_threat_intel(actor_ip)
            
            # ✅ BUILD NORMALIZED EVENT DICT FOR RULE EVALUATION
            normalized_event_dict = {
                "event_name": event_name,
                "identity_type": identity_type,
                "actor_ip": actor_ip,
                "is_read_only": is_read_only,
                "hour": hour,
                "day_of_week": day_of_week,
                "actor": actor,
                "actor_type": actor_type,
                "region": region,
                "account_id": account_id,
                "timestamp": timestamp.isoformat(),
                "resource": resource_name,
                "resource_type": resource_type,
                "event_source": event_source,
                "request_params": request_params,
                "response_elements": response_elements,
            }
            
            # ===== SEVERITY (USES RULES FROM DATABASE) =====
            severity, severity_score, severity_reason = self._determine_severity_context(
                event_name=event_name,
                identity_type=identity_type,
                actor_ip=actor_ip,
                request_params=request_params,
                is_read_only=is_read_only,
                normalized_event_dict=normalized_event_dict,
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
                hour=hour,
                day_of_week=day_of_week,
                is_read_only=is_read_only,
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
    # SEVERITY CONTEXT (Uses database rules)
    # ================================================================
    
    def _determine_severity_context(
        self,
        event_name: str,
        identity_type: str,
        actor_ip: Optional[str],
        request_params: Dict,
        is_read_only: bool,
        normalized_event_dict: Dict,
        threat_intel: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """
        Context-aware severity determination using UNIFIED rule evaluation.
        ALL rules are evaluated together.
        """
        try:
            reasons = []
            
            # ================================================================
            # UNIFIED RULE EVALUATION - ALL RULES EVALUATED TOGETHER
            # ================================================================
            try:
                from sqlalchemy.orm import Session
                from ...core.database import SessionLocal
                from ...risk.rules.rule_service import RuleService
                
                db = SessionLocal()
                rule_service = RuleService(db)
                
                # ✅ Evaluate ALL rules at once
                result = rule_service.evaluate_all_rules(normalized_event_dict)
                
                base_score = result.get("base_score", 0)
                modifier = result.get("modifier", 1.0)
                rules_applied = result.get("rules_applied", [])
                
                # Build reasons
                if rules_applied:
                    for rule_name in rules_applied:
                        reasons.append(f"Rule: {rule_name}")
                else:
                    reasons.append("No rules matched")
                
                logger.info(f"Applied rules: {rules_applied}")
                logger.info(f"Base score: {base_score}, Modifier: {modifier:.1f}x")
                
                db.close()
                
            except Exception as e:
                logger.error(f"Failed to evaluate rules: {e}")
                base_score = 0
                modifier = 1.0
                reasons.append(f"Rule evaluation error: {str(e)}")
            
            # ================================================================
            # BUILT-IN MODIFIERS (Not rules - always applied)
            # ================================================================
            if is_read_only:
                modifier *= 0.7
                reasons.append("Read-only operation (0.7x)")
            
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
            
            # Threat Intelligence (built-in)
            if threat_intel and threat_intel.get("checked", False):
                modifier *= threat_intel["modifier"]
                if threat_intel.get("is_malicious", False):
                    reasons.append(f"Malicious IP - {threat_intel['modifier']}x")

            # Add debug print before calling evaluate_all_rules
                print(f"🔍 normalized_event_dict: {normalized_event_dict}")
                print(f"   hour: {normalized_event_dict.get('hour')}")
                print(f"   day_of_week: {normalized_event_dict.get('day_of_week')}")
                print(f"   is_read_only: {normalized_event_dict.get('is_read_only')}")
            # ================================================================
            # CALCULATE FINAL SCORE
            # ================================================================
            final_score = int(base_score * modifier)
            final_score = max(0, min(100, final_score))
            
            severity_score = int(final_score)
            
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
            
            severity_reason = f"Base: {base_score} | Modifier: {modifier:.1f}x | Score: {severity_score} | Factors: {', '.join(reasons)}"
            
            return severity, severity_score, severity_reason
            
        except Exception as e:
            logger.error(f"Error in severity calculation: {e}")
            return "INFO", 0, f"Error: {str(e)}"
    
    # ================================================================
    # THREAT INTELLIGENCE
    # ================================================================
    
    def _get_threat_intel(self, actor_ip: Optional[str]) -> Optional[Dict[str, Any]]:
        """Get threat intelligence for an IP address."""
        if not actor_ip:
            return None
        
        if self._is_private_ip(actor_ip):
            return None
        
        if self._is_domain_name(actor_ip):
            return None
        
        try:
            manager = ThreatIntelManager()
            result = manager.get_ip_reputation(actor_ip)
            
            if result and result.get("checked", False):
                return {
                    "checked": True,
                    "is_malicious": result.get("is_malicious", False),
                    "provider": result.get("provider"),
                    "confidence": result.get("confidence", 0),
                    "modifier": result.get("modifier", 1.0),
                    "categories": result.get("categories", []),
                    "details": result.get("details", {}),
                }
        except Exception as e:
            logger.warning(f"Threat intel lookup failed: {e}")
        
        return {
            "checked": False,
            "is_malicious": False,
            "reason": "No threat intelligence available or lookup failed",
        }
    
    def _is_domain_name(self, value: str) -> bool:
        """Check if a string is a domain name (not an IP address)."""
        if not value:
            return True
        
        parts = value.split(".")
        
        if len(parts) == 4:
            for part in parts:
                if not part.isdigit():
                    return True
            return False
        
        if ":" in value:
            return False
        
        return True
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        if not ip:
            return True
        
        if "." in ip and not all(part.isdigit() for part in ip.split(".") if part):
            return True
        
        private_ranges = [
            "10.", "192.168.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
            "172.29.", "172.30.", "172.31.", "127.", "169.254.", "::1"
        ]
        
        for prefix in private_ranges:
            if ip.startswith(prefix):
                return True
        
        return False
    
    # ================================================================
    # HELPER METHODS
    # ================================================================
    
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
        """Generate enhanced tags for Risk Engine."""
        tags = []
        
        if "Delete" in event_name or "Stop" in event_name:
            tags.append("destructive")
        if "Attach" in event_name or "Create" in event_name:
            tags.append("privilege_change")
        if "Login" in event_name or "AssumeRole" in event_name:
            tags.append("authentication")
        
        if identity_type == "root":
            tags.append("root_user")
        elif identity_type == "assumedrole":
            tags.append("assumed_role")
        
        if actor_ip and not (
            actor_ip.startswith("192.168.") or
            actor_ip.startswith("10.") or
            actor_ip.startswith("172.16.") or
            actor_ip == "127.0.0.1"
        ):
            tags.append("public_ip")
        
        if threat_intel and threat_intel.get("checked", False):
            if threat_intel.get("is_malicious", False):
                tags.append("malicious_ip")
            if threat_intel.get("confidence", 0) >= 75:
                tags.append("high_confidence_threat")
        
        if is_read_only:
            tags.append("read_only")
        else:
            tags.append("write_operation")
        
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
        """Generate a rich description."""
        parts = []
        parts.append(f"Event: {event_name}")
        parts.append(f"Actor: {actor} ({identity_type})")
        parts.append(f"Resource: {resource_name}")
        return " | ".join(parts)
    
    def _determine_action(self, event_name: str) -> str:
        """Determine the action type."""
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
        """Map AWS event name to normalized event type."""
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
    
    # ================================================================
    # GENERIC AWS NORMALIZER (Fallback)
    # ================================================================
    
    def _normalize_generic_aws(self, raw_event: RawEvent) -> NormalizedEvent:
        """Fallback normalization for unknown AWS events"""
        data = raw_event.data
        
        user_identity = data.get("userIdentity", {})
        actor = user_identity.get("userName", "unknown")
        event_name = data.get("eventName", data.get("EventName", "unknown"))
        actor_ip = data.get("sourceIPAddress")
        threat_intel = self._get_threat_intel(actor_ip)
        
        try:
            timestamp = raw_event.timestamp
            hour = timestamp.hour if timestamp else 0
            day_of_week = timestamp.strftime("%A").lower() if timestamp else "unknown"
        except:
            hour = 0
            day_of_week = "unknown"
        
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
            timestamp=timestamp,
            hour=hour,
            day_of_week=day_of_week,
            is_read_only=False,
            region=data.get("awsRegion"),
            account_id=data.get("recipientAccountId"),
            tags=[],
            related_events=[],
            metadata={"note": "Generic AWS normalization - review raw event"},
            threat_intel=threat_intel,
            raw_event=data,
        )