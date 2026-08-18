# app/evidence/collectors/iam_policy_collector.py
"""
IAM Policy Collector - Collects IAM policy evidence for incidents
"""
import boto3
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from botocore.exceptions import ClientError

from app.evidence.collectors.base import BaseCollector
from app.domain.models.incident import Incident
from app.models.evidence import EvidenceArtifact
from app.core.config import settings

logger = logging.getLogger(__name__)


class IAMPolicyCollector(BaseCollector):
    """
    Collects IAM policy evidence for an incident.

    Collects:
    1. Policy details (name, ARN, description)
    2. Policy document (permissions)
    3. Policy analysis (what permissions it grants)
    """

    def __init__(self):
        super().__init__()
        self.collector_name = "IAMPolicyCollector"

        # Initialize AWS IAM client
        self.iam = boto3.client(
            'iam',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,
            region_name=settings.AWS_DEFAULT_REGION
        )

    def get_artifact_type(self) -> str:
        return "IAMPolicy"

    def get_source(self) -> str:
        return "aws_iam"

    async def collect(self, incident: Incident) -> Optional[EvidenceArtifact]:
        """
        Collect IAM policy evidence for an incident.
        """
        logger.info(f"🔍 IAMPolicyCollector collecting evidence for incident {incident.id}")

        try:
            event_data = incident.normalized_event
            event_name = event_data.get('event_name', '')
            actor = event_data.get('actor')
            request_params = self._get_request_params(event_data)

            # ✅ FIX: if the API call itself names an exact managed policy
            # (AttachUserPolicy / DetachUserPolicy / AttachRolePolicy /
            # DetachRolePolicy), use THAT ARN directly. This is always
            # correct — unlike listing policies "attached to the actor",
            # which misses anything the target inherits through a group,
            # and which queries the wrong identity anyway (the actor
            # performed the action, they aren't necessarily the target).
            policy_arns = self._extract_policy_arns_from_event(event_name, request_params)
            target_user = request_params.get('userName') or actor

            if policy_arns:
                logger.info(f"   📋 Policy ARN found directly in event: {policy_arns}")
            else:
                if not target_user:
                    logger.info(f"ℹ️ No actor/target user found in incident {incident.id}")
                    return self._create_empty_artifact(incident.id, "No actor found")

                logger.info(f"   👤 Target user: {target_user}")

                # 2. Get policies attached to the target user
                policy_arns = await self._get_user_policies(target_user)

            if not policy_arns:
                logger.info(f"ℹ️ No policies found for user: {target_user}")
                return self._create_empty_artifact(incident.id, f"No policies found for user: {target_user}")

            logger.info(f"   📋 Found {len(policy_arns)} policies for user: {target_user}")

            # 3. Collect policy details for each ARN
            policies = []
            for policy_arn in policy_arns:
                try:
                    policy_data = await self._collect_policy(policy_arn)
                    if policy_data:
                        policies.append(policy_data)
                        logger.info(f"   ✅ Collected: {policy_data.get('policy_name')}")
                except Exception as e:
                    logger.error(f"   ❌ Error collecting {policy_arn}: {e}")

            if not policies:
                logger.info(f"ℹ️ No policies could be collected")
                return self._create_empty_artifact(incident.id, "Failed to collect policies")

            # 4. Analyze policies for security findings
            security_findings = self._analyze_policies(policies)

            # 5. Build content
            content = {
                "policies": policies,
                "summary": {
                    "total_policies": len(policies),
                    "security_findings": security_findings
                },
                "security_analysis": {
                    "high_risk_findings": [f for f in security_findings if f.get('severity') in ['high', 'critical']],
                    "medium_risk_findings": [f for f in security_findings if f.get('severity') == 'medium'],
                    "low_risk_findings": [f for f in security_findings if f.get('severity') == 'low']
                }
            }

            # 6. Create metadata
            extra_data = {
                "user_name": target_user,
                "policy_count": len(policies),
                "high_risk_findings": len([f for f in security_findings if f.get('severity') in ['high', 'critical']])
            }

            # 7. Create artifact
            artifact = self.create_artifact(
                incident_id=incident.id,
                content=content,
                extra_data=extra_data,
                region="global"
            )

            logger.info(f"✅ IAM Policy evidence collected for incident {incident.id}")
            logger.info(f"   📋 Policies: {len(policies)}")
            logger.info(f"   🔍 High Risk: {extra_data['high_risk_findings']}")

            return artifact

        except ClientError as e:
            logger.error(f"❌ AWS API error: {e}")
            return self._create_failed_artifact(incident.id, str(e))
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return self._create_failed_artifact(incident.id, str(e))

    def _get_request_params(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        ✅ NEW: pull the raw CloudTrail API call parameters out of the
        normalized event. `NormalizedEvent.to_dict()` never had a
        'request_parameters' key — that's why the old code always got {}
        here. The closest field is 'action_details'. A couple of fallback
        locations are checked in case your normalizer stores it elsewhere
        — adjust if your actual key name differs.
        """
        action_details = event_data.get('action_details') or {}
        if action_details:
            return action_details

        raw_event = event_data.get('raw_event') or {}
        if isinstance(raw_event, dict) and raw_event.get('requestParameters'):
            return raw_event['requestParameters']

        metadata = event_data.get('metadata') or {}
        if metadata.get('request_parameters'):
            return metadata['request_parameters']

        return {}

    def _extract_policy_arns_from_event(self, event_name: str, request_params: Dict[str, Any]) -> List[str]:
        """
        ✅ NEW: if the triggering API call directly names a managed policy,
        use that exact ARN. Correct regardless of direct-vs-group attachment,
        and doesn't depend on AWS list-policies permissions the caller may
        not have.
        """
        if event_name in ("AttachUserPolicy", "DetachUserPolicy", "AttachRolePolicy", "DetachRolePolicy"):
            policy_arn = request_params.get('policyArn')
            return [policy_arn] if policy_arn else []
        return []

    async def _get_user_policies(self, user_name: str) -> List[str]:
        """
        Get policy ARNs attached to a user — DIRECTLY attached AND
        inherited through group membership.

        ✅ FIX: the old version only checked direct attachment
        (list_attached_user_policies). Most real AWS accounts grant
        permissions through groups, not direct attachment, so this
        silently returned an empty list for most real users.
        """
        policy_arns = set()
        try:
            response = self.iam.list_attached_user_policies(
                UserName=user_name,
                MaxItems=100
            )
            for policy in response.get('AttachedPolicies', []):
                arn = policy.get('PolicyArn')
                if arn:
                    policy_arns.add(arn)

            logger.info(f"   📋 Found {len(policy_arns)} directly attached policies for {user_name}")

            # ✅ NEW: policies inherited through group membership
            groups_response = self.iam.list_groups_for_user(
                UserName=user_name,
                MaxItems=100
            )
            for group in groups_response.get('Groups', []):
                group_name = group.get('GroupName')
                try:
                    group_policies = self.iam.list_attached_group_policies(
                        GroupName=group_name,
                        MaxItems=100
                    )
                    for policy in group_policies.get('AttachedPolicies', []):
                        arn = policy.get('PolicyArn')
                        if arn:
                            policy_arns.add(arn)
                except Exception as e:
                    logger.warning(f"⚠️ Error getting policies for group {group_name}: {e}")

            logger.info(f"   📋 Found {len(policy_arns)} total policies (direct + group) for {user_name}")

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logger.warning(f"⚠️ User {user_name} not found")
            else:
                logger.error(f"❌ Error getting user policies: {e}")
        except Exception as e:
            logger.error(f"❌ Error: {e}")

        return list(policy_arns)

    async def _collect_policy(self, policy_arn: str) -> Optional[Dict[str, Any]]:
        """Collect comprehensive policy evidence."""
        try:
            # Get policy details
            policy_response = self.iam.get_policy(PolicyArn=policy_arn)
            policy = policy_response.get('Policy', {})

            policy_name = policy.get('PolicyName', 'Unknown')
            default_version_id = policy.get('DefaultVersionId')
            attachment_count = policy.get('AttachmentCount', 0)
            is_attachable = policy.get('IsAttachable', False)

            # Get policy document
            policy_document = await self._get_policy_document(policy_arn, default_version_id)

            # Analyze policy document
            security_analysis = self._analyze_policy_document(policy_document)

            return {
                "policy_name": policy_name,
                "arn": policy_arn,
                "attachment_count": attachment_count,
                "is_attachable": is_attachable,
                "policy_document": policy_document,
                "security_analysis": security_analysis,
                "summary": {
                    "has_administrator_access": await self._check_admin_access(policy_document),
                    "has_privilege_escalation": await self._check_privilege_escalation(policy_document),
                    "statement_count": len(policy_document.get('Statement', [])) if policy_document else 0
                }
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logger.warning(f"⚠️ Policy not found: {policy_arn}")
            else:
                logger.error(f"❌ Error collecting policy {policy_arn}: {e}")
            return None

    async def _get_policy_document(self, policy_arn: str, version_id: str) -> Optional[Dict[str, Any]]:
        """Get the policy document from a specific version."""
        try:
            if not version_id:
                response = self.iam.get_policy(PolicyArn=policy_arn)
                version_id = response.get('Policy', {}).get('DefaultVersionId')

            if version_id:
                response = self.iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )
                document = response.get('PolicyVersion', {}).get('Document')
                if document and isinstance(document, str):
                    document = json.loads(document)
                return document
            return None

        except Exception as e:
            logger.error(f"❌ Error getting policy document: {e}")
            return None

    def _analyze_policy_document(self, document: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze policy document for security issues."""
        findings = []

        if not document:
            return findings

        statements = document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, statement in enumerate(statements):
            if statement.get('Effect') != 'Allow':
                continue

            action = statement.get('Action', [])
            if isinstance(action, str):
                action = [action]

            resource = statement.get('Resource', [])
            if isinstance(resource, str):
                resource = [resource]

            # Check for administrative actions
            if '*' in action:
                findings.append({
                    "severity": "critical",
                    "type": "administrator_access",
                    "description": "Statement grants full administrative access (*)",
                    "recommendation": "This policy should be carefully reviewed - it grants full access to all resources",
                    "statement_index": idx
                })

            # Check for IAM full access
            if any('iam:*' in a or 'iam:FullAccess' in a for a in action):
                findings.append({
                    "severity": "high",
                    "type": "iam_full_access",
                    "description": "Statement grants full IAM access",
                    "recommendation": "This allows privilege escalation - consider restricting",
                    "statement_index": idx
                })

            # Check for privilege escalation patterns
            escalation_actions = ['iam:CreateUser', 'iam:CreateRole', 'iam:AttachUserPolicy',
                                 'iam:AttachRolePolicy', 'iam:PutUserPolicy']
            if any(a in escalation_actions for a in action):
                findings.append({
                    "severity": "high",
                    "type": "privilege_escalation",
                    "description": f"Statement allows privilege escalation ({', '.join([a for a in action if a in escalation_actions][:2])})",
                    "recommendation": "Review if these actions are necessary - they can be used to escalate privileges",
                    "statement_index": idx
                })

            # Wildcard resources
            if '*' in resource:
                findings.append({
                    "severity": "medium",
                    "type": "wildcard_resource",
                    "description": "Statement uses wildcard '*' in resources",
                    "recommendation": "Consider restricting to specific resources",
                    "statement_index": idx
                })

        return findings

    def _analyze_policies(self, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aggregate security findings from all policies."""
        all_findings = []

        for policy in policies:
            policy_name = policy.get('policy_name', 'Unknown')

            # Get findings from policy document analysis
            findings = policy.get('security_analysis', [])
            for finding in findings:
                finding['policy_name'] = policy_name
                all_findings.append(finding)

            # Add summary findings
            summary = policy.get('summary', {})
            if summary.get('has_administrator_access'):
                all_findings.append({
                    "severity": "critical",
                    "type": "administrator_access_policy",
                    "description": f"Policy '{policy_name}' grants administrative access",
                    "recommendation": "This policy is extremely powerful - review immediately",
                    "policy_name": policy_name
                })

            if summary.get('has_privilege_escalation'):
                all_findings.append({
                    "severity": "high",
                    "type": "privilege_escalation_policy",
                    "description": f"Policy '{policy_name}' allows privilege escalation",
                    "recommendation": "This policy could be used to escalate privileges - review",
                    "policy_name": policy_name
                })

        return all_findings

    async def _check_admin_access(self, document: Dict[str, Any]) -> bool:
        """Check if policy grants admin access."""
        if not document:
            return False

        statements = document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                action = statement.get('Action', [])
                if isinstance(action, str):
                    action = [action]
                if '*' in action:
                    return True
        return False

    async def _check_privilege_escalation(self, document: Dict[str, Any]) -> bool:
        """Check if policy allows privilege escalation."""
        if not document:
            return False

        escalation_actions = [
            'iam:CreateUser', 'iam:CreateRole', 'iam:AttachUserPolicy',
            'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy'
        ]

        statements = document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                action = statement.get('Action', [])
                if isinstance(action, str):
                    action = [action]
                if any(a in escalation_actions for a in action):
                    return True
        return False

    def _create_empty_artifact(self, incident_id: str, message: str) -> EvidenceArtifact:
        """Create an artifact with no policies found."""
        incident_uuid = self._parse_incident_id(incident_id)

        artifact = EvidenceArtifact(
            incident_id=incident_uuid,
            artifact_type=self.get_artifact_type(),
            source=self.get_source(),
            provider="aws",
            collector=self.collector_name,
            content={
                "message": message,
                "policies": [],
                "summary": {"total_policies": 0, "security_findings": []},
                "security_analysis": {"high_risk_findings": [], "medium_risk_findings": [], "low_risk_findings": []}
            },
            collection_status="COMPLETED",
            extra_data={"policy_count": 0, "note": "No policies found"}
        )

        return artifact

    def _create_failed_artifact(self, incident_id: str, error_message: str) -> EvidenceArtifact:
        """Create a failed artifact."""
        incident_uuid = self._parse_incident_id(incident_id)

        artifact = EvidenceArtifact(
            incident_id=incident_uuid,
            artifact_type=self.get_artifact_type(),
            source=self.get_source(),
            provider="aws",
            collector=self.collector_name,
            content={"error": error_message},
            collection_status="FAILED",
            error_message=error_message,
            extra_data={"failure_time": datetime.utcnow().isoformat()}
        )

        return artifact