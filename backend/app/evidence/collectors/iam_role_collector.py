# app/evidence/collectors/iam_role_collector.py
"""
IAM Role Collector - Collects IAM role evidence for incidents
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


class IAMRoleCollector(BaseCollector):
    """
    Collects IAM role evidence for an incident.

    Collects:
    1. Role details (name, ARN, description)
    2. Role policies (attached and inline)
    3. Trust policy (who can assume the role)
    4. Role analysis (what permissions it grants)
    """

    def __init__(self):
        super().__init__()
        self.collector_name = "IAMRoleCollector"

        # Initialize AWS IAM client
        self.iam = boto3.client(
            'iam',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,
            region_name=settings.AWS_DEFAULT_REGION
        )

    def get_artifact_type(self) -> str:
        return "IAMRole"

    def get_source(self) -> str:
        return "aws_iam"

    async def collect(self, incident: Incident) -> Optional[EvidenceArtifact]:
        """
        Collect IAM role evidence for an incident.
        """
        logger.info(f"🔍 IAMRoleCollector collecting evidence for incident {incident.id}")

        try:
            # 1. Get the actor from the incident
            event_data = incident.normalized_event
            event_name = event_data.get('event_name', '')
            actor = event_data.get('actor')
            actor_type = event_data.get('actor_type', '') or ''

            logger.info(f"   👤 Actor: {actor}")
            logger.info(f"   📋 Event: {event_name}")

            # ✅ FIX: 'request_parameters' never existed as a key on the
            # normalized event dict — event_data.get('request_parameters', {})
            # always returned {}, so this branch could never fire for real
            # incidents. Use the same request-param resolver as
            # IAMPolicyCollector.
            request_params = self._get_request_params(event_data)

            roles = []

            # ✅ FIX: extract role name directly from the API call —
            # covers roleName (AttachRolePolicy, PutRolePolicy,
            # UpdateAssumeRolePolicy, ...) and roleArn (AssumeRole).
            role_names = self._extract_role_names_from_event(request_params)
            for role_name in role_names:
                logger.info(f"   Found role in request: {role_name}")
                role_data = await self._collect_role(role_name)
                if role_data:
                    roles.append(role_data)

            # ✅ NEW fallback: if the ACTOR itself is an assumed role
            # (e.g. an AssumeRole session), collect that role too.
            # actor_type for these sessions is typically "AssumedRole",
            # and actor is often "role-name/session-name".
            if not roles and actor and 'role' in actor_type.lower():
                possible_role = actor.split('/')[0] if '/' in actor else actor
                logger.info(f"   Actor appears to be an assumed role: {possible_role}")
                role_data = await self._collect_role(possible_role)
                if role_data:
                    roles.append(role_data)

            if not roles:
                logger.info(f"ℹ️ No roles found for this incident")
                return self._create_empty_artifact(incident.id, "No IAM roles found")

            # 3. Build content
            content = {
                "roles": roles,
                "summary": {
                    "total_roles": len(roles),
                    "roles_with_admin": len([r for r in roles if r.get('summary', {}).get('has_administrator_access', False)]),
                    "roles_with_trust": len([r for r in roles if r.get('trust_policy')])
                }
            }

            # 4. Create metadata
            extra_data = {
                "user_name": actor,
                "role_count": len(roles)
            }

            # 5. Create artifact
            artifact = self.create_artifact(
                incident_id=incident.id,
                content=content,
                extra_data=extra_data,
                region="global"
            )

            logger.info(f"✅ IAM Role evidence collected for incident {incident.id}")
            logger.info(f"   🎭 Roles: {len(roles)}")

            return artifact

        except ClientError as e:
            logger.error(f"❌ AWS API error: {e}")
            return self._create_failed_artifact(incident.id, str(e))
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return self._create_failed_artifact(incident.id, str(e))

    def _get_request_params(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        ✅ NEW: same resolver as IAMPolicyCollector — pulls the raw API call
        parameters from 'action_details' (the actual key on the normalized
        event), with fallbacks. Adjust if your normalizer's key differs.
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

    def _extract_role_names_from_event(self, request_params: Dict[str, Any]) -> List[str]:
        """
        ✅ NEW: pull the role name directly out of the API call parameters.
        Covers both 'roleName' (most role-policy events) and 'roleArn'
        (AssumeRole, which never includes a bare roleName).
        """
        role_name = request_params.get('roleName')
        if role_name:
            return [role_name]

        role_arn = request_params.get('roleArn')
        if role_arn and '/' in role_arn:
            return [role_arn.split('/')[-1]]

        return []

    async def _collect_role(self, role_name: str) -> Optional[Dict[str, Any]]:
        """Collect comprehensive role evidence."""
        try:
            # Get role details
            response = self.iam.get_role(RoleName=role_name)
            role = response.get('Role', {})

            role_data = {
                "role_name": role.get('RoleName', 'Unknown'),
                "arn": role.get('Arn', ''),
                "path": role.get('Path', ''),
                "description": role.get('Description', ''),
                "create_date": role.get('CreateDate').isoformat() if role.get('CreateDate') else None,
                "role_id": role.get('RoleId', ''),
                "max_session_duration": role.get('MaxSessionDuration', 3600),

                # Trust policy (who can assume this role)
                "trust_policy": role.get('AssumeRolePolicyDocument'),

                # Summary
                "summary": {
                    "has_administrator_access": False,  # Will check below
                    "has_trust_policy": bool(role.get('AssumeRolePolicyDocument'))
                }
            }

            # Get attached policies
            attached_policies = await self._get_attached_policies(role_name)
            role_data["attached_policies"] = attached_policies
            role_data["summary"]["attached_policy_count"] = len(attached_policies)

            # Get inline policies
            inline_policies = await self._get_inline_policies(role_name)
            role_data["inline_policies"] = inline_policies
            role_data["summary"]["inline_policy_count"] = len(inline_policies)

            # Check if any policy grants admin access
            for policy in attached_policies:
                if policy.get('summary', {}).get('has_administrator_access', False):
                    role_data["summary"]["has_administrator_access"] = True
                    break

            logger.info(f"   ✅ Collected role: {role_name}")
            return role_data

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logger.warning(f"⚠️ Role not found: {role_name}")
            else:
                logger.error(f"❌ Error collecting role {role_name}: {e}")
            return None

    async def _get_attached_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """Get attached policies for a role."""
        policies = []
        try:
            response = self.iam.list_attached_role_policies(
                RoleName=role_name,
                MaxItems=100
            )

            for policy in response.get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn')
                policy_name = policy.get('PolicyName')

                # Get policy document
                policy_doc = await self._get_policy_document(policy_arn)

                policies.append({
                    "policy_name": policy_name,
                    "policy_arn": policy_arn,
                    "policy_document": policy_doc,
                    "summary": {
                        "has_administrator_access": await self._check_admin_access(policy_doc)
                    }
                })

        except Exception as e:
            logger.error(f"❌ Error getting attached policies: {e}")

        return policies

    async def _get_inline_policies(self, role_name: str) -> List[Dict[str, Any]]:
        """Get inline policies for a role."""
        policies = []
        try:
            response = self.iam.list_role_policies(
                RoleName=role_name,
                MaxItems=100
            )

            for policy_name in response.get('PolicyNames', []):
                try:
                    policy_response = self.iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )

                    doc = policy_response.get('PolicyDocument')
                    if doc and isinstance(doc, str):
                        doc = json.loads(doc)

                    policies.append({
                        "policy_name": policy_name,
                        "policy_document": doc,
                        "is_inline": True
                    })
                except Exception as e:
                    logger.error(f"❌ Error getting inline policy {policy_name}: {e}")

        except Exception as e:
            logger.error(f"❌ Error getting inline policies: {e}")

        return policies

    async def _get_policy_document(self, policy_arn: str) -> Optional[Dict[str, Any]]:
        """Get policy document from ARN."""
        try:
            response = self.iam.get_policy(PolicyArn=policy_arn)
            policy = response.get('Policy', {})
            default_version_id = policy.get('DefaultVersionId')

            if default_version_id:
                version_response = self.iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version_id
                )
                document = version_response.get('PolicyVersion', {}).get('Document')
                if document and isinstance(document, str):
                    document = json.loads(document)
                return document
            return None
        except Exception as e:
            logger.error(f"❌ Error getting policy document: {e}")
            return None

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

    def _create_empty_artifact(self, incident_id: str, message: str) -> EvidenceArtifact:
        """Create an artifact with no roles found."""
        incident_uuid = self._parse_incident_id(incident_id)

        artifact = EvidenceArtifact(
            incident_id=incident_uuid,
            artifact_type=self.get_artifact_type(),
            source=self.get_source(),
            provider="aws",
            collector=self.collector_name,
            content={
                "message": message,
                "roles": [],
                "summary": {"total_roles": 0}
            },
            collection_status="COMPLETED",
            extra_data={"role_count": 0, "note": "No roles found"}
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