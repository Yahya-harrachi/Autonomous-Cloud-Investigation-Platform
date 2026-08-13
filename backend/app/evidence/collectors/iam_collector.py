# app/evidence/collectors/iam_collector.py
"""
IAM Collector - Collects IAM evidence for incidents
"""
import boto3
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from botocore.exceptions import ClientError
import uuid

from app.evidence.collectors.base import BaseCollector
from app.domain.models.incident import Incident
from app.models.evidence import EvidenceArtifact
from app.core.config import settings

logger = logging.getLogger(__name__)


class IAMCollector(BaseCollector):
    """
    Collects IAM evidence for an incident.
    
    Collects:
    1. IAM User details
    2. Attached managed policies
    3. Inline policies
    4. Groups
    5. Access keys
    6. User tags
    """
    
    def __init__(self):
        super().__init__()
        self.collector_name = "IAMCollector"
        
        # Initialize AWS IAM client
        self.iam = boto3.client(
            'iam',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,
            region_name=settings.AWS_DEFAULT_REGION
        )
    
    def get_artifact_type(self) -> str:
        return "IAMUser"
    
    def get_source(self) -> str:
        return "aws_iam"
    
    async def collect(self, incident: Incident) -> Optional[EvidenceArtifact]:
        """
        Collect IAM evidence for an incident.
        
        Args:
            incident: The incident to collect evidence for
            
        Returns:
            EvidenceArtifact or None if collection fails
        """
        logger.info(f"🔍 IAMCollector collecting evidence for incident {incident.id}")
        
        try:
            # 1. Extract actor from incident
            event_data = incident.normalized_event
            actor = event_data.get('actor')
            
            if not actor:
                logger.warning(f"⚠️ No actor found in incident {incident.id}")
                return self._create_failed_artifact(
                    incident.id, 
                    "No actor found in incident"
                )
            
            logger.info(f"👤 Collecting IAM evidence for user: {actor}")
            
            # 2. Collect IAM user details
            user_data = await self._get_user(actor)
            if not user_data:
                logger.warning(f"⚠️ User {actor} not found in IAM")
                return self._create_failed_artifact(
                    incident.id,
                    f"User {actor} not found in IAM"
                )
            
            # 3. Collect attached policies
            attached_policies = await self._get_attached_policies(actor)
            
            # 4. Collect inline policies
            inline_policies = await self._get_inline_policies(actor)
            
            # 5. Collect groups
            groups = await self._get_groups(actor)
            
            # 6. Collect access keys
            access_keys = await self._get_access_keys(actor)
            
            # 7. Collect user tags
            tags = await self._get_user_tags(actor)
            
            # 8. Build content
            content = {
                "user": user_data,
                "attached_policies": attached_policies,
                "inline_policies": inline_policies,
                "groups": groups,
                "access_keys": access_keys,
                "tags": tags,
                "summary": {
                    "total_attached_policies": len(attached_policies),
                    "total_inline_policies": len(inline_policies),
                    "total_groups": len(groups),
                    "total_access_keys": len(access_keys),
                    "has_mfa": user_data.get('MFA', False),
                    "password_last_used": user_data.get('password_last_used'),
                    "user_created": user_data.get('create_date')
                }
            }
            
            # 9. Create metadata
            extra_data = {
                "user_name": actor,
                "user_id": user_data.get('user_id'),
                "policy_count": len(attached_policies),
                "group_count": len(groups),
                "access_key_count": len(access_keys)
            }
            
            # 10. Create artifact
            artifact = self.create_artifact(
                incident_id=incident.id,
                content=content,
                extra_data=extra_data,
                region="global"  # IAM is global
            )
            
            logger.info(f"✅ IAM evidence collected for incident {incident.id}")
            logger.info(f"   👤 User: {actor}")
            logger.info(f"   📋 Policies: {len(attached_policies)} attached, {len(inline_policies)} inline")
            logger.info(f"   👥 Groups: {len(groups)}")
            logger.info(f"   🔑 Access Keys: {len(access_keys)}")
            
            return artifact
            
        except ClientError as e:
            logger.error(f"❌ AWS API error collecting IAM evidence: {e}")
            return self._create_failed_artifact(
                incident.id,
                f"AWS Error: {str(e)}"
            )
            
        except Exception as e:
            logger.error(f"❌ Error collecting IAM evidence: {e}")
            return self._create_failed_artifact(incident.id, str(e))
    
    async def _get_user(self, user_name: str) -> Optional[Dict[str, Any]]:
        """
        Get IAM user details.
        
        Args:
            user_name: The IAM username
            
        Returns:
            User data or None
        """
        try:
            response = self.iam.get_user(
                UserName=user_name
            )
            
            user = response.get('User', {})
            
            # Format user data
            user_data = {
                'user_id': user.get('UserId'),
                'user_name': user.get('UserName'),
                'arn': user.get('Arn'),
                'path': user.get('Path'),
                'create_date': user.get('CreateDate').isoformat() if user.get('CreateDate') else None,
                'password_last_used': user.get('PasswordLastUsed').isoformat() if user.get('PasswordLastUsed') else None,
                'mfa_active': await self._check_mfa(user_name)
            }
            
            logger.info(f"✅ Found user: {user_name}")
            return user_data
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logger.warning(f"⚠️ User {user_name} not found")
                return None
            raise
    
    async def _check_mfa(self, user_name: str) -> bool:
        """
        Check if MFA is enabled for a user.
        
        Args:
            user_name: The IAM username
            
        Returns:
            True if MFA is enabled
        """
        try:
            response = self.iam.list_mfa_devices(
                UserName=user_name
            )
            devices = response.get('MFADevices', [])
            return len(devices) > 0
        except:
            return False
    
    async def _get_attached_policies(self, user_name: str) -> List[Dict[str, Any]]:
        """
        Get attached managed policies for a user.
        
        Args:
            user_name: The IAM username
            
        Returns:
            List of attached policies
        """
        try:
            response = self.iam.list_attached_user_policies(
                UserName=user_name,
                MaxItems=100
            )
            
            policies = response.get('AttachedPolicies', [])
            
            # Get policy details for each
            detailed_policies = []
            for policy in policies:
                policy_arn = policy.get('PolicyArn')
                policy_name = policy.get('PolicyName')
                
                # Get policy details
                policy_details = await self._get_policy_details(policy_arn)
                
                detailed_policies.append({
                    'policy_name': policy_name,
                    'policy_arn': policy_arn,
                    'attach_date': policy.get('AttachDate').isoformat() if policy.get('AttachDate') else None,
                    'policy_document': policy_details
                })
            
            logger.info(f"✅ Found {len(detailed_policies)} attached policies for {user_name}")
            return detailed_policies
            
        except ClientError as e:
            logger.error(f"❌ Error getting attached policies: {e}")
            return []
    
    async def _get_inline_policies(self, user_name: str) -> List[Dict[str, Any]]:
        """
        Get inline policies for a user.
        
        Args:
            user_name: The IAM username
            
        Returns:
            List of inline policies
        """
        try:
            response = self.iam.list_user_policies(
                UserName=user_name,
                MaxItems=100
            )
            
            policy_names = response.get('PolicyNames', [])
            
            # Get policy documents
            inline_policies = []
            for policy_name in policy_names:
                policy_doc = await self._get_user_policy(user_name, policy_name)
                inline_policies.append({
                    'policy_name': policy_name,
                    'policy_document': policy_doc
                })
            
            logger.info(f"✅ Found {len(inline_policies)} inline policies for {user_name}")
            return inline_policies
            
        except ClientError as e:
            logger.error(f"❌ Error getting inline policies: {e}")
            return []
    
    async def _get_user_policy(self, user_name: str, policy_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a user's inline policy document.
        
        Args:
            user_name: The IAM username
            policy_name: The policy name
            
        Returns:
            Policy document or None
        """
        try:
            response = self.iam.get_user_policy(
                UserName=user_name,
                PolicyName=policy_name
            )
            
            policy_doc = response.get('PolicyDocument')
            if policy_doc and isinstance(policy_doc, str):
                policy_doc = json.loads(policy_doc)
            
            return policy_doc
            
        except ClientError as e:
            logger.error(f"❌ Error getting user policy {policy_name}: {e}")
            return None
    
    async def _get_policy_details(self, policy_arn: str) -> Optional[Dict[str, Any]]:
        """
        Get policy details including document.
        
        Args:
            policy_arn: The policy ARN
            
        Returns:
            Policy details or None
        """
        try:
            response = self.iam.get_policy(
                PolicyArn=policy_arn
            )
            
            policy = response.get('Policy', {})
            
            # Get policy version (the default version)
            version_id = policy.get('DefaultVersionId')
            if version_id:
                version_response = self.iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )
                
                doc = version_response.get('PolicyVersion', {}).get('Document')
                if doc and isinstance(doc, str):
                    doc = json.loads(doc)
                
                return doc
            
            return None
            
        except ClientError as e:
            logger.error(f"❌ Error getting policy details for {policy_arn}: {e}")
            return None
    
    async def _get_groups(self, user_name: str) -> List[Dict[str, Any]]:
        """
        Get groups for a user.
        
        Args:
            user_name: The IAM username
            
        Returns:
            List of groups
        """
        try:
            response = self.iam.list_groups_for_user(
                UserName=user_name,
                MaxItems=100
            )
            
            groups = response.get('Groups', [])
            
            # Get group details
            group_details = []
            for group in groups:
                # Get group policies
                group_policies = await self._get_group_policies(group.get('GroupName'))
                
                group_details.append({
                    'group_name': group.get('GroupName'),
                    'group_id': group.get('GroupId'),
                    'arn': group.get('Arn'),
                    'create_date': group.get('CreateDate').isoformat() if group.get('CreateDate') else None,
                    'path': group.get('Path'),
                    'attached_policies': group_policies.get('attached', []),
                    'inline_policies': group_policies.get('inline', [])
                })
            
            logger.info(f"✅ Found {len(group_details)} groups for {user_name}")
            return group_details
            
        except ClientError as e:
            logger.error(f"❌ Error getting groups: {e}")
            return []
    
    async def _get_group_policies(self, group_name: str) -> Dict[str, Any]:
        """
        Get policies for a group.
        
        Args:
            group_name: The group name
            
        Returns:
            Dictionary with attached and inline policies
        """
        result = {
            'attached': [],
            'inline': []
        }
        
        try:
            # Get attached policies
            attached_response = self.iam.list_attached_group_policies(
                GroupName=group_name,
                MaxItems=100
            )
            
            for policy in attached_response.get('AttachedPolicies', []):
                result['attached'].append({
                    'policy_name': policy.get('PolicyName'),
                    'policy_arn': policy.get('PolicyArn'),
                    'attach_date': policy.get('AttachDate').isoformat() if policy.get('AttachDate') else None
                })
            
            # Get inline policies
            inline_response = self.iam.list_group_policies(
                GroupName=group_name,
                MaxItems=100
            )
            
            for policy_name in inline_response.get('PolicyNames', []):
                try:
                    response = self.iam.get_group_policy(
                        GroupName=group_name,
                        PolicyName=policy_name
                    )
                    
                    doc = response.get('PolicyDocument')
                    if doc and isinstance(doc, str):
                        doc = json.loads(doc)
                    
                    result['inline'].append({
                        'policy_name': policy_name,
                        'policy_document': doc
                    })
                except:
                    pass
            
            return result
            
        except ClientError as e:
            logger.error(f"❌ Error getting group policies for {group_name}: {e}")
            return result
    
    async def _get_access_keys(self, user_name: str) -> List[Dict[str, Any]]:
        """
        Get access keys for a user.
        
        Args:
            user_name: The IAM username
            
        Returns:
            List of access keys
        """
        try:
            response = self.iam.list_access_keys(
                UserName=user_name,
                MaxItems=100
            )
            
            access_keys = response.get('AccessKeyMetadata', [])
            
            # Format access keys
            keys = []
            for key in access_keys:
                # Get last used details
                last_used = await self._get_access_key_last_used(key.get('AccessKeyId'))
                
                keys.append({
                    'access_key_id': key.get('AccessKeyId'),
                    'status': key.get('Status'),
                    'create_date': key.get('CreateDate').isoformat() if key.get('CreateDate') else None,
                    'last_used': last_used
                })
            
            logger.info(f"✅ Found {len(keys)} access keys for {user_name}")
            return keys
            
        except ClientError as e:
            logger.error(f"❌ Error getting access keys: {e}")
            return []
    
    async def _get_access_key_last_used(self, access_key_id: str) -> Optional[Dict[str, Any]]:
        """
        Get last used details for an access key.
        
        Args:
            access_key_id: The access key ID
            
        Returns:
            Last used details or None
        """
        try:
            response = self.iam.get_access_key_last_used(
                AccessKeyId=access_key_id
            )
            
            last_used = response.get('AccessKeyLastUsed', {})
            
            return {
                'last_used_date': last_used.get('LastUsedDate').isoformat() if last_used.get('LastUsedDate') else None,
                'region': last_used.get('Region'),
                'service_name': last_used.get('ServiceName')
            }
            
        except ClientError as e:
            logger.error(f"❌ Error getting access key last used: {e}")
            return None
    
    async def _get_user_tags(self, user_name: str) -> List[Dict[str, str]]:
        """
        Get tags for a user.
        
        Args:
            user_name: The IAM username
            
        Returns:
            List of tags
        """
        try:
            response = self.iam.list_user_tags(
                UserName=user_name,
                MaxItems=50
            )
            
            tags = response.get('Tags', [])
            
            # Format tags
            formatted_tags = [
                {
                    'key': tag.get('Key'),
                    'value': tag.get('Value')
                }
                for tag in tags
            ]
            
            logger.info(f"✅ Found {len(formatted_tags)} tags for {user_name}")
            return formatted_tags
            
        except ClientError as e:
            logger.error(f"❌ Error getting user tags: {e}")
            return []
    
    def _create_failed_artifact(self, incident_id: str, error_message: str) -> EvidenceArtifact:
        """
        Create a failed artifact when collection fails.
        
        Args:
            incident_id: The incident ID
            error_message: The error message
            
        Returns:
            EvidenceArtifact with FAILED status
        """
        from app.models.evidence import EvidenceArtifact
        
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