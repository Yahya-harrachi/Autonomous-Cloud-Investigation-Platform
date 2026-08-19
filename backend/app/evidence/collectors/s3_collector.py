# app/evidence/collectors/s3_collector.py
"""
S3 Collector - Collects S3 bucket evidence for incidents
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


class S3Collector(BaseCollector):
    """
    Collects S3 bucket evidence for an incident.
    
    Collects:
    1. Bucket details (name, region, creation date)
    2. Bucket policy
    3. Bucket ACL
    4. Public access block configuration
    5. Bucket encryption
    6. Bucket versioning
    7. Bucket logging
    8. Bucket website configuration
    """

    def __init__(self):
        super().__init__()
        self.collector_name = "S3Collector"

        # Initialize AWS S3 client
        self.s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,
            region_name=settings.AWS_DEFAULT_REGION
        )

    def get_artifact_type(self) -> str:
        return "S3Bucket"

    def get_source(self) -> str:
        return "aws_s3"

    async def collect(self, incident: Incident) -> Optional[EvidenceArtifact]:
        """
        Collect S3 bucket evidence for an incident.
        """
        logger.info(f"🔍 S3Collector collecting evidence for incident {incident.id}")

        try:
            # 1. Extract bucket name from incident
            event_data = incident.normalized_event
            event_name = event_data.get('event_name', '')
            bucket_name = await self._extract_bucket_name(incident)

            if not bucket_name:
                logger.info(f"ℹ️ No bucket name found - returning empty artifact")
                return self._create_empty_artifact(incident.id, "No S3 bucket found")

            logger.info(f"   🪣 Bucket: {bucket_name}")
            logger.info(f"   📋 Event: {event_name}")

            # 2. Collect bucket evidence
            bucket_evidence = await self._collect_bucket_evidence(bucket_name)

            if not bucket_evidence:
                logger.info(f"ℹ️ Could not collect evidence for bucket: {bucket_name}")
                return self._create_empty_artifact(incident.id, f"Could not collect evidence for bucket: {bucket_name}")

            # 3. Analyze for security issues
            security_findings = self._analyze_bucket_security(bucket_evidence)

            # 4. Build content
            content = {
                "bucket": bucket_evidence,
                "security_findings": security_findings,
                "summary": {
                    "bucket_name": bucket_name,
                    "region": bucket_evidence.get('region'),
                    "is_public": bucket_evidence.get('is_public', False),
                    "has_policy": bucket_evidence.get('policy') is not None,
                    "has_encryption": bucket_evidence.get('encryption') is not None,
                    "security_findings_count": len(security_findings)
                }
            }

            # 5. Create metadata
            extra_data = {
                "bucket_name": bucket_name,
                "region": bucket_evidence.get('region'),
                "is_public": bucket_evidence.get('is_public', False),
                "has_policy": bucket_evidence.get('policy') is not None
            }

            # 6. Create artifact
            artifact = self.create_artifact(
                incident_id=incident.id,
                content=content,
                extra_data=extra_data,
                region=bucket_evidence.get('region', settings.AWS_DEFAULT_REGION)
            )

            logger.info(f"✅ S3 evidence collected for incident {incident.id}")
            logger.info(f"   🪣 Bucket: {bucket_name}")
            logger.info(f"   🔍 Findings: {len(security_findings)}")

            return artifact

        except ClientError as e:
            logger.error(f"❌ AWS API error: {e}")
            return self._create_failed_artifact(incident.id, str(e))
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return self._create_empty_artifact(incident.id, f"Collection error: {str(e)}")

    def _get_request_params(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Pull the raw API call parameters from 'action_details' 
        (the actual key on the normalized event; 'request_parameters' never existed there).
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

    async def _extract_bucket_name(self, incident: Incident) -> Optional[str]:
        """Extract bucket name from incident."""
        event_data = incident.normalized_event
        event_name = event_data.get('event_name', '')

        # ✅ Use the request params resolver
        request_params = self._get_request_params(event_data)
        if 'bucketName' in request_params:
            return request_params.get('bucketName')
        if 'BucketName' in request_params:
            return request_params.get('BucketName')
        if 'bucket' in request_params:
            return request_params.get('bucket')

        # Check action details (fallback)
        action_details = event_data.get('action_details', {})
        if 'bucketName' in action_details:
            return action_details.get('bucketName')
        if 'Bucket' in action_details:
            return action_details.get('Bucket')

        # Check resource
        resource = event_data.get('resource', '')
        if 'arn:aws:s3:::' in resource:
            return resource.split('arn:aws:s3:::')[-1]

        # Check metadata
        metadata = incident.metadata or {}
        if 'bucket_name' in metadata:
            return metadata.get('bucket_name')

        return None

    async def _collect_bucket_evidence(self, bucket_name: str) -> Dict[str, Any]:
        """Collect comprehensive bucket evidence."""
        evidence = {
            "bucket_name": bucket_name,
            "region": None,
            "creation_date": None,
            "is_public": False,
            "policy": None,
            "acl": None,
            "public_access_block": None,
            "encryption": None,
            "versioning": None,
            "logging": None,
            "website": None,
            "tags": []
        }

        try:
            # Get bucket location
            location = self.s3.get_bucket_location(Bucket=bucket_name)
            evidence["region"] = location.get('LocationConstraint') or 'us-east-1'

            # Get bucket policy
            try:
                policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                if policy.get('Policy'):
                    evidence["policy"] = json.loads(policy.get('Policy'))
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"⚠️ Error getting bucket policy: {e}")

            # Get bucket ACL
            try:
                acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                evidence["acl"] = self._parse_acl(acl)
            except ClientError as e:
                logger.warning(f"⚠️ Error getting bucket ACL: {e}")

            # Get public access block
            try:
                response = self.s3.get_public_access_block(Bucket=bucket_name)
                evidence["public_access_block"] = response.get('PublicAccessBlockConfiguration', {})
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                    logger.warning(f"⚠️ Error getting public access block: {e}")

            # Get encryption
            try:
                encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                evidence["encryption"] = encryption.get('ServerSideEncryptionConfiguration', {})
            except ClientError as e:
                if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                    logger.warning(f"⚠️ Error getting bucket encryption: {e}")

            # Get versioning
            try:
                versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                evidence["versioning"] = versioning
            except ClientError as e:
                logger.warning(f"⚠️ Error getting bucket versioning: {e}")

            # Get logging
            try:
                logging_config = self.s3.get_bucket_logging(Bucket=bucket_name)
                evidence["logging"] = logging_config
            except ClientError as e:
                logger.warning(f"⚠️ Error getting bucket logging: {e}")

            # Get website
            try:
                website = self.s3.get_bucket_website(Bucket=bucket_name)
                evidence["website"] = website
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchWebsiteConfiguration':
                    logger.warning(f"⚠️ Error getting bucket website: {e}")

            # Get tags
            try:
                tags = self.s3.get_bucket_tagging(Bucket=bucket_name)
                evidence["tags"] = tags.get('TagSet', [])
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchTagSet':
                    logger.warning(f"⚠️ Error getting bucket tags: {e}")

            # Determine if public
            evidence["is_public"] = self._check_is_public(evidence)

            logger.info(f"   ✅ Collected evidence for bucket: {bucket_name}")

        except ClientError as e:
            logger.error(f"❌ Error collecting bucket evidence: {e}")
            return {}

        return evidence

    def _parse_acl(self, acl: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse ACL into readable format."""
        grants = []
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            grants.append({
                "permission": grant.get('Permission'),
                "type": grantee.get('Type'),
                "uri": grantee.get('URI'),
                "id": grantee.get('ID'),
                "display_name": grantee.get('DisplayName')
            })
        return grants

    def _check_is_public(self, evidence: Dict[str, Any]) -> bool:
        """Check if bucket is public."""
        # Check public access block
        public_access_block = evidence.get('public_access_block', {})
        if public_access_block:
            if (public_access_block.get('BlockPublicAcls', False) and
                public_access_block.get('IgnorePublicAcls', False) and
                public_access_block.get('BlockPublicPolicy', False) and
                public_access_block.get('RestrictPublicBuckets', False)):
                return False

        # Check ACL
        acl = evidence.get('acl', [])
        for grant in acl:
            if grant.get('uri') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                return True
            if grant.get('uri') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                return True

        # Check policy
        policy = evidence.get('policy', {})
        if policy:
            statements = policy.get('Statement', [])
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    if principal == '*' or principal.get('AWS') == '*':
                        return True

        return False

    def _analyze_bucket_security(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze bucket for security issues."""
        findings = []

        # Check if public
        if evidence.get('is_public', False):
            findings.append({
                "severity": "critical",
                "type": "public_bucket",
                "description": "Bucket is publicly accessible",
                "recommendation": "Immediately block public access to this bucket"
            })

        # Check encryption
        if not evidence.get('encryption'):
            findings.append({
                "severity": "medium",
                "type": "no_encryption",
                "description": "Bucket does not have server-side encryption enabled",
                "recommendation": "Enable server-side encryption for this bucket"
            })

        # Check versioning
        versioning = evidence.get('versioning', {})
        if versioning.get('Status') != 'Enabled':
            findings.append({
                "severity": "medium",
                "type": "no_versioning",
                "description": "Bucket versioning is not enabled",
                "recommendation": "Enable versioning to protect against accidental deletion"
            })

        # Check logging
        logging_config = evidence.get('logging', {})
        if not logging_config.get('LoggingEnabled'):
            findings.append({
                "severity": "low",
                "type": "no_logging",
                "description": "Bucket access logging is not enabled",
                "recommendation": "Enable access logging for audit purposes"
            })

        # Check public access block
        public_access_block = evidence.get('public_access_block', {})
        if public_access_block:
            if not public_access_block.get('BlockPublicAcls'):
                findings.append({
                    "severity": "high",
                    "type": "public_acl_allowed",
                    "description": "BlockPublicAcls is not enabled",
                    "recommendation": "Enable BlockPublicAcls to prevent public ACLs"
                })
        else:
            findings.append({
                "severity": "high",
                "type": "no_public_access_block",
                "description": "Public Access Block is not configured",
                "recommendation": "Configure Public Access Block for this bucket"
            })

        return findings

    def _create_empty_artifact(self, incident_id: str, message: str) -> EvidenceArtifact:
        """Create an artifact with no bucket found."""
        incident_uuid = self._parse_incident_id(incident_id)

        artifact = EvidenceArtifact(
            incident_id=incident_uuid,
            artifact_type=self.get_artifact_type(),
            source=self.get_source(),
            provider="aws",
            collector=self.collector_name,
            content={
                "message": message,
                "bucket": None,
                "security_findings": [],
                "summary": {
                    "bucket_name": None,
                    "region": None,
                    "is_public": False,
                    "has_policy": False,
                    "has_encryption": False,
                    "security_findings_count": 0
                }
            },
            collection_status="COMPLETED",
            extra_data={"bucket_name": None, "note": "No bucket found"}
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