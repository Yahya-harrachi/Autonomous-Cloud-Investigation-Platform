# app/evidence/collectors/ec2_collector.py
"""
EC2 Collector - Collects EC2 and Security Group evidence for incidents
"""
import boto3
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from botocore.exceptions import ClientError

from app.evidence.collectors.base import BaseCollector
from app.domain.models.incident import Incident
from app.models.evidence import EvidenceArtifact
from app.core.config import settings

logger = logging.getLogger(__name__)


class EC2Collector(BaseCollector):
    """
    Collects EC2 and Security Group evidence for an incident.

    Collects:
    1. Security Group details
    2. Inbound/Outbound rules
    3. EC2 instances using the security group
    4. VPC details
    """

    def __init__(self):
        super().__init__()
        self.collector_name = "EC2Collector"

        # Initialize AWS EC2 client
        self.ec2 = boto3.client(
            'ec2',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,
            region_name=settings.AWS_DEFAULT_REGION
        )

    def get_artifact_type(self) -> str:
        return "SecurityGroup"

    def get_source(self) -> str:
        return "aws_ec2"

    async def collect(self, incident: Incident) -> Optional[EvidenceArtifact]:
        """
        Collect EC2/Security Group evidence for an incident.
        """
        logger.info(f"🔍 EC2Collector collecting evidence for incident {incident.id}")

        try:
            # 1. Extract security group ID from incident
            event_data = incident.normalized_event
            event_name = event_data.get('event_name', '')
            security_group_id = await self._extract_security_group_id(incident)

            if not security_group_id:
                logger.info(f"ℹ️ No security group found in incident {incident.id}")
                return self._create_empty_artifact(incident.id, "No security group found")

            logger.info(f"   🔒 Security Group: {security_group_id}")
            logger.info(f"   📋 Event: {event_name}")

            # 2. Collect security group evidence
            sg_evidence = await self._collect_security_group_evidence(security_group_id)

            if not sg_evidence:
                logger.info(f"ℹ️ Could not collect evidence for security group: {security_group_id}")
                return self._create_empty_artifact(incident.id, f"Could not collect evidence for security group: {security_group_id}")

            # 3. Analyze for security issues
            security_findings = self._analyze_security_group_security(sg_evidence)

            # 4. Build content
            content = {
                "security_group": sg_evidence,
                "security_findings": security_findings,
                "summary": {
                    "group_id": security_group_id,
                    "group_name": sg_evidence.get('group_name'),
                    "vpc_id": sg_evidence.get('vpc_id'),
                    "inbound_rules_count": len(sg_evidence.get('inbound_rules', [])),
                    "outbound_rules_count": len(sg_evidence.get('outbound_rules', [])),
                    "instances_count": len(sg_evidence.get('instances', [])),
                    "security_findings_count": len(security_findings)
                }
            }

            # 5. Create metadata
            extra_data = {
                "security_group_id": security_group_id,
                "group_name": sg_evidence.get('group_name'),
                "vpc_id": sg_evidence.get('vpc_id'),
                "instances_count": len(sg_evidence.get('instances', []))
            }

            # 6. Create artifact
            artifact = self.create_artifact(
                incident_id=incident.id,
                content=content,
                extra_data=extra_data,
                region=settings.AWS_DEFAULT_REGION
            )

            logger.info(f"✅ EC2 evidence collected for incident {incident.id}")
            logger.info(f"   🔒 Security Group: {security_group_id}")
            logger.info(f"   🔍 Findings: {len(security_findings)}")

            return artifact

        except ClientError as e:
            logger.error(f"❌ AWS API error: {e}")
            return self._create_failed_artifact(incident.id, str(e))
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return self._create_failed_artifact(incident.id, str(e))

    def _get_request_params(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        ✅ NEW: same resolver used across the other collectors — pulls the
        raw API call parameters from 'action_details' (the actual key on
        the normalized event; 'request_parameters' never existed there).
        Adjust the key order if your aws_normalizer.py stores it elsewhere.
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

    async def _extract_security_group_id(self, incident: Incident) -> Optional[str]:
        """Extract security group ID from incident."""
        event_data = incident.normalized_event
        event_name = event_data.get('event_name', '')

        # ✅ FIX: was event_data.get('request_parameters', {}) — that key
        # never existed on the normalized event, so this always returned {}.
        request_params = self._get_request_params(event_data)
        if 'groupId' in request_params:
            return request_params.get('groupId')
        if 'GroupId' in request_params:
            return request_params.get('GroupId')

        # Check resources
        resources = event_data.get('resources', [])
        for resource in resources:
            if resource.get('type') == 'AWS::EC2::SecurityGroup':
                return resource.get('ARN', '').split('/')[-1]
            if 'security-group' in str(resource):
                if 'sg-' in str(resource):
                    return resource

        # Check resource details
        resource_details = event_data.get('resource_details', {})
        if 'groupId' in resource_details:
            return resource_details.get('groupId')

        # Check action details (kept as explicit fallback too)
        action_details = event_data.get('action_details', {})
        if 'groupId' in action_details:
            return action_details.get('groupId')

        return None

    async def _collect_security_group_evidence(self, security_group_id: str) -> Dict[str, Any]:
        """Collect comprehensive security group evidence."""
        evidence = {
            "group_id": security_group_id,
            "group_name": None,
            "description": None,
            "vpc_id": None,
            "inbound_rules": [],
            "outbound_rules": [],
            "instances": [],
            "tags": []
        }

        try:
            # Describe security group
            response = self.ec2.describe_security_groups(
                GroupIds=[security_group_id]
            )

            sg = response.get('SecurityGroups', [])[0] if response.get('SecurityGroups') else None

            if not sg:
                logger.warning(f"⚠️ Security group not found: {security_group_id}")
                return {}

            evidence["group_name"] = sg.get('GroupName')
            evidence["description"] = sg.get('Description')
            evidence["vpc_id"] = sg.get('VpcId')
            evidence["tags"] = sg.get('Tags', [])

            # Parse inbound rules
            for rule in sg.get('IpPermissions', []):
                evidence["inbound_rules"].append(self._parse_rule(rule, 'inbound'))

            # Parse outbound rules
            for rule in sg.get('IpPermissionsEgress', []):
                evidence["outbound_rules"].append(self._parse_rule(rule, 'outbound'))

            # Get instances using this security group
            evidence["instances"] = await self._get_instances_with_security_group(security_group_id)

            logger.info(f"   ✅ Collected evidence for security group: {security_group_id}")

        except ClientError as e:
            logger.error(f"❌ Error collecting security group evidence: {e}")
            return {}

        return evidence

    def _parse_rule(self, rule: Dict[str, Any], direction: str) -> Dict[str, Any]:
        """Parse a security group rule into readable format."""
        parsed_rule = {
            "direction": direction,
            "protocol": rule.get('IpProtocol', '-1'),
            "from_port": rule.get('FromPort'),
            "to_port": rule.get('ToPort'),
            "sources": [],
            "destinations": []
        }

        # Parse IP ranges
        for ip_range in rule.get('IpRanges', []):
            parsed_rule["sources"].append({
                "type": "ipv4",
                "cidr": ip_range.get('CidrIp'),
                "description": ip_range.get('Description')
            })

        for ip_range in rule.get('Ipv6Ranges', []):
            parsed_rule["sources"].append({
                "type": "ipv6",
                "cidr": ip_range.get('CidrIpv6'),
                "description": ip_range.get('Description')
            })

        # Parse security group references
        for group in rule.get('UserIdGroupPairs', []):
            parsed_rule["sources"].append({
                "type": "security_group",
                "group_id": group.get('GroupId'),
                "group_name": group.get('GroupName'),
                "description": group.get('Description')
            })

        return parsed_rule

    async def _get_instances_with_security_group(self, security_group_id: str) -> List[Dict[str, Any]]:
        """Get EC2 instances using a security group."""
        instances = []
        try:
            response = self.ec2.describe_instances(
                Filters=[
                    {
                        'Name': 'instance.group-id',
                        'Values': [security_group_id]
                    }
                ]
            )

            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append({
                        "instance_id": instance.get('InstanceId'),
                        "instance_type": instance.get('InstanceType'),
                        "state": instance.get('State', {}).get('Name'),
                        "private_ip": instance.get('PrivateIpAddress'),
                        "public_ip": instance.get('PublicIpAddress'),
                        "launch_time": instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                        "name": self._get_instance_name(instance)
                    })
        except ClientError as e:
            logger.error(f"❌ Error getting instances: {e}")

        return instances

    def _get_instance_name(self, instance: Dict[str, Any]) -> Optional[str]:
        """Extract instance name from tags."""
        tags = instance.get('Tags', [])
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value')
        return None

    def _analyze_security_group_security(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security group for security issues."""
        findings = []

        # Check inbound rules for public access
        inbound_rules = evidence.get('inbound_rules', [])
        for rule in inbound_rules:
            for source in rule.get('sources', []):
                cidr = source.get('cidr')
                if cidr and cidr == '0.0.0.0/0':
                    # Check if it's a dangerous port
                    from_port = rule.get('from_port')
                    to_port = rule.get('to_port')

                    # SSH (22) or RDP (3389) open to world
                    if from_port == 22:
                        findings.append({
                            "severity": "critical",
                            "type": "ssh_open_to_world",
                            "description": "SSH (port 22) is open to 0.0.0.0/0",
                            "recommendation": "Restrict SSH access to specific IP ranges"
                        })
                    elif from_port == 3389:
                        findings.append({
                            "severity": "critical",
                            "type": "rdp_open_to_world",
                            "description": "RDP (port 3389) is open to 0.0.0.0/0",
                            "recommendation": "Restrict RDP access to specific IP ranges"
                        })
                    elif from_port == 3306:
                        findings.append({
                            "severity": "high",
                            "type": "mysql_open_to_world",
                            "description": "MySQL (port 3306) is open to 0.0.0.0/0",
                            "recommendation": "Restrict MySQL access to specific IP ranges"
                        })
                    elif from_port == 5432:
                        findings.append({
                            "severity": "high",
                            "type": "postgresql_open_to_world",
                            "description": "PostgreSQL (port 5432) is open to 0.0.0.0/0",
                            "recommendation": "Restrict PostgreSQL access to specific IP ranges"
                        })
                    elif from_port == 80 or from_port == 443:
                        if from_port == 80:
                            findings.append({
                                "severity": "medium",
                                "type": "http_open_to_world",
                                "description": "HTTP (port 80) is open to 0.0.0.0/0",
                                "recommendation": "Consider restricting HTTP access if not intended"
                            })
                        else:
                            findings.append({
                                "severity": "medium",
                                "type": "https_open_to_world",
                                "description": "HTTPS (port 443) is open to 0.0.0.0/0",
                                "recommendation": "Consider restricting HTTPS access if not intended"
                            })
                    else:
                        # General warning for any port open to world
                        if from_port and to_port:
                            port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                            findings.append({
                                "severity": "medium",
                                "type": "port_open_to_world",
                                "description": f"Port {port_range} ({rule.get('protocol', 'tcp')}) is open to 0.0.0.0/0",
                                "recommendation": f"Review if port {port_range} needs to be publicly accessible"
                            })

        # Check if no instances are using this security group (might be unused)
        if not evidence.get('instances'):
            findings.append({
                "severity": "low",
                "type": "unused_security_group",
                "description": "Security group is not attached to any EC2 instances",
                "recommendation": "Consider deleting if not needed"
            })

        return findings

    def _create_empty_artifact(self, incident_id: str, message: str) -> EvidenceArtifact:
        """Create an artifact with no security group found."""
        incident_uuid = self._parse_incident_id(incident_id)

        artifact = EvidenceArtifact(
            incident_id=incident_uuid,
            artifact_type=self.get_artifact_type(),
            source=self.get_source(),
            provider="aws",
            collector=self.collector_name,
            content={
                "message": message,
                "security_group": None,
                "summary": {"group_id": None, "security_findings_count": 0}
            },
            collection_status="COMPLETED",
            extra_data={"security_group_id": None, "note": "No security group found"}
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