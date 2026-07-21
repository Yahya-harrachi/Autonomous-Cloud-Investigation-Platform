"""
Mock event source with REALISTIC cloud security events
"""
import json
import random
import uuid
from datetime import datetime, timedelta
from typing import List
from ...domain.models.event import RawEvent

class MockEventSource:
    """Generates realistic cloud security events"""
    
    def __init__(self):
        self.event_count = 0
    
    def get_events(self, count: int = 3) -> List[RawEvent]:
        """Generate realistic mock events"""
        events = []
        
        # Generate different types of events
        event_generators = [
            self._generate_aws_cloudtrail_event,
            self._generate_aws_guardduty_event,
            self._generate_azure_activity_event,
            self._generate_gcp_audit_event,
            self._generate_aws_s3_event,
            self._generate_aws_iam_event
        ]
        
        for _ in range(count):
            generator = random.choice(event_generators)
            event = generator()
            events.append(event)
            self.event_count += 1
        
        return events
    
    def _generate_aws_cloudtrail_event(self) -> RawEvent:
        """Generate a realistic AWS CloudTrail event"""
        event_types = [
            "ConsoleLogin",
            "CreateKeyPair",
            "AuthorizeSecurityGroupIngress",
            "CreateBucket",
            "DeleteBucket",
            "PutBucketPolicy"
        ]
        
        event_type = random.choice(event_types)
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))
        
        event_data = {
            "eventVersion": "1.08",
            "eventID": f"cloudtrail-{uuid.uuid4().hex[:16]}",
            "eventType": "AwsApiCall",
            "eventName": event_type,
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": random.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2"]),
            "sourceIPAddress": f"{random.randint(10, 200)}.{random.randint(10, 200)}.{random.randint(10, 200)}.{random.randint(10, 200)}",
            "userAgent": f"aws-cli/2.13.0 Python/3.11.0 Linux/5.15.0-1022-aws",
            "requestParameters": {
                "keyName": f"key-{uuid.uuid4().hex[:8]}",
                "instanceType": random.choice(["t2.micro", "t3.medium", "m5.large"]),
                "subnetId": f"subnet-{uuid.uuid4().hex[:12]}"
            },
            "responseElements": {
                "keyId": f"key-{uuid.uuid4().hex[:8]}",
                "requestId": f"req-{uuid.uuid4().hex[:12]}"
            },
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDAI{random.choice(['A', 'B', 'C', 'D'])}XS{random.randint(10000, 99999)}",
                "arn": f"arn:aws:iam::123456789012:user/{random.choice(['admin', 'devops', 'security', 'developer'])}",
                "accountId": "123456789012",
                "userName": random.choice(["admin-user", "dev-ops", "security-auditor", "automation-service"])
            },
            "eventTime": timestamp.isoformat() + "Z",
            "eventCategory": "Management",
            "readOnly": False,
            "resources": [
                {
                    "type": "AWS::EC2::Instance",
                    "ARN": f"arn:aws:ec2:us-east-1:123456789012:instance/i-{uuid.uuid4().hex[:10]}"
                }
            ],
            "managementEvent": True,
            "recipientAccountId": "123456789012",
            "sharedEventID": str(uuid.uuid4()),
            "vpcEndpointId": f"vpce-{uuid.uuid4().hex[:12]}"
        }
        
        return RawEvent(
            source="aws",
            provider="cloudtrail",
            event_type=event_type,
            data=event_data,
            timestamp=timestamp,
            received_at=datetime.utcnow(),
            raw_json=json.dumps(event_data, indent=2)
        )
    
    def _generate_aws_guardduty_event(self) -> RawEvent:
        """Generate a realistic AWS GuardDuty finding"""
        finding_types = [
            "UnauthorizedAccess:IAMUser/ConsoleLogin",
            "CryptoCurrency:EC2/BitcoinTool.B",
            "Recon:EC2/Portscan",
            "Backdoor:EC2/DenialOfService.Tcp",
            "Policy:IAMUser/RootCredentialUsage"
        ]
        
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 300))
        
        event_data = {
            "version": "1.1",
            "id": f"guardduty-{uuid.uuid4().hex[:16]}",
            "accountId": "123456789012",
            "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
            "type": random.choice(finding_types),
            "severity": random.randint(1, 10),
            "createdAt": (timestamp - timedelta(hours=1)).isoformat() + "Z",
            "updatedAt": timestamp.isoformat() + "Z",
            "title": "Unusual API activity detected from suspicious IP",
            "description": "An IAM user performed API calls from an IP address that is known to be used by threat actors.",
            "service": {
                "action": {
                    "actionType": "AWS_API_CALL",
                    "awsApiCallAction": {
                        "api": random.choice(["ec2.DescribeInstances", "s3.ListBuckets", "iam.CreateUser"]),
                        "serviceName": random.choice(["ec2.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com"]),
                        "remoteIpDetails": {
                            "ipAddressV4": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                            "country": {
                                "countryName": random.choice(["Russia", "China", "Iran", "North Korea"])
                            }
                        }
                    }
                },
                "resourceRole": "TARGET",
                "eventFirstSeen": (timestamp - timedelta(hours=1)).isoformat() + "Z",
                "eventLastSeen": timestamp.isoformat() + "Z",
                "archived": False,
                "count": random.randint(1, 50)
            },
            "resource": {
                "instanceDetails": {
                    "instanceId": f"i-{uuid.uuid4().hex[:10]}",
                    "instanceType": random.choice(["t2.micro", "t3.large", "m5.xlarge"]),
                    "launchTime": (timestamp - timedelta(days=random.randint(1, 30))).isoformat() + "Z",
                    "tags": [
                        {"key": "Environment", "value": "Production"},
                        {"key": "Application", "value": "WebApp"}
                    ]
                }
            }
        }
        
        return RawEvent(
            source="aws",
            provider="guardduty",
            event_type=random.choice(finding_types),
            data=event_data,
            timestamp=timestamp,
            received_at=datetime.utcnow(),
            raw_json=json.dumps(event_data, indent=2)
        )
    
    def _generate_azure_activity_event(self) -> RawEvent:
        """Generate a realistic Azure Activity Log event"""
        event_types = [
            "Create VM",
            "Delete VM",
            "Network Security Group Creation",
            "Role Assignment",
            "Storage Account Creation",
            "Key Vault Operation"
        ]
        
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 300))
        
        event_data = {
            "authorization": {
                "action": random.choice([
                    "Microsoft.Compute/virtualMachines/write",
                    "Microsoft.Network/networkSecurityGroups/write",
                    "Microsoft.Storage/storageAccounts/write",
                    "Microsoft.Authorization/roleAssignments/write"
                ]),
                "role": random.choice(["Owner", "Contributor", "Reader"]),
                "scope": f"/subscriptions/{uuid.uuid4().hex[:8]}/resourceGroups/prod-rg"
            },
            "caller": random.choice(["admin@company.com", "devops@company.com", "security@company.com"]),
            "description": random.choice([
                "Virtual machine was created",
                "Virtual machine was deleted",
                "Network security group was modified",
                "Role assignment was created"
            ]),
            "eventDataId": str(uuid.uuid4()),
            "eventName": {
                "value": random.choice(event_types),
                "localizedValue": random.choice(["Virtual Machine Created", "Resource Deleted", "Role Assigned"])
            },
            "category": {
                "value": "Administrative",
                "localizedValue": "Administrative"
            },
            "id": f"/subscriptions/{uuid.uuid4().hex[:8]}/resourceGroups/prod-rg/providers/Microsoft.Insights/eventtypes/management/guid/{uuid.uuid4()}",
            "level": random.choice(["Informational", "Warning", "Error", "Critical"]),
            "operationId": str(uuid.uuid4()),
            "operationName": {
                "value": random.choice(["Microsoft.Compute/virtualMachines/write", "Microsoft.Storage/storageAccounts/write"]),
                "localizedValue": random.choice(["Create Virtual Machine", "Create Storage Account"])
            },
            "resourceGroupName": "prod-rg",
            "resourceProviderName": {
                "value": random.choice(["Microsoft.Compute", "Microsoft.Storage", "Microsoft.Network"]),
                "localizedValue": random.choice(["Compute", "Storage", "Network"])
            },
            "resourceType": {
                "value": random.choice(["virtualMachines", "storageAccounts", "networkSecurityGroups"]),
                "localizedValue": random.choice(["Virtual Machines", "Storage Accounts", "Network Security Groups"])
            },
            "eventTimestamp": timestamp.isoformat() + "Z",
            "submissionTimestamp": (timestamp + timedelta(minutes=1)).isoformat() + "Z",
            "subscriptionId": f"{uuid.uuid4().hex[:8]}",
            "tenantId": f"{uuid.uuid4().hex[:8]}",
            "correlationId": str(uuid.uuid4()),
            "properties": {
                "status": random.choice(["Succeeded", "Failed", "Accepted"]),
                "requestId": str(uuid.uuid4()),
                "resourceId": f"/subscriptions/{uuid.uuid4().hex[:8]}/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-{random.randint(1, 100)}",
                "eventCategory": "Administrative"
            }
        }
        
        return RawEvent(
            source="azure",
            provider="activity_logs",
            event_type=random.choice(event_types),
            data=event_data,
            timestamp=timestamp,
            received_at=datetime.utcnow(),
            raw_json=json.dumps(event_data, indent=2)
        )
    
    def _generate_gcp_audit_event(self) -> RawEvent:
        """Generate a realistic GCP Audit Log event"""
        event_types = [
            "Create Instance",
            "Delete Instance",
            "Create Bucket",
            "Update IAM Policy",
            "Start VM"
        ]
        
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 300))
        
        event_data = {
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {
                    "principalEmail": random.choice([
                        "admin@company.com",
                        "service-account@project.iam.gserviceaccount.com",
                        "user@company.com"
                    ])
                },
                "requestMetadata": {
                    "callerIp": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "callerSuppliedUserAgent": random.choice([
                        "gcloud/452.0.0",
                        "Google-Cloud-SDK/452.0.0",
                        "terraform/1.5.0"
                    ]),
                    "callerNetwork": "/projects/project-id/global/networks/default"
                },
                "serviceName": random.choice([
                    "compute.googleapis.com",
                    "storage.googleapis.com",
                    "iam.googleapis.com"
                ]),
                "methodName": random.choice([
                    "v1.compute.instances.insert",
                    "v1.compute.instances.delete",
                    "v1.storage.buckets.create",
                    "v1.iam.serviceAccounts.setIamPolicy"
                ]),
                "resourceName": f"projects/project-id/zones/us-central1-a/instances/instance-{random.randint(1, 100)}",
                "request": {
                    "@type": "type.googleapis.com/compute.instances.insert",
                    "name": f"instance-{random.randint(1, 100)}",
                    "zone": "us-central1-a",
                    "machineType": random.choice(["n1-standard-1", "n1-standard-2", "n1-standard-4"])
                },
                "response": {
                    "@type": "type.googleapis.com/compute.operation",
                    "status": "DONE"
                },
                "metadata": {
                    "@type": "type.googleapis.com/google.cloud.audit.GcpAuditMetadata",
                    "resourceName": f"projects/project-id/zones/us-central1-a/instances/instance-{random.randint(1, 100)}"
                }
            },
            "insertId": f"insert-{uuid.uuid4().hex[:12]}",
            "resource": {
                "type": random.choice(["gce_instance", "gcs_bucket", "iam_role"]),
                "labels": {
                    "project_id": "project-id",
                    "instance_id": str(random.randint(100000, 999999)),
                    "zone": random.choice(["us-central1-a", "us-east1-b", "europe-west1-c"])
                }
            },
            "timestamp": timestamp.isoformat() + "Z",
            "severity": random.choice(["INFO", "WARNING", "ERROR", "CRITICAL"]),
            "logName": "projects/project-id/logs/cloudaudit.googleapis.com%2Factivity",
            "receiveTimestamp": (timestamp + timedelta(seconds=5)).isoformat() + "Z",
            "resourceName": f"projects/project-id/zones/us-central1-a/instances/instance-{random.randint(1, 100)}",
            "operation": {
                "id": f"operation-{uuid.uuid4().hex[:12]}",
                "producer": "compute.googleapis.com",
                "last": True
            }
        }
        
        return RawEvent(
            source="gcp",
            provider="audit_logs",
            event_type=random.choice(event_types),
            data=event_data,
            timestamp=timestamp,
            received_at=datetime.utcnow(),
            raw_json=json.dumps(event_data, indent=2)
        )
    
    def _generate_aws_s3_event(self) -> RawEvent:
        """Generate a realistic S3 event (Object-level)"""
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))
        
        event_data = {
            "Records": [
                {
                    "eventVersion": "2.1",
                    "eventSource": "aws:s3",
                    "awsRegion": random.choice(["us-east-1", "us-west-2"]),
                    "eventTime": timestamp.isoformat() + "Z",
                    "eventName": random.choice(["PutObject", "DeleteObject", "CopyObject"]),
                    "userIdentity": {
                        "principalId": f"AWS:{uuid.uuid4().hex[:16]}"
                    },
                    "requestParameters": {
                        "sourceIPAddress": f"{random.randint(10, 200)}.{random.randint(10, 200)}.{random.randint(10, 200)}.{random.randint(10, 200)}"
                    },
                    "responseElements": {
                        "x-amz-request-id": f"req-{uuid.uuid4().hex[:12]}",
                        "x-amz-id-2": f"id-{uuid.uuid4().hex[:20]}"
                    },
                    "s3": {
                        "s3SchemaVersion": "1.0",
                        "configurationId": random.choice(["prod-bucket-events", "audit-bucket-events"]),
                        "bucket": {
                            "name": f"production-bucket-{random.randint(1, 100)}",
                            "ownerIdentity": {
                                "principalId": f"AIDAI{random.choice(['A','B','C','D'])}XS{random.randint(10000, 99999)}"
                            },
                            "arn": f"arn:aws:s3:::production-bucket-{random.randint(1, 100)}"
                        },
                        "object": {
                            "key": f"logs/application-{random.randint(1, 100)}.log",
                            "size": random.randint(1024, 10485760),
                            "eTag": f"{uuid.uuid4().hex[:16]}",
                            "versionId": str(uuid.uuid4())
                        }
                    }
                }
            ]
        }
        
        return RawEvent(
            source="aws",
            provider="s3_events",
            event_type=random.choice(["PutObject", "DeleteObject", "CopyObject"]),
            data=event_data,
            timestamp=timestamp,
            received_at=datetime.utcnow(),
            raw_json=json.dumps(event_data, indent=2)
        )
    
    def _generate_aws_iam_event(self) -> RawEvent:
        """Generate a realistic IAM event"""
        event_types = [
            "CreateUser",
            "DeleteUser",
            "AttachUserPolicy",
            "DetachUserPolicy",
            "CreateRole",
            "DeleteRole"
        ]
        
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 300))
        event_type = random.choice(event_types)
        
        event_data = {
            "eventVersion": "1.08",
            "eventID": f"iam-{uuid.uuid4().hex[:16]}",
            "eventType": "AwsApiCall",
            "eventName": event_type,
            "eventSource": "iam.amazonaws.com",
            "awsRegion": random.choice(["us-east-1", "us-west-2"]),
            "sourceIPAddress": f"{random.randint(10, 200)}.{random.randint(10, 200)}.{random.randint(10, 200)}.{random.randint(10, 200)}",
            "userAgent": f"aws-cli/2.13.0 Python/3.11.0",
            "requestParameters": {
                "userName": f"{random.choice(['admin', 'dev', 'security', 'audit'])}-{random.randint(1, 100)}",
                "path": "/"
            },
            "responseElements": {
                "user": {
                    "path": "/",
                    "userName": f"{random.choice(['admin', 'dev', 'security', 'audit'])}-{random.randint(1, 100)}",
                    "userId": f"AIDAI{random.choice(['A','B','C','D'])}XS{random.randint(10000, 99999)}",
                    "arn": f"arn:aws:iam::123456789012:user/{random.choice(['admin', 'dev', 'security', 'audit'])}-{random.randint(1, 100)}",
                    "createDate": (timestamp - timedelta(days=random.randint(0, 30))).isoformat() + "Z"
                }
            },
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDAI{random.choice(['A','B','C','D'])}XS{random.randint(10000, 99999)}",
                "arn": f"arn:aws:iam::123456789012:user/{random.choice(['admin', 'devops', 'security'])}",
                "accountId": "123456789012",
                "userName": random.choice(["admin-user", "devops-service", "security-auditor"])
            },
            "eventTime": timestamp.isoformat() + "Z",
            "eventCategory": "Management",
            "readOnly": False,
            "resources": [
                {
                    "type": "AWS::IAM::User",
                    "ARN": f"arn:aws:iam::123456789012:user/{random.choice(['admin','dev','security','audit'])}-{random.randint(1, 100)}"
                }
            ]
        }
        
        return RawEvent(
            source="aws",
            provider="iam",
            event_type=event_type,
            data=event_data,
            timestamp=timestamp,
            received_at=datetime.utcnow(),
            raw_json=json.dumps(event_data, indent=2)
        )