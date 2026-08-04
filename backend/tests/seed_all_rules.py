"""
Seed ALL Rules - Event Type, Identity, Context, Threat Intel
Compatible with the unified rule evaluation engine
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.infrastructure.repositories.rule_repository import RuleRepository


def seed_all_rules():
    """Seed all rules with proper format"""
    db = SessionLocal()
    repo = RuleRepository(db)
    
    # Clear existing rules
    print("🧹 Clearing existing rules...")
    for rule in repo.get_all():
        repo.delete(str(rule.id))
    
    rules = [
        # ================================================================
        # EVENT TYPE RULES - Base Scores
        # ================================================================
        
        # CRITICAL (40)
        {
            "name": "DeleteTrail - Critical",
            "description": "CloudTrail deletion disables auditing",
            "enabled": True,
            "priority": 10,
            "rule_type": "event_type",
            "parameters": {"event_name": "DeleteTrail"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "DeleteTrail"}
                ],
                "logic": "and"
            },
            "base_score": 40,
            "modifier": 1.0,
        },
        {
            "name": "StopLogging - Critical",
            "description": "CloudTrail logging stopped",
            "enabled": True,
            "priority": 10,
            "rule_type": "event_type",
            "parameters": {"event_name": "StopLogging"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "StopLogging"}
                ],
                "logic": "and"
            },
            "base_score": 40,
            "modifier": 1.0,
        },
        {
            "name": "AttachUserPolicy - Critical",
            "description": "IAM policy attached to user",
            "enabled": True,
            "priority": 10,
            "rule_type": "event_type",
            "parameters": {"event_name": "AttachUserPolicy"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "AttachUserPolicy"}
                ],
                "logic": "and"
            },
            "base_score": 40,
            "modifier": 1.0,
        },
        {
            "name": "AttachRolePolicy - High",
            "description": "IAM policy attached to role",
            "enabled": True,
            "priority": 20,
            "rule_type": "event_type",
            "parameters": {"event_name": "AttachRolePolicy"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "AttachRolePolicy"}
                ],
                "logic": "and"
            },
            "base_score": 35,
            "modifier": 1.0,
        },
        {
            "name": "PutBucketPolicy - High",
            "description": "S3 bucket policy modified",
            "enabled": True,
            "priority": 20,
            "rule_type": "event_type",
            "parameters": {"event_name": "PutBucketPolicy"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "PutBucketPolicy"}
                ],
                "logic": "and"
            },
            "base_score": 35,
            "modifier": 1.0,
        },
        {
            "name": "AuthorizeSecurityGroupIngress - High",
            "description": "Security group ingress rule added",
            "enabled": True,
            "priority": 20,
            "rule_type": "event_type",
            "parameters": {"event_name": "AuthorizeSecurityGroupIngress"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "AuthorizeSecurityGroupIngress"}
                ],
                "logic": "and"
            },
            "base_score": 35,
            "modifier": 1.0,
        },
        {
            "name": "CreateUser - High",
            "description": "IAM user created",
            "enabled": True,
            "priority": 30,
            "rule_type": "event_type",
            "parameters": {"event_name": "CreateUser"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "CreateUser"}
                ],
                "logic": "and"
            },
            "base_score": 30,
            "modifier": 1.0,
        },
        {
            "name": "CreateRole - High",
            "description": "IAM role created",
            "enabled": True,
            "priority": 30,
            "rule_type": "event_type",
            "parameters": {"event_name": "CreateRole"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "CreateRole"}
                ],
                "logic": "and"
            },
            "base_score": 30,
            "modifier": 1.0,
        },
        
        # MEDIUM (25)
        {
            "name": "DeleteUser - Medium",
            "description": "IAM user deleted",
            "enabled": True,
            "priority": 40,
            "rule_type": "event_type",
            "parameters": {"event_name": "DeleteUser"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "DeleteUser"}
                ],
                "logic": "and"
            },
            "base_score": 25,
            "modifier": 1.0,
        },
        {
            "name": "DeleteRole - Medium",
            "description": "IAM role deleted",
            "enabled": True,
            "priority": 40,
            "rule_type": "event_type",
            "parameters": {"event_name": "DeleteRole"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "DeleteRole"}
                ],
                "logic": "and"
            },
            "base_score": 25,
            "modifier": 1.0,
        },
        {
            "name": "RevokeSecurityGroupIngress - Medium",
            "description": "Security group ingress rule removed",
            "enabled": True,
            "priority": 40,
            "rule_type": "event_type",
            "parameters": {"event_name": "RevokeSecurityGroupIngress"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "RevokeSecurityGroupIngress"}
                ],
                "logic": "and"
            },
            "base_score": 25,
            "modifier": 1.0,
        },
        {
            "name": "CreateAccessKey - Medium",
            "description": "IAM access key created",
            "enabled": True,
            "priority": 40,
            "rule_type": "event_type",
            "parameters": {"event_name": "CreateAccessKey"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "CreateAccessKey"}
                ],
                "logic": "and"
            },
            "base_score": 25,
            "modifier": 1.0,
        },
        {
            "name": "TerminateInstances - Medium",
            "description": "EC2 instance terminated",
            "enabled": True,
            "priority": 40,
            "rule_type": "event_type",
            "parameters": {"event_name": "TerminateInstances"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "TerminateInstances"}
                ],
                "logic": "and"
            },
            "base_score": 25,
            "modifier": 1.0,
        },
        {
            "name": "DeleteBucket - Medium",
            "description": "S3 bucket deleted",
            "enabled": True,
            "priority": 40,
            "rule_type": "event_type",
            "parameters": {"event_name": "DeleteBucket"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "DeleteBucket"}
                ],
                "logic": "and"
            },
            "base_score": 20,
            "modifier": 1.0,
        },
        {
            "name": "ConsoleLogin - Medium",
            "description": "Console login event",
            "enabled": True,
            "priority": 50,
            "rule_type": "event_type",
            "parameters": {"event_name": "ConsoleLogin"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "ConsoleLogin"}
                ],
                "logic": "and"
            },
            "base_score": 20,
            "modifier": 1.0,
        },
        {
            "name": "RunInstances - Medium",
            "description": "EC2 instance launched",
            "enabled": True,
            "priority": 50,
            "rule_type": "event_type",
            "parameters": {"event_name": "RunInstances"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "RunInstances"}
                ],
                "logic": "and"
            },
            "base_score": 20,
            "modifier": 1.0,
        },
        {
            "name": "CreateBucket - Medium",
            "description": "S3 bucket created",
            "enabled": True,
            "priority": 50,
            "rule_type": "event_type",
            "parameters": {"event_name": "CreateBucket"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "CreateBucket"}
                ],
                "logic": "and"
            },
            "base_score": 20,
            "modifier": 1.0,
        },
        
        # LOW (15)
        {
            "name": "AssumeRole - Low",
            "description": "Role assumed",
            "enabled": True,
            "priority": 60,
            "rule_type": "event_type",
            "parameters": {"event_name": "AssumeRole"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "AssumeRole"}
                ],
                "logic": "and"
            },
            "base_score": 15,
            "modifier": 1.0,
        },
        {
            "name": "GetCallerIdentity - Low",
            "description": "Identity check - low risk",
            "enabled": True,
            "priority": 70,
            "rule_type": "event_type",
            "parameters": {"event_name": "GetCallerIdentity"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "GetCallerIdentity"}
                ],
                "logic": "and"
            },
            "base_score": 15,
            "modifier": 1.0,
        },
        {
            "name": "LookupEvents - Low",
            "description": "CloudTrail lookup - low risk",
            "enabled": True,
            "priority": 70,
            "rule_type": "event_type",
            "parameters": {"event_name": "LookupEvents"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "LookupEvents"}
                ],
                "logic": "and"
            },
            "base_score": 15,
            "modifier": 1.0,
        },
        {
            "name": "ListImages - Low",
            "description": "Image listing - low risk",
            "enabled": True,
            "priority": 70,
            "rule_type": "event_type",
            "parameters": {"event_name": "ListImages"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "ListImages"}
                ],
                "logic": "and"
            },
            "base_score": 15,
            "modifier": 1.0,
        },
        {
            "name": "ListJobTemplates - Low",
            "description": "Job template listing - low risk",
            "enabled": True,
            "priority": 70,
            "rule_type": "event_type",
            "parameters": {"event_name": "ListJobTemplates"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "ListJobTemplates"}
                ],
                "logic": "and"
            },
            "base_score": 15,
            "modifier": 1.0,
        },
        {
            "name": "CreateKeyPair - Low",
            "description": "EC2 key pair created",
            "enabled": True,
            "priority": 70,
            "rule_type": "event_type",
            "parameters": {"event_name": "CreateKeyPair"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "CreateKeyPair"}
                ],
                "logic": "and"
            },
            "base_score": 10,
            "modifier": 1.0,
        },
        {
            "name": "DescribeInstanceTypes - Low",
            "description": "Instance type description - low risk",
            "enabled": True,
            "priority": 70,
            "rule_type": "event_type",
            "parameters": {"event_name": "DescribeInstanceTypes"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "DescribeInstanceTypes"}
                ],
                "logic": "and"
            },
            "base_score": 10,
            "modifier": 1.0,
        },
        {
            "name": "ListManagedNotificationEvents - Low",
            "description": "Notification events listing - low risk",
            "enabled": True,
            "priority": 70,
            "rule_type": "event_type",
            "parameters": {"event_name": "ListManagedNotificationEvents"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "ListManagedNotificationEvents"}
                ],
                "logic": "and"
            },
            "base_score": 10,
            "modifier": 1.0,
        },
        {
            "name": "ListPipelines - Low",
            "description": "Pipeline listing - low risk",
            "enabled": True,
            "priority": 70,
            "rule_type": "event_type",
            "parameters": {"event_name": "ListPipelines"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "ListPipelines"}
                ],
                "logic": "and"
            },
            "base_score": 10,
            "modifier": 1.0,
        },
        
        # DEFAULT (10) - Catches all other events
        {
            "name": "Default - All Events",
            "description": "Default base score for events without specific rules",
            "enabled": True,
            "priority": 999,
            "rule_type": "custom",
            "parameters": {
                "condition_json": '{"conditions": [{"field": "event_name", "operator": "neq", "value": ""}], "logic": "and"}'
            },
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "neq", "value": ""}
                ],
                "logic": "and"
            },
            "base_score": 10,
            "modifier": 1.0,
        },
        
        # ================================================================
        # IDENTITY RULES
        # ================================================================
        {
            "name": "Root User - Critical",
            "description": "Root user actions have highest risk",
            "enabled": True,
            "priority": 10,
            "rule_type": "identity",
            "parameters": {"identity_type": "root"},
            "condition": {
                "conditions": [
                    {"field": "identity_type", "operator": "eq", "value": "root"}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 2.0,
        },
        {
            "name": "Assumed Role - High",
            "description": "Assumed roles may have elevated permissions",
            "enabled": True,
            "priority": 20,
            "rule_type": "identity",
            "parameters": {"identity_type": "assumed_role"},
            "condition": {
                "conditions": [
                    {"field": "identity_type", "operator": "eq", "value": "assumed_role"}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 1.5,
        },
        {
            "name": "IAM User - Normal",
            "description": "Normal IAM user (baseline)",
            "enabled": True,
            "priority": 40,
            "rule_type": "identity",
            "parameters": {"identity_type": "iamuser"},
            "condition": {
                "conditions": [
                    {"field": "identity_type", "operator": "eq", "value": "iamuser"}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 1.0,
        },
        {
            "name": "Service Account - Lower Risk",
            "description": "Service accounts have limited, specific permissions",
            "enabled": True,
            "priority": 50,
            "rule_type": "identity",
            "parameters": {"identity_type": "awsservice"},
            "condition": {
                "conditions": [
                    {"field": "identity_type", "operator": "eq", "value": "awsservice"}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 0.8,
        },
        
        # ================================================================
        # CONTEXT RULES
        # ================================================================
        {
            "name": "Off-Hours - Higher Risk",
            "description": "Actions during off-hours (10 PM - 6 AM)",
            "enabled": True,
            "priority": 10,
            "rule_type": "context",
            "parameters": {"context_type": "off_hours", "start_time": "22:00", "end_time": "06:00"},
            "condition": {
                "conditions": [
                    {"field": "hour", "operator": "gte", "value": 22},
                    {"field": "hour", "operator": "lt", "value": 6}
                ],
                "logic": "or"
            },
            "base_score": 0,
            "modifier": 2.0,
        },
        {
            "name": "Public IP - Higher Risk",
            "description": "Actions from public IP addresses",
            "enabled": True,
            "priority": 20,
            "rule_type": "context",
            "parameters": {"context_type": "public_ip"},
            "condition": {
                "conditions": [
                    {"field": "actor_ip", "operator": "is_public", "value": True}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 1.3,
        },
        {
            "name": "Read-Only - Lower Risk",
            "description": "Read-only operations have lower impact",
            "enabled": True,
            "priority": 30,
            "rule_type": "context",
            "parameters": {"context_type": "read_only"},
            "condition": {
                "conditions": [
                    {"field": "is_read_only", "operator": "eq", "value": True}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 0.7,
        },
        {
            "name": "Weekend - Higher Risk",
            "description": "Actions during weekends",
            "enabled": True,
            "priority": 40,
            "rule_type": "context",
            "parameters": {"context_type": "weekend"},
            "condition": {
                "conditions": [
                    {"field": "day_of_week", "operator": "in", "value": ["saturday", "sunday"]}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 1.5,
        },
        
        # ================================================================
        # THREAT INTELLIGENCE RULES
        # ================================================================
        {
            "name": "Malicious IP - Critical",
            "description": "Known malicious IP addresses",
            "enabled": True,
            "priority": 5,
            "rule_type": "threat_intel",
            "parameters": {"min_confidence": 75},
            "condition": {
                "conditions": [
                    {"field": "threat_intel_confidence", "operator": "gte", "value": 75}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 2.5,
        },
        {
            "name": "Suspicious IP - High",
            "description": "Suspicious IP addresses",
            "enabled": True,
            "priority": 10,
            "rule_type": "threat_intel",
            "parameters": {"min_confidence": 50},
            "condition": {
                "conditions": [
                    {"field": "threat_intel_confidence", "operator": "gte", "value": 50}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 1.8,
        },
    ]
    
    print(f"\n📊 Creating {len(rules)} rules...")
    
    for rule_data in rules:
        try:
            rule = repo.create(rule_data)
            status = "✅" if rule.enabled else "❌"
            print(f"  {status} {rule.name} (Base: {rule.base_score}, Modifier: {rule.modifier}x, Priority: {rule.priority})")
        except Exception as e:
            print(f"  ❌ Failed to create {rule_data['name']}: {e}")
    
    db.close()
    print("\n✅ All rules seeded successfully!")


if __name__ == "__main__":
    seed_all_rules()