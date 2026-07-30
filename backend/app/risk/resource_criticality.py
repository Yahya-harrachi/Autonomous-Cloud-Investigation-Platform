"""
Resource Criticality Scores
Defines how critical different resources are.
"""
from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class ResourceCriticality:
    """Criticality information for a resource"""
    base_score: int          # 0-20
    environment_modifier: float  # 0.5-2.0
    sensitive_data_modifier: float  # 0.5-2.0
    reasoning: str


# ============================================================
# RESOURCE TYPE BASE SCORES (0-20)
# ============================================================

RESOURCE_TYPE_SCORES: Dict[str, int] = {
    # ===== CRITICAL RESOURCES (15-20) =====
    "cloudtrail_trail": 20,      # Audit logging
    "iam_role": 18,               # Identity and access
    "iam_user": 18,
    "iam_policy": 18,
    "security_group": 16,
    "vpc": 16,
    "kms_key": 20,               # Encryption keys
    "secrets_manager_secret": 20,
    "parameter_store": 18,
    "s3_bucket": 16,
    "rds_database": 16,
    "route53_hosted_zone": 16,
    "cloudfront_distribution": 16,
    "cloudformation_stack": 16,
    
    # ===== MEDIUM RESOURCES (8-14) =====
    "ec2_instance": 12,
    "ec2_key_pair": 10,
    "ec2_volume": 10,
    "ec2_snapshot": 8,
    "vpn_connection": 10,
    "load_balancer": 12,
    "lambda_function": 12,
    "api_gateway": 12,
    "dynamodb_table": 12,
    "elasticsearch_domain": 12,
    "redshift_cluster": 12,
    "elasticache_cluster": 10,
    "efs_file_system": 10,
    "fsx_file_system": 10,
    
    # ===== LOW RESOURCES (1-7) =====
    "sns_topic": 6,
    "sqs_queue": 6,
    "cloudwatch_log_group": 5,
    "cloudwatch_alarm": 5,
    "eventbridge_rule": 5,
    "eventbridge_bus": 5,
    "step_functions": 5,
    "codebuild_project": 5,
    "codepipeline": 5,
    "ecr_repository": 6,
    "eks_cluster": 8,
}

# ============================================================
# ENVIRONMENT MODIFIERS
# ============================================================

ENVIRONMENT_MODIFIERS: Dict[str, float] = {
    "production": 2.0,
    "staging": 1.5,
    "testing": 1.0,
    "development": 0.8,
    "sandbox": 0.5,
    "unknown": 1.0,
}

# ============================================================
# SENSITIVE DATA MODIFIERS
# ============================================================

SENSITIVE_DATA_MODIFIERS: Dict[str, float] = {
    "pii": 1.5,              # Personal Identifiable Information
    "phi": 1.5,              # Protected Health Information
    "financial": 1.5,        # Financial data
    "credit_card": 2.0,      # PCI data
    "source_code": 1.2,      # Code repositories
    "customer_data": 1.3,    # Customer data
    "unknown": 1.0,
}

# ============================================================
# RESOURCE TYPE DETECTION
# ============================================================

# Keywords to detect resource type from resource name/ARN
RESOURCE_TYPE_KEYWORDS: Dict[str, str] = {
    "trail": "cloudtrail_trail",
    "role": "iam_role",
    "user": "iam_user",
    "policy": "iam_policy",
    "security-group": "security_group",
    "vpc": "vpc",
    "bucket": "s3_bucket",
    "db": "rds_database",
    "instance": "ec2_instance",
    "key": "ec2_key_pair",
    "volume": "ec2_volume",
    "snapshot": "ec2_snapshot",
    "lambda": "lambda_function",
    "function": "lambda_function",
    "table": "dynamodb_table",
    "topic": "sns_topic",
    "queue": "sqs_queue",
    "secret": "secrets_manager_secret",
    "parameter": "parameter_store",
    "zone": "route53_hosted_zone",
}


def get_resource_type_from_name(resource_name: str) -> str:
    """
    Detect resource type from resource name or ARN.
    
    Args:
        resource_name: Resource name or ARN
        
    Returns:
        Detected resource type
    """
    resource_name_lower = resource_name.lower()
    
    for keyword, resource_type in RESOURCE_TYPE_KEYWORDS.items():
        if keyword in resource_name_lower:
            return resource_type
    
    return "unknown"


def get_resource_criticality(
    resource_type: str,
    environment: str = "unknown",
    sensitive_data_type: str = "unknown"
) -> ResourceCriticality:
    """
    Get the criticality for a resource.
    
    Args:
        resource_type: Type of resource
        environment: Environment (production, staging, etc.)
        sensitive_data_type: Type of sensitive data
        
    Returns:
        ResourceCriticality object
    """
    # Get base score
    base_score = RESOURCE_TYPE_SCORES.get(resource_type, 5)
    
    # Get environment modifier
    environment_modifier = ENVIRONMENT_MODIFIERS.get(
        environment.lower() if environment else "unknown",
        1.0
    )
    
    # Get sensitive data modifier
    sensitive_modifier = SENSITIVE_DATA_MODIFIERS.get(
        sensitive_data_type.lower() if sensitive_data_type else "unknown",
        1.0
    )
    
    # Generate reasoning
    reasoning_parts = []
    
    if base_score >= 15:
        reasoning_parts.append(f"Resource type '{resource_type}' is critical (score: {base_score})")
    elif base_score >= 8:
        reasoning_parts.append(f"Resource type '{resource_type}' is medium importance (score: {base_score})")
    else:
        reasoning_parts.append(f"Resource type '{resource_type}' is low importance (score: {base_score})")
    
    if environment != "unknown":
        reasoning_parts.append(f"Environment '{environment}' has modifier: {environment_modifier}x")
    
    if sensitive_data_type != "unknown":
        reasoning_parts.append(f"Sensitive data '{sensitive_data_type}' has modifier: {sensitive_modifier}x")
    
    return ResourceCriticality(
        base_score=base_score,
        environment_modifier=environment_modifier,
        sensitive_data_modifier=sensitive_modifier,
        reasoning="; ".join(reasoning_parts),
    )