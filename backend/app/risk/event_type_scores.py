"""
Event Type Base Scores
Maps normalized event types to base risk scores (0-40).

These are the FOUNDATION of risk calculation.
All events start with a base score, then modifiers are applied.
"""
from typing import Dict, Optional

# ============================================================
# EVENT TYPE BASE SCORES (0-40)
# ============================================================

# Lower score = less risk (0-20)
# Medium score = some risk (21-30)
# Higher score = more risk (31-40)

EVENT_TYPE_BASE_SCORES: Dict[str, int] = {
    # ===== AWS CLOUDTRAIL =====
    "console_login": 15,
    "console_logout": 5,
    "assume_role": 10,
    "create_access_key": 20,
    "delete_access_key": 15,
    "create_user": 25,
    "delete_user": 20,
    "attach_user_policy": 40,
    "detach_user_policy": 30,
    "create_role": 25,
    "delete_role": 20,
    "attach_role_policy": 35,
    "detach_role_policy": 25,
    "create_group": 15,
    "delete_group": 10,
    "add_user_to_group": 20,
    "remove_user_from_group": 15,
    "create_policy": 25,
    "delete_policy": 20,
    "put_bucket_policy": 30,
    "delete_bucket_policy": 25,
    "create_bucket": 10,
    "delete_bucket": 15,
    "put_object": 5,
    "delete_object": 5,
    "run_instances": 20,
    "terminate_instances": 25,
    "stop_instances": 15,
    "start_instances": 10,
    "modify_instance_attributes": 20,
    "create_security_group": 15,
    "delete_security_group": 10,
    "authorize_security_group_ingress": 35,
    "revoke_security_group_ingress": 25,
    "create_key_pair": 10,
    "delete_key_pair": 5,
    "modify_vpc_attributes": 15,
    "delete_trail": 35,
    "update_trail": 25,
    "stop_logging": 35,
    "start_logging": 10,
    "create_vpc": 10,
    "delete_vpc": 15,
    "modify_network_interface": 20,
    "create_vpn_connection": 10,
    "delete_vpn_connection": 10,
    "create_database": 15,
    "delete_database": 20,
    "modify_database": 15,
    "create_snapshot": 10,
    "delete_snapshot": 10,
    "put_bucket_encryption": 15,
    "delete_bucket_encryption": 20,
    "put_bucket_versioning": 10,
    "delete_bucket_versioning": 15,
    "put_bucket_acl": 20,
    "delete_bucket_acl": 15,
    "put_bucket_tagging": 10,
    "delete_bucket_tagging": 10,
    
    # ===== GUARDDUTY FINDINGS =====
    "unauthorized_access": 35,
    "crypto_mining": 40,
    "port_scan": 30,
    "dos_attack": 35,
    "backdoor": 40,
    "reconnaissance": 30,
    "privilege_escalation": 40,
    "data_exfiltration": 40,
    "credential_compromise": 40,
    "suspicious_api_activity": 25,
    "unusual_traffic": 20,
    
    # ===== AZURE ACTIVITY LOGS =====
    "create_vm": 15,
    "delete_vm": 20,
    "stop_vm": 15,
    "start_vm": 10,
    "create_storage_account": 10,
    "delete_storage_account": 15,
    "create_role_assignment": 30,
    "delete_role_assignment": 25,
    "create_security_group": 15,
    "delete_security_group": 10,
    "modify_security_group": 20,
    "create_key_vault": 15,
    "delete_key_vault": 20,
    "create_virtual_network": 10,
    "delete_virtual_network": 15,
    "create_network_interface": 10,
    "delete_network_interface": 10,
    
    # ===== GCP AUDIT LOGS =====
    "compute_instances_create": 15,
    "compute_instances_delete": 20,
    "compute_instances_start": 10,
    "compute_instances_stop": 10,
    "storage_buckets_create": 10,
    "storage_buckets_delete": 15,
    "storage_buckets_update": 15,
    "iam_roles_create": 25,
    "iam_roles_delete": 20,
    "iam_roles_update": 25,
    "iam_policies_create": 25,
    "iam_policies_delete": 20,
    "iam_policies_update": 25,
    "cloudsql_instances_create": 15,
    "cloudsql_instances_delete": 20,
    "cloudsql_instances_modify": 15,
    "kubernetes_clusters_create": 15,
    "kubernetes_clusters_delete": 20,
    "kubernetes_clusters_modify": 15,
    
    # ===== GENERIC / FALLBACK =====
    "unknown": 10,
    "informational": 5,
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}

def get_base_score(event_type: str) -> int:
    """
    Get the base score for an event type.
    
    Args:
        event_type: Normalized event type
        
    Returns:
        Base score (0-40)
    """
    return EVENT_TYPE_BASE_SCORES.get(event_type, 10)


def get_base_score_with_fallback(event_type: str, fallback: int = 10) -> int:
    """
    Get the base score for an event type with a fallback value.
    
    Args:
        event_type: Normalized event type
        fallback: Score to use if event type not found
        
    Returns:
        Base score (0-40)
    """
    return EVENT_TYPE_BASE_SCORES.get(event_type, fallback)


def get_severity_from_score(score: int) -> str:
    """
    Map a base score to a severity level.
    
    Args:
        score: Base score (0-40)
        
    Returns:
        Severity string (informational, low, medium, high, critical)
    """
    if score <= 5:
        return "informational"
    elif score <= 10:
        return "low"
    elif score <= 20:
        return "medium"
    elif score <= 30:
        return "high"
    else:
        return "critical"