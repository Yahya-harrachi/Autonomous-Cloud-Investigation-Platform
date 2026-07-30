"""
Identity Risk Scores
Defines how risky different identity types are.
"""
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class IdentityRisk:
    """Risk information for an identity"""
    type: str
    risk_level: str          # critical, high, medium, low
    modifier: float          # 0.5-2.0
    reasoning: str


# ============================================================
# IDENTITY TYPE RISK MODIFIERS
# ============================================================

IDENTITY_RISK_MAP: Dict[str, Dict] = {
    # ===== CRITICAL RISK (2.0x) =====
    "root": {
        "risk_level": "critical",
        "modifier": 2.0,
        "reasoning": "Root user has unrestricted access to all AWS resources"
    },
    "root_user": {
        "risk_level": "critical",
        "modifier": 2.0,
        "reasoning": "Root user has unrestricted access to all AWS resources"
    },
    
    # ===== HIGH RISK (1.8x) =====
    "administrator": {
        "risk_level": "high",
        "modifier": 1.8,
        "reasoning": "Administrator has broad permissions across the account"
    },
    "admin": {
        "risk_level": "high",
        "modifier": 1.8,
        "reasoning": "Administrator has broad permissions across the account"
    },
    
    # ===== MEDIUM-HIGH RISK (1.5x) =====
    "power_user": {
        "risk_level": "medium",
        "modifier": 1.5,
        "reasoning": "Power user can create and modify resources"
    },
    "assumed_role": {
        "risk_level": "medium",
        "modifier": 1.5,
        "reasoning": "Assumed role may have elevated permissions"
    },
    "federated_user": {
        "risk_level": "medium",
        "modifier": 1.3,
        "reasoning": "Federated user from external identity provider"
    },
    
    # ===== MEDIUM RISK (1.2x) =====
    "developer": {
        "risk_level": "medium",
        "modifier": 1.2,
        "reasoning": "Developer has permissions to modify resources"
    },
    "operator": {
        "risk_level": "medium",
        "modifier": 1.2,
        "reasoning": "Operator has operational permissions"
    },
    
    # ===== LOW RISK (0.8x) =====
    "service_account": {
        "risk_level": "low",
        "modifier": 0.8,
        "reasoning": "Service account with specific permissions"
    },
    "system": {
        "risk_level": "low",
        "modifier": 0.8,
        "reasoning": "System account with automated tasks"
    },
    "lambda": {
        "risk_level": "low",
        "modifier": 0.7,
        "reasoning": "Lambda function with specific permissions"
    },
    
    # ===== VERY LOW RISK (0.5x) =====
    "readonly": {
        "risk_level": "low",
        "modifier": 0.5,
        "reasoning": "Read-only user cannot modify resources"
    },
    "read_only": {
        "risk_level": "low",
        "modifier": 0.5,
        "reasoning": "Read-only user cannot modify resources"
    },
    "viewer": {
        "risk_level": "low",
        "modifier": 0.5,
        "reasoning": "Viewer has read-only permissions"
    },
    
    # ===== UNKNOWN (1.0x) =====
    "unknown": {
        "risk_level": "medium",
        "modifier": 1.0,
        "reasoning": "Identity type could not be determined"
    },
}


def get_identity_risk(identity_type: str, identity_name: str = "") -> IdentityRisk:
    """
    Get the risk information for an identity type.
    
    Args:
        identity_type: Type of identity (root, admin, etc.)
        identity_name: Name of the identity (for reasoning)
        
    Returns:
        IdentityRisk object
    """
    # Normalize identity type
    normalized_type = identity_type.lower().replace(" ", "_") if identity_type else "unknown"
    
    # Try exact match
    if normalized_type in IDENTITY_RISK_MAP:
        risk_info = IDENTITY_RISK_MAP[normalized_type]
        return IdentityRisk(
            type=identity_type,
            risk_level=risk_info["risk_level"],
            modifier=risk_info["modifier"],
            reasoning=f"{identity_name or identity_type}: {risk_info['reasoning']}"
        )
    
    # Try partial match
    for key, risk_info in IDENTITY_RISK_MAP.items():
        if key in normalized_type or normalized_type in key:
            return IdentityRisk(
                type=identity_type,
                risk_level=risk_info["risk_level"],
                modifier=risk_info["modifier"],
                reasoning=f"{identity_name or identity_type}: {risk_info['reasoning']}"
            )
    
    # Fallback
    return IdentityRisk(
        type=identity_type or "unknown",
        risk_level="medium",
        modifier=1.0,
        reasoning=f"Unknown identity type: {identity_type or 'unknown'}"
    )


def detect_identity_type(actor: str, actor_type: str = "", identity_type: str = "") -> str:
    """
    Detect the identity type from actor, actor_type, and identity_type.
    """
    actor_lower = actor.lower() if actor else ""
    identity_type_lower = identity_type.lower() if identity_type else ""
    
    # Check if it's root
    if actor_lower == "root" or identity_type_lower == "root":
        return "root"
    
    # Check if it's an assumed role
    if identity_type_lower == "assumedrole" or "assumed-role" in actor_lower:
        return "assumed_role"
    
    # Check if it's a service account
    if identity_type_lower == "awsservice" or "-service-" in actor_lower:
        return "service_account"
    
    # Check if it's a federated user
    if identity_type_lower == "federateduser":
        return "federated_user"
    
    # Check if it's an admin
    if "admin" in actor_lower:
        return "administrator"
    
    # Check if it's a lambda
    if "lambda" in actor_lower:
        return "lambda"
    
    # Check if it's read-only
    if "readonly" in actor_lower or "viewer" in actor_lower:
        return "readonly"
    
    # Check if it's a developer
    if "dev" in actor_lower or "developer" in actor_lower:
        return "developer"
    
    # Default to unknown
    return "unknown"