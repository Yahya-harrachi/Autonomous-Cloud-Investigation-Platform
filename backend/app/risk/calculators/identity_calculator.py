"""
Identity Risk Calculator
Calculates the risk contribution from the identity (who performed the action).
"""
from typing import Dict, Any, Optional
from ..enums import RiskFactor
from ..models import RiskContribution
from ..identity_risk import get_identity_risk, detect_identity_type


class IdentityCalculator:
    """
    Calculates risk contribution from the identity.
    
    Factors considered:
    - Identity type (root, admin, service account, etc.)
    - Identity name (for reasoning)
    """
    
    def __init__(self):
        """Initialize the identity calculator."""
        pass
    
    def calculate(self, event_data: Dict[str, Any]) -> Optional[RiskContribution]:
        """
        Calculate the risk contribution from the identity.
        
        Args:
            event_data: Normalized event data
            
        Returns:
            RiskContribution with score and reasoning
        """
        # Extract identity information
        actor = event_data.get("actor", "unknown")
        actor_type = event_data.get("actor_type", "unknown")
        
        # Detect identity type
        identity_type = detect_identity_type(actor, actor_type)
        
        # Get identity risk
        identity_risk = get_identity_risk(identity_type, actor)
        
        # Calculate contribution (base 20, multiplied by modifier)
        base_score = 20  # Base for identity
        contribution = int(base_score * identity_risk.modifier)
        
        # Clamp to 0-20
        contribution = max(0, min(20, contribution))
        
        # Generate description
        description = f"Identity: {actor} ({identity_type})"
        
        # Generate reasoning
        reasoning = identity_risk.reasoning
        
        return RiskContribution(
            factor=RiskFactor.IDENTITY,
            description=description,
            base_score=base_score,
            modifier=identity_risk.modifier,
            contribution=contribution,
            reasoning=reasoning,
        )