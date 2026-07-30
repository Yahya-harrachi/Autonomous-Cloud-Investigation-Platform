"""
Resource Risk Calculator
Calculates the risk contribution from the resource.
"""
from typing import Dict, Any, Optional
from ..enums import RiskFactor
from ..models import RiskContribution
from ..resource_criticality import (
    get_resource_criticality,
    get_resource_type_from_name,
)


class ResourceCalculator:
    """
    Calculates risk contribution from the resource.
    
    Factors considered:
    - Resource type (critical vs non-critical)
    - Environment (production vs development)
    - Sensitive data (PII, PHI, etc.)
    """
    
    def __init__(self):
        """Initialize the resource calculator."""
        pass
    
    def calculate(self, event_data: Dict[str, Any]) -> Optional[RiskContribution]:
        """
        Calculate the risk contribution from the resource.
        
        Args:
            event_data: Normalized event data
            
        Returns:
            RiskContribution with score and reasoning
        """
        # Extract resource information
        resource = event_data.get("resource", "unknown")
        resource_type = event_data.get("resource_type")
        
        # If no resource type, try to detect from resource name
        if not resource_type or resource_type == "unknown":
            resource_type = get_resource_type_from_name(resource)
        
        # Extract environment and sensitive data from metadata
        metadata = event_data.get("metadata", {})
        environment = metadata.get("environment", "unknown")
        sensitive_data_type = metadata.get("sensitive_data_type", "unknown")
        
        # Get criticality
        criticality = get_resource_criticality(
            resource_type=resource_type,
            environment=environment,
            sensitive_data_type=sensitive_data_type,
        )
        
        # Calculate contribution
        # Base score (0-20) multiplied by modifiers
        contribution = int(
            criticality.base_score
            * criticality.environment_modifier
            * criticality.sensitive_data_modifier
        )
        
        # Clamp to 0-20
        contribution = max(0, min(20, contribution))
        
        # Generate description
        description = f"Resource: {resource} ({resource_type})"
        
        # Generate reasoning
        reasoning = criticality.reasoning
        
        return RiskContribution(
            factor=RiskFactor.RESOURCE,
            description=description,
            base_score=criticality.base_score,
            modifier=criticality.environment_modifier * criticality.sensitive_data_modifier,
            contribution=contribution,
            reasoning=reasoning,
        )