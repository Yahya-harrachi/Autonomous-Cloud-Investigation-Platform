"""
Event Type Calculator
Calculates the base risk contribution from the event type.
"""
from typing import Dict, Any
from ..enums import RiskFactor
from ..models import RiskContribution
from ..event_type_scores import get_base_score


class EventTypeCalculator:
    """
    Calculates risk contribution from the event type.
    
    This is the FIRST factor in risk calculation.
    Every event gets a base score based on what action occurred.
    """
    
    def __init__(self, custom_scores: Dict[str, int] = None):
        """
        Initialize the calculator.
        
        Args:
            custom_scores: Optional custom event type scores (overrides defaults)
        """
        self.custom_scores = custom_scores or {}
    
    def calculate(self, event_data: Dict[str, Any]) -> RiskContribution:
        """
        Calculate the risk contribution from the event type.
        
        Args:
            event_data: Normalized event data
            
        Returns:
            RiskContribution with score and reasoning
        """
        # Extract event type
        event_type = event_data.get("event_type", "unknown")
        event_name = event_data.get("event_name", event_type)
        
        # Get base score (custom or default)
        base_score = self.custom_scores.get(event_type)
        if base_score is None:
            from ..event_type_scores import get_base_score
            base_score = get_base_score(event_type)
        
        # Generate description and reasoning
        description = f"{event_name} ({event_type})"
        reasoning = self._get_reasoning(event_type, base_score)
        
        return RiskContribution(
            factor=RiskFactor.EVENT_TYPE,
            description=description,
            base_score=base_score,
            modifier=1.0,  # No modifier for event type (base score already 0-40)
            contribution=base_score,
            reasoning=reasoning,
        )
    
    def _get_reasoning(self, event_type: str, score: int) -> str:
        """
        Generate reasoning for the contribution.
        """
        # Get severity from score
        from ..event_type_scores import get_severity_from_score
        severity = get_severity_from_score(score)
        
        # Common reasoning templates
        high_risk_events = {
            "delete_trail": "Deleting CloudTrail trails is a critical security event that can disable auditing.",
            "stop_logging": "Stopping CloudTrail logging disables security monitoring.",
            "attach_user_policy": "Attaching policies to users can grant excessive permissions.",
            "attach_role_policy": "Attaching policies to roles can grant excessive permissions.",
            "authorize_security_group_ingress": "Opening security groups to the internet increases attack surface.",
            "create_user": "Creating new users without proper review can lead to privilege creep.",
            "put_bucket_policy": "Modifying bucket policies can expose sensitive data.",
        }
        
        if event_type in high_risk_events:
            return high_risk_events[event_type]
        elif score >= 30:
            return f"Event type '{event_type}' has high base risk ({score}/40)."
        elif score >= 20:
            return f"Event type '{event_type}' has medium base risk ({score}/40)."
        elif score >= 10:
            return f"Event type '{event_type}' has low base risk ({score}/40)."
        else:
            return f"Event type '{event_type}' has minimal base risk ({score}/40)."