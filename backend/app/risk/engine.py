"""
Risk Engine - Main Orchestrator
Coordinates all calculators and produces the final RiskAssessment.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from .enums import RiskLevel
from .models import RiskAssessment, RiskContribution
from .calculators.event_type_calculator import EventTypeCalculator
from .calculators.resource_calculator import ResourceCalculator
from .calculators.identity_calculator import IdentityCalculator  # 


class RiskEngine:
    """
    Main Risk Engine orchestrator.
    
    Responsibilities:
    1. Run all calculators
    2. Aggregate contributions
    3. Generate RiskAssessment
    4. Provide reasoning
    """
    
    def __init__(self):
        """Initialize the risk engine with all calculators."""
        self.event_type_calculator = EventTypeCalculator()
        self.resource_calculator = ResourceCalculator()
        self.identity_calculator = IdentityCalculator()  # 
        
        # Future calculators
        # self.context_calculator = ContextCalculator()
        # self.threat_intel_calculator = ThreatIntelCalculator()
    
    def assess_event(self, event_data: Dict[str, Any], event_id: Optional[str] = None) -> RiskAssessment:
        """
        Assess the risk of a single event.
        
        Args:
            event_data: Normalized event data
            event_id: Optional event ID (generated if not provided)
            
        Returns:
            RiskAssessment with full details
        """
        # Generate event ID if not provided
        if event_id is None:
            event_id = event_data.get("event_id", f"evt-{uuid.uuid4().hex[:12]}")
        
        # Collect contributions from all calculators
        contributions = []
        rules_applied = []
        
        # 1. Event Type Calculator
        contribution = self.event_type_calculator.calculate(event_data)
        contributions.append(contribution)
        
        # 2. Resource Calculator
        resource_contribution = self.resource_calculator.calculate(event_data)
        if resource_contribution:
            contributions.append(resource_contribution)
        
        # 3. Identity Calculator 
        identity_contribution = self.identity_calculator.calculate(event_data)
        if identity_contribution:
            contributions.append(identity_contribution)
        
        # 4. Future calculators will be added here
        # if self.context_calculator:
        #     contribution = self.context_calculator.calculate(event_data)
        #     contributions.append(contribution)
        
        # 5. Calculate final risk score (sum of contributions)
        total_score = sum(c.contribution for c in contributions)
        
        # Clamp to 0-100
        total_score = max(0, min(100, total_score))
        
        # Determine risk level
        risk_level = RiskLevel.from_score(total_score)
        
        # Build the assessment
        assessment = RiskAssessment(
            event_id=event_id,
            risk_score=total_score,
            risk_level=risk_level,
            contributions=contributions,
            rules_applied=rules_applied,
            threat_intel_data=None,
            created_at=datetime.utcnow(),
        )
        
        return assessment
    
    def assess_multiple_events(self, events: List[Dict[str, Any]]) -> List[RiskAssessment]:
        """
        Assess the risk of multiple events.
        
        Args:
            events: List of normalized event data
            
        Returns:
            List of RiskAssessment objects
        """
        return [self.assess_event(event) for event in events]
    
    def get_score_summary(self, assessment: RiskAssessment) -> Dict[str, Any]:
        """
        Get a brief summary of the assessment.
        
        Args:
            assessment: RiskAssessment object
            
        Returns:
            Summary dictionary
        """
        return {
            "event_id": assessment.event_id,
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level.value,
            "severity": assessment.risk_level.display_name(),
            "contributions": len(assessment.contributions),
            "total_contributions": assessment.total_contributions,
            "created_at": assessment.created_at.isoformat(),
        }