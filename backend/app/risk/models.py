"""
Risk Engine Models
Data structures used across the risk engine.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from .enums import RiskLevel, RiskFactor, DecisionAction, RuleOperator

# ============================================================
# RISK ASSESSMENT MODELS
# ============================================================

@dataclass
class RiskContribution:
    """
    Single factor's contribution to the total risk score.
    Used to build explanations.
    
    Example:
    RiskContribution(
        factor=RiskFactor.EVENT_TYPE,
        description="DeleteTrail API call",
        base_score=35,
        modifier=1.5,
        contribution=53,
        reasoning="CloudTrail deletion is a critical security event"
    )
    """
    factor: RiskFactor                    # Which category (event_type, resource, etc.)
    description: str                      # Human readable description
    base_score: int                       # Base score before modifier (0-100)
    modifier: float                       # Multiplier (0.5-2.0)
    contribution: int                     # Final contribution (base_score * modifier)
    reasoning: str                        # Why this factor contributed
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "factor": self.factor.value,
            "description": self.description,
            "base_score": self.base_score,
            "modifier": self.modifier,
            "contribution": self.contribution,
            "reasoning": self.reasoning,
        }


@dataclass
class RiskAssessment:
    """
    Complete risk assessment for a single event.
    This is the primary output of the Risk Engine.
    """
    event_id: str                         # ID of the event being assessed
    risk_score: int                       # 0-100
    risk_level: RiskLevel
    contributions: List[RiskContribution] = field(default_factory=list)
    rules_applied: List[str] = field(default_factory=list)   # Rule IDs that triggered
    threat_intel_data: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def summary(self) -> str:
        """Short summary of the assessment"""
        return f"Risk Score: {self.risk_score}/100 - {self.risk_level.display_name()}"
    
    @property
    def total_contributions(self) -> int:
        """Sum of all contributions (should equal risk_score)"""
        return sum(c.contribution for c in self.contributions)
    
    def get_reasoning(self) -> str:
        """Generate human-readable reasoning"""
        parts = []
        parts.append(f"Risk Score: {self.risk_score}/100")
        parts.append(f"Severity: {self.risk_level.display_name()}")
        parts.append("")
        parts.append("Contributions:")
        for c in self.contributions:
            sign = "+" if c.contribution > 0 else ""
            parts.append(f"  {sign}{c.contribution}: {c.description}")
            parts.append(f"    -> {c.reasoning}")
        
        if self.rules_applied:
            parts.append("")
            parts.append("Rules Applied:")
            for rule in self.rules_applied:
                parts.append(f"  - {rule}")
        
        return "\n".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "event_id": self.event_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "risk_level_display": self.risk_level.display_name(),
            "contributions": [c.to_dict() for c in self.contributions],
            "rules_applied": self.rules_applied,
            "threat_intel_data": self.threat_intel_data,
            "created_at": self.created_at.isoformat(),
            "reasoning": self.get_reasoning(),
        }


# ============================================================
# RULE MODELS
# ============================================================

@dataclass
class RuleCondition:
    """
    Single condition in a rule.
    Combined with other conditions using AND logic.
    """
    field: str                           # "event_type", "actor", "resource_type"
    operator: RuleOperator
    value: Any                           # The value to compare against
    
    def evaluate(self, event_data: Dict[str, Any]) -> bool:
        """
        Evaluate this condition against event data.
        
        Args:
            event_data: Dictionary of event fields
            
        Returns:
            True if condition matches, False otherwise
        """
        # Get the value from the event
        event_value = self._get_nested_value(event_data, self.field)
        
        # Compare based on operator
        if self.operator == RuleOperator.EQ:
            return event_value == self.value
        elif self.operator == RuleOperator.NEQ:
            return event_value != self.value
        elif self.operator == RuleOperator.GT:
            return event_value > self.value
        elif self.operator == RuleOperator.GTE:
            return event_value >= self.value
        elif self.operator == RuleOperator.LT:
            return event_value < self.value
        elif self.operator == RuleOperator.LTE:
            return event_value <= self.value
        elif self.operator == RuleOperator.IN:
            return event_value in self.value
        elif self.operator == RuleOperator.NOT_IN:
            return event_value not in self.value
        elif self.operator == RuleOperator.CONTAINS:
            return self.value in str(event_value)
        elif self.operator == RuleOperator.STARTS_WITH:
            return str(event_value).startswith(self.value)
        elif self.operator == RuleOperator.ENDS_WITH:
            return str(event_value).endswith(self.value)
        else:
            return False
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """
        Get a nested value using dot notation.
        
        Example: "user_identity.user_name" → data["user_identity"]["user_name"]
        """
        if not path:
            return data
        
        keys = path.split(".")
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        
        return value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API/UI"""
        return {
            "field": self.field,
            "operator": self.operator.value,
            "operator_display": self.operator.display_name(),
            "value": self.value,
        }


@dataclass
class Rule:
    """
    Configurable risk rule.
    SOC analysts create and modify these via UI.
    """
    id: str
    name: str
    description: str
    enabled: bool
    priority: int                        # 1 = highest, higher number = lower priority
    conditions: List[RuleCondition]
    base_score: int                      # 0-100
    weight_modifier: float               # 0.5-2.0
    criticality_factor: float            # 0.5-2.0
    threat_intel_weight: float           # 0-1
    tags: List[str] = field(default_factory=list)
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: int = 1
    
    def evaluate(self, event_data: Dict[str, Any]) -> Optional["RuleResult"]:
        """
        Evaluate this rule against an event.
        
        Returns:
            RuleResult if all conditions match, None otherwise
        """
        if not self.enabled:
            return None
        
        # Check all conditions
        matched_conditions = []
        all_match = True
        
        for condition in self.conditions:
            if condition.evaluate(event_data):
                matched_conditions.append(condition.field)
            else:
                all_match = False
                break
        
        if all_match and matched_conditions:
            return RuleResult(
                rule_id=self.id,
                rule_name=self.name,
                base_score=self.base_score,
                weight_modifier=self.weight_modifier,
                criticality_factor=self.criticality_factor,
                threat_intel_weight=self.threat_intel_weight,
                matched_conditions=matched_conditions,
                priority=self.priority,
            )
        
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API/UI"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "conditions": [c.to_dict() for c in self.conditions],
            "base_score": self.base_score,
            "weight_modifier": self.weight_modifier,
            "criticality_factor": self.criticality_factor,
            "threat_intel_weight": self.threat_intel_weight,
            "tags": self.tags,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
        }


@dataclass
class RuleResult:
    """
    Result of a rule evaluation.
    Used by the Risk Engine to calculate contributions.
    """
    rule_id: str
    rule_name: str
    base_score: int
    weight_modifier: float
    criticality_factor: float
    threat_intel_weight: float
    matched_conditions: List[str]
    priority: int = 100
    
    @property
    def effective_score(self) -> int:
        """Calculate effective score with modifiers"""
        return int(self.base_score * self.weight_modifier)


# ============================================================
# DECISION MODELS
# ============================================================

@dataclass
class DecisionResult:
    """
    Result of the Decision Engine.
    Determines what happens to the event.
    """
    action: DecisionAction
    reasons: List[str] = field(default_factory=list)
    incident_data: Optional[Dict[str, Any]] = None
    observation_data: Optional[Dict[str, Any]] = None
    required_review: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def summary(self) -> str:
        """Short summary of the decision"""
        return f"Action: {self.action.value} - {', '.join(self.reasons[:2])}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "action": self.action.value,
            "reasons": self.reasons,
            "incident_data": self.incident_data,
            "observation_data": self.observation_data,
            "required_review": self.required_review,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class RiskPolicy:
    """
    Configurable policy for the Decision Engine.
    SOC analysts configure these via UI.
    """
    id: str
    name: str
    description: str
    enabled: bool
    
    # Thresholds
    incident_threshold: int = 70          # Risk score >= this → incident
    high_severity_threshold: int = 80
    medium_severity_threshold: int = 50
    low_severity_threshold: int = 20
    
    # Threat intelligence thresholds
    threat_intel_confidence_threshold: int = 90  # 0-100
    
    # Other flags
    require_analyst_review: bool = True
    require_analyst_review_threshold: int = 60   # Risk score >= this → review
    
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def should_create_incident(self, assessment: RiskAssessment) -> bool:
        """Check if assessment meets incident creation criteria"""
        reasons = []
        
        # Check 1: Risk score threshold
        if assessment.risk_score >= self.incident_threshold:
            reasons.append(f"Risk score ({assessment.risk_score}) >= threshold ({self.incident_threshold})")
        
        # Check 2: Severity threshold
        if assessment.risk_level == RiskLevel.CRITICAL or assessment.risk_level == RiskLevel.HIGH:
            reasons.append(f"Severity is {assessment.risk_level.display_name()}")
        
        # Check 3: Threat intelligence
        if assessment.threat_intel_data:
            confidence = assessment.threat_intel_data.get("confidence_score", 0)
            if confidence >= self.threat_intel_confidence_threshold:
                reasons.append(f"Threat intelligence confidence ({confidence}%) >= threshold")
        
        return len(reasons) > 0, reasons
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API/UI"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "incident_threshold": self.incident_threshold,
            "high_severity_threshold": self.high_severity_threshold,
            "medium_severity_threshold": self.medium_severity_threshold,
            "low_severity_threshold": self.low_severity_threshold,
            "threat_intel_confidence_threshold": self.threat_intel_confidence_threshold,
            "require_analyst_review": self.require_analyst_review,
            "require_analyst_review_threshold": self.require_analyst_review_threshold,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }