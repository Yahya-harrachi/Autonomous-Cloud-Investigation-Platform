"""
Risk Engine Enums
All constants used across the risk engine.
"""
from enum import Enum

class RiskLevel(str, Enum):
    """
    Risk levels used across the platform.
    Every event gets one of these.
    """
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def score_min(self) -> int:
        """Minimum risk score for each level"""
        mapping = {
            RiskLevel.INFORMATIONAL: 0,
            RiskLevel.LOW: 21,
            RiskLevel.MEDIUM: 41,
            RiskLevel.HIGH: 61,
            RiskLevel.CRITICAL: 81,
        }
        return mapping[self]
    
    @property
    def score_max(self) -> int:
        """Maximum risk score for each level"""
        mapping = {
            RiskLevel.INFORMATIONAL: 20,
            RiskLevel.LOW: 40,
            RiskLevel.MEDIUM: 60,
            RiskLevel.HIGH: 80,
            RiskLevel.CRITICAL: 100,
        }
        return mapping[self]
    
    @classmethod
    def from_score(cls, score: int) -> "RiskLevel":
        """Convert a numeric score (0-100) to RiskLevel"""
        if score <= 20:
            return cls.INFORMATIONAL
        elif score <= 40:
            return cls.LOW
        elif score <= 60:
            return cls.MEDIUM
        elif score <= 80:
            return cls.HIGH
        else:
            return cls.CRITICAL
    
    def display_name(self) -> str:
        """Human-readable name"""
        mapping = {
            RiskLevel.INFORMATIONAL: "Informational",
            RiskLevel.LOW: "Low",
            RiskLevel.MEDIUM: "Medium",
            RiskLevel.HIGH: "High",
            RiskLevel.CRITICAL: "Critical",
        }
        return mapping[self]
    
    def color(self) -> str:
        """UI color for each level"""
        mapping = {
            RiskLevel.INFORMATIONAL: "gray",
            RiskLevel.LOW: "blue",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "orange",
            RiskLevel.CRITICAL: "red",
        }
        return mapping[self]


class RuleOperator(str, Enum):
    """
    Operators used in rule conditions.
    Analysts use these when creating rules.
    """
    EQ = "eq"               # Equals
    NEQ = "neq"             # Not equals
    GT = "gt"               # Greater than
    GTE = "gte"             # Greater than or equal
    LT = "lt"               # Less than
    LTE = "lte"             # Less than or equal
    IN = "in"               # In list
    NOT_IN = "not_in"       # Not in list
    CONTAINS = "contains"   # Contains substring
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    
    def display_name(self) -> str:
        """Human-readable name for UI"""
        mapping = {
            RuleOperator.EQ: "equals",
            RuleOperator.NEQ: "does not equal",
            RuleOperator.GT: "greater than",
            RuleOperator.GTE: "greater than or equal",
            RuleOperator.LT: "less than",
            RuleOperator.LTE: "less than or equal",
            RuleOperator.IN: "in list",
            RuleOperator.NOT_IN: "not in list",
            RuleOperator.CONTAINS: "contains",
            RuleOperator.STARTS_WITH: "starts with",
            RuleOperator.ENDS_WITH: "ends with",
        }
        return mapping[self]


class RiskFactor(str, Enum):
    """
    Categories of risk factors.
    Used to group contributions in explanations.
    """
    EVENT_TYPE = "event_type"
    RESOURCE = "resource"
    IDENTITY = "identity"
    CONTEXT = "context"
    THREAT_INTEL = "threat_intel"


class DecisionAction(str, Enum):
    """
    Possible decisions from the Decision Engine.
    """
    CREATE_INCIDENT = "create_incident"
    CREATE_OBSERVATION = "create_observation"
    SUPPRESS = "suppress"
    FLAG_FOR_REVIEW = "flag_for_review"