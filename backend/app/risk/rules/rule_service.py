"""
Rule Service - Applies rules to severity calculation
"""
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from ...infrastructure.repositories.rule_repository import RuleRepository
from ...domain.models.risk_rule import RuleModel
from .rule_evaluator import RuleEvaluator

logger = logging.getLogger(__name__)


class RuleService:
    """
    Service for applying rules to severity calculation.
    """
    
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.repository = RuleRepository(db_session)
        self.evaluator = RuleEvaluator()
        self._rules_cache = None
    
    def get_applicable_rules(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get all rules that apply to an event.
        Returns a list of rule results with their scores.
        """
        # Get all enabled rules
        rules = self.repository.get_all(enabled_only=True)
        
        if not rules:
            return []
        
        applicable_rules = []
        
        for rule in rules:
            result = self.evaluator.evaluate_rule_result(rule, event_data)
            if result:
                applicable_rules.append(result)
        
        # Sort by priority (lower priority number = higher priority)
        # Rules with higher priority are applied first
        applicable_rules.sort(key=lambda x: rules[[r.id for r in rules].index(x['rule_id'])].priority)
        
        return applicable_rules
    
    def get_event_type_score(self, event_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the base score and modifier for an event type from rules.
        """
        # Get all event_type rules
        from ...domain.models.risk_rule import RuleType
        rules = self.repository.get_by_type(RuleType.EVENT_TYPE)
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            condition = rule.condition
            conditions = condition.get("conditions", [])
            
            # Check if this rule is for the specific event_name
            for cond in conditions:
                if cond.get("field") == "event_name" and cond.get("operator") == "eq":
                    if cond.get("value") == event_name:
                        return {
                            "rule_id": str(rule.id),
                            "rule_name": rule.name,
                            "base_score": rule.base_score,
                            "modifier": rule.modifier,
                            "priority": rule.priority,
                        }
        
        return None
    
    def get_identity_modifier(self, identity_type: str) -> Optional[float]:
        """
        Get the identity modifier from rules.
        """
        from ...domain.models.risk_rule import RuleType
        rules = self.repository.get_by_type(RuleType.IDENTITY)
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            condition = rule.condition
            conditions = condition.get("conditions", [])
            
            # Check if this rule is for the specific identity_type
            for cond in conditions:
                if cond.get("field") == "identity_type" and cond.get("operator") == "eq":
                    if cond.get("value") == identity_type:
                        return rule.modifier
        
        return None
    
    def get_context_modifiers(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get all context modifiers that apply to an event.
        """
        from ...domain.models.risk_rule import RuleType
        rules = self.repository.get_by_type(RuleType.CONTEXT)
        
        applicable = []
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            result = self.evaluator.evaluate_rule_result(rule, event_data)
            if result:
                applicable.append({
                    "rule_id": str(rule.id),
                    "rule_name": rule.name,
                    "modifier": rule.modifier,
                    "priority": rule.priority,
                })
        
        return sorted(applicable, key=lambda x: x.get("priority", 100))