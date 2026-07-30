"""
Rule Evaluation Engine - Evaluates rules against events
"""
import logging
from typing import Dict, Any, List, Optional
from ...domain.models.risk_rule import RuleModel
from ...schemas.rule import RuleCondition

logger = logging.getLogger(__name__)


class RuleEvaluator:
    """
    Evaluates rules against normalized events.
    """
    
    def __init__(self):
        self.operators = {
            "eq": self._eq,
            "neq": self._neq,
            "gt": self._gt,
            "lt": self._lt,
            "gte": self._gte,
            "lte": self._lte,
            "contains": self._contains,
            "starts_with": self._starts_with,
            "ends_with": self._ends_with,
            "in": self._in_list,
            "not_in": self._not_in_list,
        }
    
    def evaluate_rule(self, rule: RuleModel, event_data: Dict[str, Any]) -> bool:
        """
        Evaluate a rule against event data.
        
        Returns:
            True if rule matches, False otherwise
        """
        if not rule.enabled:
            return False
        
        condition = rule.condition
        conditions = condition.get("conditions", [])
        logic = condition.get("logic", "and")  # 'and' or 'or'
        
        results = []
        for cond in conditions:
            field = cond.get("field")
            operator = cond.get("operator")
            value = cond.get("value")
            
            # Get the actual value from event data
            event_value = self._get_nested_value(event_data, field)
            
            # Evaluate the condition
            result = self.operators.get(operator, self._eq)(event_value, value)
            results.append(result)
        
        if logic == "or":
            return any(results)
        else:
            return all(results)
    
    def evaluate_rule_result(self, rule: RuleModel, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate rule and return detailed result.
        """
        if not rule.enabled:
            return None
        
        condition = rule.condition
        conditions = condition.get("conditions", [])
        logic = condition.get("logic", "and")
        
        matched_conditions = []
        results = []
        
        for cond in conditions:
            field = cond.get("field")
            operator = cond.get("operator")
            value = cond.get("value")
            
            event_value = self._get_nested_value(event_data, field)
            result = self.operators.get(operator, self._eq)(event_value, value)
            
            if result:
                matched_conditions.append({
                    "field": field,
                    "operator": operator,
                    "value": value,
                    "event_value": event_value,
                })
            results.append(result)
        
        matches = any(results) if logic == "or" else all(results)
        
        if not matches:
            return None
        
        # ✅ FIX: Handle rule_type as string or enum
        rule_type_value = rule.rule_type
        if hasattr(rule_type_value, 'value'):
            rule_type_value = rule_type_value.value
        
        return {
            "matches": True,
            "rule_id": str(rule.id),
            "rule_name": rule.name,
            "rule_type": rule_type_value,
            "base_score": rule.base_score,
            "modifier": rule.modifier,
            "effective_score": int(rule.base_score * rule.modifier),
            "matched_conditions": matched_conditions,
            "logic": logic,
        }
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
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
    
    # ===== OPERATORS =====
    
    def _eq(self, event_value: Any, rule_value: Any) -> bool:
        return event_value == rule_value
    
    def _neq(self, event_value: Any, rule_value: Any) -> bool:
        return event_value != rule_value
    
    def _gt(self, event_value: Any, rule_value: Any) -> bool:
        try:
            return float(event_value) > float(rule_value)
        except (TypeError, ValueError):
            return False
    
    def _lt(self, event_value: Any, rule_value: Any) -> bool:
        try:
            return float(event_value) < float(rule_value)
        except (TypeError, ValueError):
            return False
    
    def _gte(self, event_value: Any, rule_value: Any) -> bool:
        try:
            return float(event_value) >= float(rule_value)
        except (TypeError, ValueError):
            return False
    
    def _lte(self, event_value: Any, rule_value: Any) -> bool:
        try:
            return float(event_value) <= float(rule_value)
        except (TypeError, ValueError):
            return False
    
    def _contains(self, event_value: Any, rule_value: Any) -> bool:
        return str(rule_value) in str(event_value)
    
    def _starts_with(self, event_value: Any, rule_value: Any) -> bool:
        return str(event_value).startswith(str(rule_value))
    
    def _ends_with(self, event_value: Any, rule_value: Any) -> bool:
        return str(event_value).endswith(str(rule_value))
    
    def _in_list(self, event_value: Any, rule_value: list) -> bool:
        return event_value in rule_value
    
    def _not_in_list(self, event_value: Any, rule_value: list) -> bool:
        return event_value not in rule_value