"""
Rule Service - Unified Rule Evaluation
ALL rules are evaluated together, regardless of type
"""
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from ...infrastructure.repositories.rule_repository import RuleRepository
from ...domain.models.risk_rule import RuleModel, RuleType
from .rule_evaluator import RuleEvaluator

logger = logging.getLogger(__name__)


class RuleService:
    """Unified rule service - ALL rules evaluated together"""
    
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.repository = RuleRepository(db_session)
        self.evaluator = RuleEvaluator()
    
    def evaluate_all_rules(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate ALL enabled rules against an event.
        Returns aggregated results with ALL matching rules.
        """
        # 1. Get ALL enabled rules
        all_rules = self.repository.get_all(enabled_only=True)
        
        if not all_rules:
            logger.warning("No rules found in database")
            return {
                "base_score": 0,
                "modifier": 1.0,
                "rules_applied": [],
                "rule_details": [],
                "total_effective_score": 0,
            }
        
        # 2. Evaluate each rule
        matched_rules = []
        
        for rule in all_rules:
            result = self.evaluator.evaluate_rule_result(rule, event_data)
            if result:
                matched_rules.append(result)
                logger.info(f"✅ Rule matched: {rule.name} (type: {rule.rule_type})")
            else:
                logger.debug(f"❌ Rule not matched: {rule.name}")
        
        # 3. Aggregate results
        return self._aggregate_rule_results(matched_rules, event_data)
    
    def _aggregate_rule_results(self, matched_rules: List[Dict], event_data: Dict) -> Dict[str, Any]:
        """
        Aggregate results from ALL matched rules.
        
        Rules are processed by priority:
        - Event Type: Highest base_score wins (priority)
        - Identity: All modifiers are multiplied
        - Context: All modifiers are multiplied
        - Threat Intel: All modifiers are multiplied
        """
        if not matched_rules:
            return {
                "base_score": 0,
                "modifier": 1.0,
                "rules_applied": [],
                "rule_details": [],
                "total_effective_score": 0,
            }
        
        # Sort by priority (lower number = higher priority)
        matched_rules.sort(key=lambda x: x.get('priority', 100))
        
        base_score = 0
        modifier = 1.0
        applied_rules = []
        
        for rule_result in matched_rules:
            rule_type = rule_result.get('rule_type', 'unknown')
            rule_name = rule_result.get('rule_name', 'unknown')
            rule_base = rule_result.get('base_score', 0)
            rule_modifier = rule_result.get('modifier', 1.0)
            
            applied_rules.append(rule_name)
            
            # Event Type: Take the highest base_score
            if rule_type == 'event_type':
                if rule_base > base_score:
                    base_score = rule_base
                    logger.debug(f"Event type rule '{rule_name}' set base_score to {base_score}")
            
            # Identity: Multiply modifier
            elif rule_type == 'identity':
                modifier *= rule_modifier
                logger.debug(f"Identity rule '{rule_name}' applied modifier: {rule_modifier}x")
            
            # Context: Multiply modifier
            elif rule_type == 'context':
                modifier *= rule_modifier
                logger.debug(f"Context rule '{rule_name}' applied modifier: {rule_modifier}x")
            
            # Threat Intel: Multiply modifier
            elif rule_type == 'threat_intel':
                modifier *= rule_modifier
                logger.debug(f"Threat Intel rule '{rule_name}' applied modifier: {rule_modifier}x")
            
            # Custom: Use both base_score and modifier
            elif rule_type == 'custom':
                if rule_base > base_score:
                    base_score = rule_base
                modifier *= rule_modifier
                logger.debug(f"Custom rule '{rule_name}' applied base: {rule_base}, modifier: {rule_modifier}x")
        
        # Calculate final score
        final_score = int(base_score * modifier)
        final_score = max(0, min(100, final_score))
        
        logger.info(f"Final score: {final_score} (base: {base_score}, modifier: {modifier:.1f}x)")
        
        return {
            "base_score": base_score,
            "modifier": modifier,
            "rules_applied": applied_rules,
            "rule_details": matched_rules,
            "total_effective_score": final_score,
        }
    
    def get_event_type_score(self, event_name: str) -> Optional[Dict[str, Any]]:
        """Get base score for an event type (backward compatibility)"""
        rules = self.repository.get_by_type(RuleType.EVENT_TYPE)
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            condition = rule.condition
            conditions = condition.get("conditions", [])
            
            for cond in conditions:
                if cond.get("field") == "event_name" and cond.get("operator") == "eq":
                    if cond.get("value", "").lower() == event_name.lower():
                        return {
                            "rule_id": str(rule.id),
                            "rule_name": rule.name,
                            "base_score": rule.base_score,
                            "modifier": rule.modifier,
                            "priority": rule.priority,
                        }
        
        return None
    
    def get_identity_modifier(self, identity_type: str) -> Optional[float]:
        """Get identity modifier (backward compatibility)"""
        rules = self.repository.get_by_type(RuleType.IDENTITY)
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            condition = rule.condition
            conditions = condition.get("conditions", [])
            
            for cond in conditions:
                if cond.get("field") == "identity_type" and cond.get("operator") == "eq":
                    if cond.get("value", "") == identity_type:
                        return rule.modifier
        
        return None
    
    def get_context_modifiers(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get context modifiers (backward compatibility)"""
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
                    "base_score": rule.base_score,
                })
        
        return sorted(applicable, key=lambda x: x.get("priority", 100))