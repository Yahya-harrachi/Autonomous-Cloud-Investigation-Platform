"""
Rule Repository - Database operations for risk rules
"""
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc
from uuid import UUID

from ...domain.models.risk_rule import RuleModel, RuleType


class RuleRepository:
    """
    Repository for risk rule operations.
    """
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def create(self, rule_data: Dict[str, Any]) -> RuleModel:
        """Create a new rule"""
        rule = RuleModel(
            name=rule_data["name"],
            description=rule_data.get("description"),
            enabled=rule_data.get("enabled", True),
            priority=rule_data.get("priority", 100),
            rule_type=RuleType(rule_data["rule_type"]),
            condition=rule_data["condition"],
            base_score=rule_data.get("base_score", 0),
            modifier=rule_data.get("modifier", 1.0),
            created_by=rule_data.get("created_by"),
        )
        self.db.add(rule)
        self.db.commit()
        self.db.refresh(rule)
        return rule
    
    def get_all(self, enabled_only: bool = False) -> List[RuleModel]:
        """Get all rules"""
        query = self.db.query(RuleModel)
        if enabled_only:
            query = query.filter(RuleModel.enabled == True)
        return query.order_by(RuleModel.priority.asc()).all()
    
    def get_by_id(self, rule_id: str) -> Optional[RuleModel]:
        """Get rule by ID"""
        try:
            return self.db.query(RuleModel).filter(RuleModel.id == UUID(rule_id)).first()
        except ValueError:
            return None
    
    def get_by_type(self, rule_type: RuleType) -> List[RuleModel]:
        """Get rules by type"""
        return self.db.query(RuleModel).filter(RuleModel.rule_type == rule_type).all()
    
    def update(self, rule_id: str, rule_data: Dict[str, Any]) -> Optional[RuleModel]:
        """Update a rule"""
        rule = self.get_by_id(rule_id)
        if not rule:
            return None
        
        if "name" in rule_data:
            rule.name = rule_data["name"]
        if "description" in rule_data:
            rule.description = rule_data["description"]
        if "enabled" in rule_data:
            rule.enabled = rule_data["enabled"]
        if "priority" in rule_data:
            rule.priority = rule_data["priority"]
        if "rule_type" in rule_data:
            rule.rule_type = RuleType(rule_data["rule_type"])
        if "condition" in rule_data:
            rule.condition = rule_data["condition"]
        if "base_score" in rule_data:
            rule.base_score = rule_data["base_score"]
        if "modifier" in rule_data:
            rule.modifier = rule_data["modifier"]
        
        self.db.commit()
        self.db.refresh(rule)
        return rule
    
    def delete(self, rule_id: str) -> bool:
        """Delete a rule"""
        rule = self.get_by_id(rule_id)
        if not rule:
            return False
        
        self.db.delete(rule)
        self.db.commit()
        return True
    
    def enable(self, rule_id: str) -> Optional[RuleModel]:
        """Enable a rule"""
        rule = self.get_by_id(rule_id)
        if not rule:
            return None
        rule.enabled = True
        self.db.commit()
        self.db.refresh(rule)
        return rule
    
    def disable(self, rule_id: str) -> Optional[RuleModel]:
        """Disable a rule"""
        rule = self.get_by_id(rule_id)
        if not rule:
            return None
        rule.enabled = False
        self.db.commit()
        self.db.refresh(rule)
        return rule