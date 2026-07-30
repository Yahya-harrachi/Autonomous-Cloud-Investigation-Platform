"""
Seed rules for testing the rule engine
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.infrastructure.repositories.rule_repository import RuleRepository


def seed_rules():
    """Seed default rules"""
    db = SessionLocal()
    repo = RuleRepository(db)
    
    # Clear existing rules
    for rule in repo.get_all():
        repo.delete(str(rule.id))
    
    rules = [
        {
            "name": "DeleteTrail Critical",
            "description": "CloudTrail deletion is a critical security event",
            "enabled": True,
            "priority": 1,
            "rule_type": "event_type",
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "DeleteTrail"}
                ],
                "logic": "and"
            },
            "base_score": 40,
            "modifier": 1.5,
        },
        {
            "name": "ConsoleLogin Detection",
            "description": "Console login events",
            "enabled": True,
            "priority": 2,
            "rule_type": "event_type",
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "ConsoleLogin"}
                ],
                "logic": "and"
            },
            "base_score": 20,
            "modifier": 1.0,
        },
        {
            "name": "AssumeRole Detection",
            "description": "Role assumption events",
            "enabled": True,
            "priority": 3,
            "rule_type": "event_type",
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "AssumeRole"}
                ],
                "logic": "and"
            },
            "base_score": 15,
            "modifier": 1.0,
        },
        {
            "name": "Root User Modifier",
            "description": "Root user actions are higher risk",
            "enabled": True,
            "priority": 1,
            "rule_type": "identity",
            "condition": {
                "conditions": [
                    {"field": "identity_type", "operator": "eq", "value": "root"}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 2.0,
        },
        {
            "name": "Service Account Modifier",
            "description": "Service account actions are lower risk",
            "enabled": True,
            "priority": 2,
            "rule_type": "identity",
            "condition": {
                "conditions": [
                    {"field": "identity_type", "operator": "eq", "value": "service_account"}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 0.8,
        },
        {
            "name": "Off-Hours Modifier",
            "description": "Actions during off-hours are higher risk",
            "enabled": True,
            "priority": 1,
            "rule_type": "context",
            "condition": {
                "conditions": [
                    {"field": "hour", "operator": "lt", "value": 6}
                ],
                "logic": "or"
            },
            "base_score": 0,
            "modifier": 1.5,
        },
    ]
    
    for rule_data in rules:
        rule = repo.create(rule_data)
        print(f"✅ Created rule: {rule.name}")
    
    db.close()
    print("\n✅ All rules seeded!")


if __name__ == "__main__":
    seed_rules()