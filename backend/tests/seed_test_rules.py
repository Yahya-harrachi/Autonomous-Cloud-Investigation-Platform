"""
Seed test rules for debugging
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.infrastructure.repositories.rule_repository import RuleRepository

def seed_test_rules():
    db = SessionLocal()
    repo = RuleRepository(db)
    
    # Clear existing rules
    print("🧹 Clearing existing rules...")
    for rule in repo.get_all():
        repo.delete(str(rule.id))
    
    rules = [
        # Event Type Rule
        {
            "name": "GetCallerIdentity - Base",
            "description": "Base score for GetCallerIdentity",
            "enabled": True,
            "priority": 10,
            "rule_type": "event_type",
            "parameters": {"event_name": "GetCallerIdentity"},
            "condition": {
                "conditions": [
                    {"field": "event_name", "operator": "eq", "value": "GetCallerIdentity"}
                ],
                "logic": "and"
            },
            "base_score": 20,
            "modifier": 1.0,
        },
        # Identity Rule
        {
            "name": "IAM User - Normal",
            "description": "Normal IAM user modifier",
            "enabled": True,
            "priority": 20,
            "rule_type": "identity",
            "parameters": {"identity_type": "iamuser"},
            "condition": {
                "conditions": [
                    {"field": "identity_type", "operator": "eq", "value": "iamuser"}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 1.0,
        },
        # Context Rule - Off Hours
        {
            "name": "Testing Off Hours",
            "description": "Off-hours activity (10 PM - 6 AM)",
            "enabled": True,
            "priority": 1,
            "rule_type": "context",
            "parameters": {
                "context_type": "off_hours",
                "start_time": "22:00",
                "end_time": "06:00"
            },
            "condition": {
                "conditions": [
                    {"field": "hour", "operator": "gte", "value": 22},
                    {"field": "hour", "operator": "lt", "value": 6}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 2.0,
        },
        # Context Rule - Read Only
        {
            "name": "Read-Only - Lower Risk",
            "description": "Read-only operations have lower impact",
            "enabled": True,
            "priority": 10,
            "rule_type": "context",
            "parameters": {"context_type": "read_only"},
            "condition": {
                "conditions": [
                    {"field": "is_read_only", "operator": "eq", "value": True}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 0.7,
        },
        # Context Rule - Public IP
        {
            "name": "Public IP - Higher Risk",
            "description": "Actions from public IP addresses",
            "enabled": True,
            "priority": 10,
            "rule_type": "context",
            "parameters": {"context_type": "public_ip"},
            "condition": {
                "conditions": [
                    {"field": "actor_ip", "operator": "is_public", "value": True}
                ],
                "logic": "and"
            },
            "base_score": 0,
            "modifier": 1.3,
        },
    ]
    
    print(f"\n📊 Creating {len(rules)} test rules...")
    
    for rule_data in rules:
        try:
            rule = repo.create(rule_data)
            status = "✅" if rule.enabled else "❌"
            print(f"  {status} {rule.name} (Base: {rule.base_score}, Modifier: {rule.modifier}x)")
        except Exception as e:
            print(f"  ❌ Failed to create {rule_data['name']}: {e}")
    
    db.close()
    print("\n✅ Test rules seeded successfully!")

if __name__ == "__main__":
    seed_test_rules()