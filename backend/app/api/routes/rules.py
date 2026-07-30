"""
Rule Management API Routes
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from ...core.database import get_db
from ...infrastructure.repositories.rule_repository import RuleRepository
from ...domain.models.risk_rule import RuleType
from ...schemas.rule import (
    RuleCreate,
    RuleUpdate,
    RuleResponse,
    RuleTestRequest,
    RuleTestResponse,
)
from ...risk.rules.rule_evaluator import RuleEvaluator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rules", tags=["rules"])


# ================================================================
# CRUD ENDPOINTS
# ================================================================

@router.post("/", response_model=RuleResponse)
def create_rule(
    rule_data: RuleCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new risk rule.
    
    Example condition:
    {
        "conditions": [
            {"field": "event_name", "operator": "eq", "value": "DeleteTrail"},
            {"field": "identity_type", "operator": "eq", "value": "root"}
        ],
        "logic": "and"
    }
    """
    repo = RuleRepository(db)
    
    # Validate rule type
    try:
        RuleType(rule_data.rule_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid rule_type: {rule_data.rule_type}")
    
    # Validate condition structure
    if not rule_data.condition.get("conditions"):
        raise HTTPException(status_code=400, detail="Rule must have at least one condition")
    
    # Check for duplicate name
    existing_rules = repo.get_all()
    for rule in existing_rules:
        if rule.name.lower() == rule_data.name.lower():
            raise HTTPException(status_code=400, detail=f"Rule with name '{rule_data.name}' already exists")
    
    # Create the rule
    rule = repo.create(rule_data.model_dump())
    return rule


@router.get("/", response_model=List[RuleResponse])
def list_rules(
    enabled_only: bool = Query(False, description="Only return enabled rules"),
    rule_type: Optional[str] = Query(None, description="Filter by rule type"),
    db: Session = Depends(get_db),
):
    """
    List all risk rules with optional filters.
    """
    repo = RuleRepository(db)
    
    rules = repo.get_all(enabled_only=enabled_only)
    
    # Filter by type if provided
    if rule_type:
        try:
            rule_type_enum = RuleType(rule_type)
            rules = [r for r in rules if r.rule_type == rule_type_enum]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid rule_type: {rule_type}")
    
    return rules


@router.get("/{rule_id}", response_model=RuleResponse)
def get_rule(
    rule_id: str,
    db: Session = Depends(get_db),
):
    """
    Get a single rule by ID.
    """
    repo = RuleRepository(db)
    rule = repo.get_by_id(rule_id)
    
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
def update_rule(
    rule_id: str,
    rule_data: RuleUpdate,
    db: Session = Depends(get_db),
):
    """
    Update an existing rule.
    """
    repo = RuleRepository(db)
    
    # Check if rule exists
    existing = repo.get_by_id(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    
    # Validate rule type if provided
    if rule_data.rule_type:
        try:
            RuleType(rule_data.rule_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid rule_type: {rule_data.rule_type}")
    
    # Update the rule
    updated = repo.update(rule_id, rule_data.model_dump(exclude_unset=True))
    return updated


@router.delete("/{rule_id}")
def delete_rule(
    rule_id: str,
    db: Session = Depends(get_db),
):
    """
    Delete a rule.
    """
    repo = RuleRepository(db)
    
    # Check if rule exists
    existing = repo.get_by_id(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    
    repo.delete(rule_id)
    return {"message": f"Rule {rule_id} deleted successfully"}


@router.patch("/{rule_id}/enable")
def enable_rule(
    rule_id: str,
    db: Session = Depends(get_db),
):
    """
    Enable a rule.
    """
    repo = RuleRepository(db)
    rule = repo.enable(rule_id)
    
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    
    return {"message": f"Rule '{rule.name}' enabled", "rule": rule.to_dict()}


@router.patch("/{rule_id}/disable")
def disable_rule(
    rule_id: str,
    db: Session = Depends(get_db),
):
    """
    Disable a rule.
    """
    repo = RuleRepository(db)
    rule = repo.disable(rule_id)
    
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    
    return {"message": f"Rule '{rule.name}' disabled", "rule": rule.to_dict()}


# ================================================================
# TEST ENDPOINT
# ================================================================

@router.post("/test", response_model=RuleTestResponse)
def test_rule(
    test_data: RuleTestRequest,
):
    """
    Test a rule against sample event data.
    """
    evaluator = RuleEvaluator()
    
    # Convert the test rule to a RuleModel for evaluation
    class TempRule:
        def __init__(self, data):
            self.id = "test"
            self.name = data.name
            self.enabled = True
            self.condition = data.condition
            self.rule_type = data.rule_type  # This is a string
            self.base_score = data.base_score
            self.modifier = data.modifier
    
    temp_rule = TempRule(test_data.rule)
    
    # Evaluate the rule
    result = evaluator.evaluate_rule_result(temp_rule, test_data.event_data)
    
    if not result:
        return RuleTestResponse(
            matches=False,
            rule_name=test_data.rule.name,
            rule_type=test_data.rule.rule_type,
            base_score=test_data.rule.base_score,
            modifier=test_data.rule.modifier,
            effective_score=0,
            matched_conditions=[],
            reasoning="Rule conditions did not match the event data",
        )
    
    return RuleTestResponse(
        matches=True,
        rule_name=test_data.rule.name,
        rule_type=test_data.rule.rule_type,
        base_score=test_data.rule.base_score,
        modifier=test_data.rule.modifier,
        effective_score=result["effective_score"],
        matched_conditions=[f"{c['field']} {c['operator']} {c['value']} (event: {c['event_value']})" for c in result["matched_conditions"]],
        reasoning=f"Rule matched {len(result['matched_conditions'])} conditions",
    )


# ================================================================
# RULE TYPES ENDPOINT
# ================================================================

@router.get("/types")
def get_rule_types():
    """
    Get all available rule types.
    """
    return {
        "types": [
            {"value": "event_type", "label": "Event Type"},
            {"value": "identity", "label": "Identity"},
            {"value": "context", "label": "Context"},
            {"value": "threat_intel", "label": "Threat Intelligence"},
            {"value": "resource", "label": "Resource"},
        ]
    }