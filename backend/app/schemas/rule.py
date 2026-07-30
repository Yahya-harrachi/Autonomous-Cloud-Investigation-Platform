"""
Rule Schemas - Pydantic models for rule API
"""
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID


class RuleCondition(BaseModel):
    """Rule condition structure"""
    field: str          # event_name, identity_type, actor_ip, etc.
    operator: str       # eq, neq, gt, lt, contains, starts_with, ends_with
    value: Any          # The value to compare against


class RuleCreate(BaseModel):
    """Schema for creating a rule"""
    name: str
    description: Optional[str] = None
    enabled: bool = True
    priority: int = 100
    rule_type: str  # event_type, identity, context, threat_intel, resource
    condition: Dict[str, Any]  # JSON condition
    base_score: int = 0
    modifier: float = 1.0


class RuleUpdate(BaseModel):
    """Schema for updating a rule"""
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    rule_type: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    base_score: Optional[int] = None
    modifier: Optional[float] = None


class RuleResponse(BaseModel):
    """Schema for rule response"""
    id: UUID
    name: str
    description: Optional[str]
    enabled: bool
    priority: int
    rule_type: str
    condition: Dict[str, Any]
    base_score: int
    modifier: float
    created_at: datetime
    updated_at: Optional[datetime]
    created_by: Optional[UUID]

    class Config:
        from_attributes = True


class RuleTestRequest(BaseModel):
    """Schema for testing a rule against an event"""
    rule: RuleCreate
    event_data: Dict[str, Any]  # Sample event data to test against


class RuleTestResponse(BaseModel):
    """Schema for rule test response"""
    matches: bool
    rule_name: str
    rule_type: str
    base_score: int
    modifier: float
    effective_score: int
    matched_conditions: List[str]
    reasoning: str