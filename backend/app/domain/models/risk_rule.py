"""
Risk Rule Model - Configurable rules for SOC analysts
"""
from sqlalchemy import Column, String, DateTime, Text, JSON, Boolean, Integer, Float, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from ...core.database import Base
import uuid
import enum


class RuleType(str, enum.Enum):
    """Types of rules"""
    EVENT_TYPE = "event_type"
    IDENTITY = "identity"
    CONTEXT = "context"
    THREAT_INTEL = "threat_intel"
    RESOURCE = "resource"


class RuleModel(Base):
    """SQLAlchemy model for risk rules"""
    __tablename__ = "risk_rules"

    # ===== IDENTIFICATION =====
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # ===== STATUS =====
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=100)  # Lower number = higher priority
    
    # ===== RULE TYPE =====
    rule_type = Column(SQLEnum(RuleType), nullable=False)
    
    # ===== RULE LOGIC =====
    condition = Column(JSON, nullable=False)  # JSON structure for rule conditions
    base_score = Column(Integer, default=0)   # Base score contribution
    modifier = Column(Float, default=1.0)     # Multiplier
    
    # ===== TIMING =====
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(UUID(as_uuid=True), nullable=True)  # User who created the rule
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "rule_type": self.rule_type.value if self.rule_type else None,
            "condition": self.condition or {},
            "base_score": self.base_score or 0,
            "modifier": self.modifier or 1.0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": str(self.created_by) if self.created_by else None,
        }