"""
Risk Rule Model - Fully dynamic
"""
from sqlalchemy import Column, String, DateTime, Text, JSON, Boolean, Integer, Float, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from ...core.database import Base
import uuid
import enum


class RuleType(str, enum.Enum):
    EVENT_TYPE = "event_type"
    IDENTITY = "identity"
    CONTEXT = "context"
    THREAT_INTEL = "threat_intel"
    CUSTOM = "custom"


class RuleModel(Base):
    """SQLAlchemy model for risk rules - Fully dynamic"""
    __tablename__ = "risk_rules"

    # ===== IDENTIFICATION =====
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # ===== STATUS =====
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=100)
    
    # ===== RULE TYPE =====
    rule_type = Column(SQLEnum(RuleType), nullable=False)
    
    # ===== DYNAMIC STORAGE =====
    # Store all rule parameters (fully dynamic)
    parameters = Column(JSON, default={})
    
    # ===== EVALUATION =====
    # Condition as JSON (can be evaluated dynamically)
    condition = Column(JSON, nullable=False)
    
    # ===== SCORING =====
    base_score = Column(Integer, default=0)
    modifier = Column(Float, default=1.0)
    
    # ===== METADATA =====
    tags = Column(JSON, default=[])  # JSON array
    created_by = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    version = Column(Integer, default=1)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "rule_type": self.rule_type.value if self.rule_type else None,
            "parameters": self.parameters or {},
            "condition": self.condition or {},
            "base_score": self.base_score or 0,
            "modifier": self.modifier or 1.0,
            "tags": self.tags or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": str(self.created_by) if self.created_by else None,
            "version": self.version,
        }