"""
SQLAlchemy model for incidents
"""
from sqlalchemy import Column, String, DateTime, Text, JSON, Enum as SQLEnum, ARRAY
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.types import TypeDecorator
from ..core.database import Base
import uuid
import enum
import json


class IncidentStatus(str, enum.Enum):
    PENDING = "pending"
    INVESTIGATING = "investigating"
    COMPLETED = "completed"
    RESOLVED = "resolved"


class IncidentPriority(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class JSONType(TypeDecorator):
    """Custom JSON type for PostgreSQL"""
    impl = JSON
    
    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value) if not isinstance(value, dict) else value
        return value
    
    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value) if isinstance(value, str) else value
        return value


class IncidentModel(Base):
    """SQLAlchemy model for incidents table"""
    __tablename__ = "incidents"

    # ===== IDENTIFICATION =====
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    
    # ===== STATUS & PRIORITY =====
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.PENDING)
    priority = Column(SQLEnum(IncidentPriority), default=IncidentPriority.MEDIUM)
    
    # ===== SOURCE =====
    source_type = Column(String(50), nullable=False)  # "aws_cloudtrail", "azure_activity"
    source_event_id = Column(String(100), nullable=False)  # Original event ID
    
    # ===== TAGS & METADATA =====
    tags = Column(ARRAY(String), default=[])
    extra_data = Column(JSON, default={})
    
    # ===== ASSIGNMENT =====
    assigned_to = Column(String(100), nullable=True)
    assigned_team = Column(String(50), nullable=True)
    
    # ===== TIMING =====
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    # ===== EVIDENCE =====
    evidence_count = Column(JSON, default=0)  # Using JSON instead of Integer
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value if self.priority else None,
            "status": self.status.value if self.status else None,
            "source_type": self.source_type,
            "source_event_id": self.source_event_id,
            "tags": self.tags or [],
            "extra_data": self.extra_data or {},
            "assigned_to": self.assigned_to,
            "assigned_team": self.assigned_team,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "evidence_count": self.evidence_count or 0
        }