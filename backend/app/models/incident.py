# app/models/incident.py
from sqlalchemy import Column, String, DateTime, JSON, Integer, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime

from app.core.database import Base
from app.domain.models.incident import IncidentStatus, IncidentPriority


class IncidentModel(Base):
    __tablename__ = "incidents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Display fields
    title = Column(String(500), nullable=False)
    description = Column(String(2000))
    
    # Status & Priority
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.PENDING)
    priority = Column(SQLEnum(IncidentPriority), default=IncidentPriority.MEDIUM)
    
    # Source information
    source_type = Column(String(100))
    source_event_id = Column(String(255))
    
    # Additional data
    tags = Column(JSON, default=list)
    extra_data = Column(JSON, default=dict)
    
    # Assignment
    assigned_to = Column(String(255))
    assigned_team = Column(String(255))
    
    # Evidence
    evidence_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    
    # ✅ Relationship - uses string reference to EvidenceArtifact
    evidence_artifacts = relationship(
        "EvidenceArtifact",
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="select"
    )
    
    def to_dict(self):
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "status": self.status.value if self.status else None,
            "priority": self.priority.value if self.priority else None,
            "source_type": self.source_type,
            "source_event_id": self.source_event_id,
            "tags": self.tags,
            "extra_data": self.extra_data,
            "assigned_to": self.assigned_to,
            "assigned_team": self.assigned_team,
            "evidence_count": self.evidence_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }