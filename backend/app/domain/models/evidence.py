# app/models/evidence.py
from sqlalchemy import Column, String, DateTime, JSON, Boolean, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.core.database import Base

class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False)
    
    # Artifact Identification
    artifact_type = Column(String(50), nullable=False)
    source = Column(String(50), nullable=False)
    provider = Column(String(20), default="aws")
    region = Column(String(50))
    
    # Collection Metadata
    collector = Column(String(100), nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow)
    
    # Content
    content = Column(JSON, nullable=False)
    metadata = Column(JSON)
    
    # Integrity
    hash = Column(String(128))
    hash_algorithm = Column(String(20), default="SHA-256")
    
    # Status
    collection_status = Column(String(20), default="PENDING")
    error_message = Column(Text)
    
    # Verification
    integrity_verified = Column(Boolean, default=False)
    verified_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    incident = relationship("IncidentModel", back_populates="evidence_artifacts")
    
    def to_dict(self):
        return {
            "id": str(self.id),
            "incident_id": str(self.incident_id),
            "artifact_type": self.artifact_type,
            "source": self.source,
            "provider": self.provider,
            "region": self.region,
            "collector": self.collector,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
            "content": self.content,
            "metadata": self.metadata,
            "hash": self.hash,
            "hash_algorithm": self.hash_algorithm,
            "collection_status": self.collection_status,
            "error_message": self.error_message,
            "integrity_verified": self.integrity_verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class EvidencePlaybook(Base):
    __tablename__ = "evidence_playbooks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    
    # Trigger events (JSON array of event names)
    trigger_events = Column(JSON, nullable=False)
    
    # Evidence to collect (JSON array)
    evidence_required = Column(JSON, nullable=False)
    
    enabled = Column(Boolean, default=True)
    version = Column(String(10), default="1.0.0")
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "trigger_events": self.trigger_events,
            "evidence_required": self.evidence_required,
            "enabled": self.enabled,
            "version": self.version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }