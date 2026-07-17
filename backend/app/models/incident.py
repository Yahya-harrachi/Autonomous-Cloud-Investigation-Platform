from sqlalchemy import Column, String, DateTime, Text, JSON, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from ..core.database import Base
import uuid
import enum

class IncidentStatus(str, enum.Enum):
    PENDING = "pending"
    INVESTIGATING = "investigating"
    COMPLETED = "completed"
    RESOLVED = "resolved"

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.PENDING)
    source_type = Column(String(50))
    source_id = Column(String(255))
    severity = Column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW
    extra_data = Column(JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())