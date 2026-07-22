"""
Incident domain model
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum


class IncidentStatus(str, Enum):
    PENDING = "pending"
    INVESTIGATING = "investigating"
    COMPLETED = "completed"
    RESOLVED = "resolved"


class IncidentPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Incident:
    """Incident domain model"""
    
    # ===== REQUIRED FIELDS =====
    id: str
    title: str
    description: str
    status: IncidentStatus
    priority: IncidentPriority
    source_type: str
    source_event_id: str
    normalized_event: Dict[str, Any]
    created_at: datetime
    
    # ===== OPTIONAL FIELDS =====
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    
    # ===== DICT FIELDS =====
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)  # ✅ Added
    evidence_ids: List[str] = field(default_factory=list)
    
    # ===== INTEGER FIELDS =====
    evidence_count: int = 0
    
    @property
    def is_resolved(self) -> bool:
        return self.status in [IncidentStatus.COMPLETED, IncidentStatus.RESOLVED]
    
    @property
    def display_name(self) -> str:
        return f"[{self.priority.value.upper()}] {self.title}"
    
    @property
    def duration_hours(self) -> float:
        """Hours since incident was created"""
        if not self.updated_at:
            return 0
        delta = self.updated_at - self.created_at
        return delta.total_seconds() / 3600
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority.value,
            "source_type": self.source_type,
            "source_event_id": self.source_event_id,
            "normalized_event": self.normalized_event,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "assigned_to": self.assigned_to,
            "assigned_team": self.assigned_team,
            "tags": self.tags,
            "metadata": self.metadata,
            "evidence_ids": self.evidence_ids,
            "evidence_count": self.evidence_count,
            "is_resolved": self.is_resolved,
            "display_name": self.display_name
        }