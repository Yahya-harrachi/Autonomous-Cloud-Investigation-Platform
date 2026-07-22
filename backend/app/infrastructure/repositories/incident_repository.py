"""
PostgreSQL repository for incidents
"""
from typing import List, Optional
from sqlalchemy.orm import Session
from uuid import UUID
from datetime import datetime

from ...domain.models.incident import Incident, IncidentStatus, IncidentPriority
from ...models.incident import IncidentModel


class IncidentRepository:
    """
    PostgreSQL repository for incidents.
    Handles all database operations for incidents.
    """
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def save(self, incident: Incident) -> IncidentModel:
        """
        Save an incident to the database.
        """
        # Check if incident already exists by ID
        try:
            # Extract UUID from inc-xxx format
            incident_id = incident.id.replace('inc-', '')
            existing = self.db.query(IncidentModel).filter(
                IncidentModel.id == UUID(incident_id)
            ).first()
        except ValueError:
            existing = None
        
        if existing:
            # Update existing
            existing.title = incident.title
            existing.description = incident.description
            existing.status = IncidentStatus(incident.status.value)
            existing.priority = IncidentPriority(incident.priority.value)
            existing.source_type = incident.source_type
            existing.source_event_id = incident.source_event_id
            existing.tags = incident.tags
            existing.extra_data = incident.metadata  # ✅ FIXED: Use metadata
            existing.assigned_to = incident.assigned_to
            existing.assigned_team = incident.assigned_team
            existing.updated_at = datetime.utcnow()
            existing.resolved_at = incident.resolved_at
            existing.evidence_count = incident.evidence_count
            
            self.db.commit()
            self.db.refresh(existing)
            return existing
        
        # Create new incident
        db_incident = IncidentModel(
            title=incident.title,
            description=incident.description,
            status=IncidentStatus(incident.status.value),
            priority=IncidentPriority(incident.priority.value),
            source_type=incident.source_type,
            source_event_id=incident.source_event_id,
            tags=incident.tags,
            extra_data=incident.metadata,  # ✅ FIXED: Use metadata
            assigned_to=incident.assigned_to,
            assigned_team=incident.assigned_team,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            resolved_at=incident.resolved_at,
            evidence_count=incident.evidence_count
        )
        
        self.db.add(db_incident)
        self.db.commit()
        self.db.refresh(db_incident)
        
        return db_incident
    
    def get_all(self, skip: int = 0, limit: int = 100) -> List[IncidentModel]:
        """Get all incidents with pagination."""
        return self.db.query(IncidentModel)\
            .order_by(IncidentModel.created_at.desc())\
            .offset(skip)\
            .limit(limit)\
            .all()
    
    def get_by_id(self, incident_id: str) -> Optional[IncidentModel]:
        """Get an incident by ID."""
        try:
            # Handle inc- prefix
            if incident_id.startswith('inc-'):
                incident_id = incident_id.replace('inc-', '')
            
            uuid_obj = UUID(incident_id)
            return self.db.query(IncidentModel)\
                .filter(IncidentModel.id == uuid_obj)\
                .first()
        except ValueError:
            return None
    
    def update_status(self, incident_id: str, status: IncidentStatus) -> Optional[IncidentModel]:
        """Update incident status."""
        incident = self.get_by_id(incident_id)
        if not incident:
            return None
        
        incident.status = status
        incident.updated_at = datetime.utcnow()
        
        if status in [IncidentStatus.COMPLETED, IncidentStatus.RESOLVED]:
            incident.resolved_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(incident)
        return incident
    
    def update_priority(self, incident_id: str, priority: IncidentPriority) -> Optional[IncidentModel]:
        """Update incident priority."""
        incident = self.get_by_id(incident_id)
        if not incident:
            return None
        
        incident.priority = priority
        incident.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(incident)
        return incident
    
    def assign(self, incident_id: str, assigned_to: str, assigned_team: str = None) -> Optional[IncidentModel]:
        """Assign incident to someone."""
        incident = self.get_by_id(incident_id)
        if not incident:
            return None
        
        incident.assigned_to = assigned_to
        incident.assigned_team = assigned_team
        incident.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(incident)
        return incident
    
    def delete(self, incident_id: str) -> bool:
        """Delete an incident."""
        incident = self.get_by_id(incident_id)
        if not incident:
            return False
        
        self.db.delete(incident)
        self.db.commit()
        return True
    
    def get_stats(self) -> dict:
        """Get incident statistics."""
        total = self.db.query(IncidentModel).count()
        pending = self.db.query(IncidentModel)\
            .filter(IncidentModel.status == IncidentStatus.PENDING).count()
        investigating = self.db.query(IncidentModel)\
            .filter(IncidentModel.status == IncidentStatus.INVESTIGATING).count()
        resolved = self.db.query(IncidentModel)\
            .filter(IncidentModel.status.in_([IncidentStatus.COMPLETED, IncidentStatus.RESOLVED])).count()
        
        return {
            "total": total,
            "pending": pending,
            "investigating": investigating,
            "resolved": resolved
        }