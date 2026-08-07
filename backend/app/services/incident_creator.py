"""
Incident Creator - Creates incidents from normalized events based on severity
"""
import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session

from ..domain.models.event import NormalizedEvent
from ..domain.models.incident import Incident, IncidentStatus, IncidentPriority
from ..models.incident import IncidentModel
from ..core.database import SessionLocal

logger = logging.getLogger(__name__)


class IncidentCreator:
    """
    Creates incidents from normalized events based on severity.
    Only processes events that are severe enough.
    """
    
    def __init__(self):
        self.severity_thresholds = {
            "CRITICAL": True,        # Always create incident
            "HIGH": True,            # Always create incident
            "MEDIUM": 40,            # Create if score >= 40
            "LOW": False,            # Never create incident
            "INFO": False,           # Never create incident
        }
    
    def process_event(self, normalized: NormalizedEvent) -> Optional[Incident]:
        """
        Process a normalized event and create an incident if needed.
        """
        print(f"🔍 IncidentCreator.process_event called for: {normalized.event_name}")
        
        # 1. Check if incident should be created
        should_create, reason = self._should_create_incident(normalized)
        print(f"   Should create: {should_create}, Reason: {reason}")
        
        if not should_create:
            print(f"   ❌ Not creating incident")
            return None
        
        # 2. Check for duplicates
        if self._is_duplicate(normalized):
            print(f"   ❌ Duplicate incident, skipping")
            return None
        
        # 3. Create incident
        incident = self._create_incident(normalized)
        print(f"   ✅ Incident object created: {incident.title}")
        
        # 4. Save to database
        self._save_incident(incident)
        
        # ✅ FIX: Use priority.value instead of severity
        print(f"✅ Incident created: {incident.title} ({incident.priority.value})")
        return incident
    
    def _should_create_incident(self, event: NormalizedEvent) -> Tuple[bool, str]:
        """
        Determine if an incident should be created.
        
        Returns:
            (should_create, reason)
        """
        severity = event.severity
        score = event.severity_score
        
        # CRITICAL and HIGH always create incidents
        if severity in ["CRITICAL", "HIGH"]:
            return True, f"Severity is {severity}"
        
        # MEDIUM creates incident if score is above threshold
        if severity == "MEDIUM" and score >= self.severity_thresholds["MEDIUM"]:
            return True, f"MEDIUM severity with score {score} >= threshold"
        
        # LOW and INFO never create incidents
        return False, f"Severity {severity} or score {score} below threshold"
    
    def _is_duplicate(self, event: NormalizedEvent) -> bool:
        """
        Check if a similar incident was created recently.
        
        Args:
            event: Normalized event
            
        Returns:
            True if duplicate exists
        """
        db = SessionLocal()
        try:
            # Check for same event_name in last 5 minutes
            cutoff = datetime.utcnow() - timedelta(minutes=5)
            
            count = db.query(IncidentModel).filter(
                IncidentModel.title.ilike(f"%{event.event_name}%"),
                IncidentModel.created_at >= cutoff
            ).count()
            
            return count > 0
        except Exception as e:
            logger.warning(f"Duplicate check failed: {e}")
            return False
        finally:
            db.close()
    
    def _create_incident(self, event: NormalizedEvent) -> Incident:
        """
        Create an incident from a normalized event.
        """
        priority = self._map_severity_to_priority(event.severity)
        
        title = self._generate_title(event)
        description = self._generate_description(event)
        
        # Generate a valid UUID for database storage
        incident_uuid = uuid.uuid4()
        incident_id = f"inc-{incident_uuid.hex[:12]}"  # Display ID
        
        # ✅ Add severity_score to metadata
        metadata = {
            "severity": event.severity,
            "severity_score": event.severity_score,
            "reason": event.severity_reason,
            "event_name": event.event_name,
            "actor": event.actor,
            "actor_type": event.actor_type,
            "region": event.region,
            "source_ip": event.actor_ip,
            "timestamp": event.timestamp.isoformat(),
        }
        
        return Incident(
            id=incident_id,
            title=title,
            description=description,
            status=IncidentStatus.PENDING,
            priority=priority,
            source_type=f"{event.provider}_{event.provider_type}",
            source_event_id=event.event_id,
            normalized_event=event.to_dict(),
            created_at=datetime.utcnow(),
            updated_at=None,
            resolved_at=None,
            assigned_to=None,
            assigned_team=None,
            tags=event.tags or [],
            metadata=metadata,
            evidence_count=0,
            evidence_ids=[],
        )
    
    def _save_incident(self, incident: Incident) -> None:
        """
        Save incident to database.
        
        Args:
            incident: Incident to save
        """
        db = SessionLocal()
        try:
            # Generate a valid UUID from the incident ID
            # incident.id format: inc-abc123def456
            uuid_str = incident.id.replace('inc-', '')
            
            # If the UUID is short (12 chars), pad it to 32 chars
            if len(uuid_str) < 32:
                uuid_str = uuid_str.ljust(32, '0')
            
            db_incident = IncidentModel(
                id=uuid.UUID(uuid_str),
                title=incident.title,
                description=incident.description,
                status=IncidentStatus(incident.status.value),
                priority=IncidentPriority(incident.priority.value),
                source_type=incident.source_type,
                source_event_id=incident.source_event_id,
                tags=incident.tags,
                extra_data=incident.metadata,
                created_at=incident.created_at,
                updated_at=incident.updated_at,
                resolved_at=incident.resolved_at,
                evidence_count=incident.evidence_count,
            )
            
            db.add(db_incident)
            db.commit()
            db.refresh(db_incident)
            logger.info(f"✅ Incident saved to database: {incident.id}")
            
        except Exception as e:
            logger.error(f"Failed to save incident: {e}")
            db.rollback()
            raise
        finally:
            db.close()
    
    def _map_severity_to_priority(self, severity: str) -> IncidentPriority:
        """
        Map severity to incident priority.
        
        Args:
            severity: Severity string
            
        Returns:
            IncidentPriority enum
        """
        mapping = {
            "CRITICAL": IncidentPriority.CRITICAL,
            "HIGH": IncidentPriority.HIGH,
            "MEDIUM": IncidentPriority.MEDIUM,
            "LOW": IncidentPriority.LOW,
            "INFO": IncidentPriority.LOW,
        }
        return mapping.get(severity, IncidentPriority.MEDIUM)
    
    def _generate_title(self, event: NormalizedEvent) -> str:
        """
        Generate incident title.
        """
        severity = event.severity
        event_name = event.event_name
        actor = event.actor
        
        if actor and actor != "unknown":
            return f"[{severity}] {event_name} by {actor}"
        else:
            return f"[{severity}] {event_name}"
    
    def _generate_description(self, event: NormalizedEvent) -> str:
        """
        Generate incident description.
        
        Args:
            event: Normalized event
            
        Returns:
            Description string
        """
        parts = []
        
        # Source
        parts.append(f"Incident detected from {event.provider.upper()}")
        
        # Event
        parts.append(f"Event: {event.event_name}")
        
        # Actor
        if event.actor and event.actor != "unknown":
            parts.append(f"Actor: {event.actor} ({event.actor_type})")
        
        # Severity
        parts.append(f"Severity: {event.severity} (Score: {event.severity_score}/100)")
        
        # Resource
        if event.resource and event.resource != "unknown":
            parts.append(f"Resource: {event.resource}")
        
        # Region
        if event.region:
            parts.append(f"Region: {event.region}")
        
        # Source IP
        if event.actor_ip and event.actor_ip != "unknown":
            parts.append(f"Source IP: {event.actor_ip}")
        
        # Severity reason
        if event.severity_reason:
            parts.append(f"Reason: {event.severity_reason}")
        
        return " | ".join(parts)
    
    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Get incident by ID.
        
        Args:
            incident_id: Incident ID
            
        Returns:
            Incident data or None
        """
        db = SessionLocal()
        try:
            # Extract UUID from inc-xxx format
            uuid_str = incident_id.replace('inc-', '')
            if len(uuid_str) < 32:
                uuid_str = uuid_str.ljust(32, '0')
            
            incident = db.query(IncidentModel).filter(
                IncidentModel.id == uuid.UUID(uuid_str)
            ).first()
            
            if not incident:
                return None
            
            return incident.to_dict()
        except Exception as e:
            logger.error(f"Error getting incident: {e}")
            return None
        finally:
            db.close()
    
    def get_incidents(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get all incidents.
        
        Args:
            skip: Number to skip
            limit: Max results
            
        Returns:
            List of incident dictionaries
        """
        db = SessionLocal()
        try:
            incidents = db.query(IncidentModel)\
                .order_by(IncidentModel.created_at.desc())\
                .offset(skip)\
                .limit(limit)\
                .all()
            
            return [i.to_dict() for i in incidents]
        except Exception as e:
            logger.error(f"Error getting incidents: {e}")
            return []
        finally:
            db.close()
    
    def get_incident_stats(self) -> Dict[str, Any]:
        """
        Get incident statistics.
        
        Returns:
            Stats dictionary
        """
        db = SessionLocal()
        try:
            total = db.query(IncidentModel).count()
            pending = db.query(IncidentModel).filter(
                IncidentModel.status == IncidentStatus.PENDING
            ).count()
            investigating = db.query(IncidentModel).filter(
                IncidentModel.status == IncidentStatus.INVESTIGATING
            ).count()
            resolved = db.query(IncidentModel).filter(
                IncidentModel.status.in_([IncidentStatus.COMPLETED, IncidentStatus.RESOLVED])
            ).count()
            
            return {
                "total": total,
                "pending": pending,
                "investigating": investigating,
                "resolved": resolved,
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {"total": 0, "pending": 0, "investigating": 0, "resolved": 0}
        finally:
            db.close()