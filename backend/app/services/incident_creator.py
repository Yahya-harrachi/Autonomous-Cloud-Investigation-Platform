"""
Incident Creator - Creates incidents from normalized events
"""
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session

from ..domain.models.event import NormalizedEvent
from ..domain.models.incident import Incident, IncidentStatus, IncidentPriority
from ..models.incident import IncidentModel
from ..core.database import SessionLocal
from ..risk.rules.rule_service import RuleService
from ..risk.rules.rule_evaluator import RuleEvaluator

logger = logging.getLogger(__name__)


class IncidentCreator:
    """
    Creates incidents from normalized events based on severity.
    Only processes events that are severe enough.
    """
    
    def __init__(self):
        self.severity_thresholds = {
            "CRITICAL": True,
            "HIGH": True,
            "MEDIUM": 40,  # Score threshold
            "LOW": False,
            "INFO": False,
        }
    
    def process_event(self, normalized: NormalizedEvent) -> Optional[Incident]:
        """
        Process a normalized event and create an incident if needed.
        
        Args:
            normalized: Normalized event
            
        Returns:
            Incident if created, None otherwise
        """
        # 1. Check if incident should be created
        should_create, reason = self._should_create_incident(normalized)
        
        if not should_create:
            logger.debug(f"Event {normalized.event_name} not severe enough: {reason}")
            return None
        
        # 2. Check for duplicates
        if self._is_duplicate(normalized):
            logger.debug(f"Duplicate incident for {normalized.event_name}, skipping")
            return None
        
        # 3. Create incident
        incident = self._create_incident(normalized)
        
        # 4. Save to database
        self._save_incident(incident)
        
        logger.info(f"✅ Incident created: {incident.title} ({incident.severity})")
        return incident
    
    def _should_create_incident(self, event: NormalizedEvent) -> Tuple[bool, str]:
        """Determine if an incident should be created"""
        severity = event.severity
        score = event.severity_score
        
        if severity in ["CRITICAL", "HIGH"]:
            return True, f"Severity is {severity}"
        
        if severity == "MEDIUM" and score >= self.severity_thresholds["MEDIUM"]:
            return True, f"MEDIUM severity with score {score} >= threshold"
        
        return False, f"Severity {severity} or score {score} below threshold"
    
    def _is_duplicate(self, event: NormalizedEvent) -> bool:
        """Check if a similar incident was created recently"""
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
        """Create an incident from a normalized event"""
        priority = self._map_severity_to_priority(event.severity)
        
        title = self._generate_title(event)
        description = self._generate_description(event)
        
        return Incident(
            id=f"inc-{uuid.uuid4().hex[:12]}",
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
            metadata={
                "severity": event.severity,
                "severity_score": event.severity_score,
                "reason": event.severity_reason,
                "event_name": event.event_name,
                "actor": event.actor,
                "region": event.region,
            },
            evidence_count=0,
            evidence_ids=[],
        )
    
    def _save_incident(self, incident: Incident) -> None:
        """Save incident to database"""
        db = SessionLocal()
        try:
            db_incident = IncidentModel(
                id=uuid.UUID(incident.id.replace('inc-', '')),
                title=incident.title,
                description=incident.description,
                status=IncidentStatus(incident.status.value),
                priority=IncidentPriority(incident.priority.value),
                source_type=incident.source_type,
                source_event_id=incident.source_event_id,
                tags=incident.tags,
                extra_data=incident.metadata,
                created_at=incident.created_at,
            )
            db.add(db_incident)
            db.commit()
            db.refresh(db_incident)
        except Exception as e:
            logger.error(f"Failed to save incident: {e}")
            db.rollback()
            raise
        finally:
            db.close()
    
    def _map_severity_to_priority(self, severity: str) -> IncidentPriority:
        """Map severity to incident priority"""
        mapping = {
            "CRITICAL": IncidentPriority.CRITICAL,
            "HIGH": IncidentPriority.HIGH,
            "MEDIUM": IncidentPriority.MEDIUM,
            "LOW": IncidentPriority.LOW,
            "INFO": IncidentPriority.LOW,
        }
        return mapping.get(severity, IncidentPriority.MEDIUM)
    
    def _generate_title(self, event: NormalizedEvent) -> str:
        """Generate incident title"""
        severity = event.severity
        event_name = event.event_name
        actor = event.actor
        
        if severity in ["CRITICAL", "HIGH"]:
            return f"[{severity}] {event_name} by {actor}"
        else:
            return f"{event_name} by {actor}"
    
    def _generate_description(self, event: NormalizedEvent) -> str:
        """Generate incident description"""
        parts = []
        parts.append(f"Incident detected from {event.provider.upper()}")
        parts.append(f"Event: {event.event_name}")
        parts.append(f"Actor: {event.actor} ({event.actor_type})")
        parts.append(f"Severity: {event.severity} (Score: {event.severity_score})")
        
        if event.resource and event.resource != "unknown":
            parts.append(f"Resource: {event.resource}")
        
        if event.region:
            parts.append(f"Region: {event.region}")
        
        if event.severity_reason:
            parts.append(f"Reason: {event.severity_reason}")
        
        return " | ".join(parts)