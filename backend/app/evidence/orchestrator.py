# app/evidence/orchestrator.py
"""
Evidence Orchestrator - Coordinates evidence collection for incidents
"""
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from app.domain.models.incident import Incident
from app.models.evidence import EvidenceArtifact, EvidencePlaybook
from app.evidence.collectors.cloudtrail_collector import CloudTrailCollector
from app.core.database import SessionLocal
from app.models.incident import IncidentModel
from app.evidence.collectors.iam_collector import IAMCollector
from app.evidence.collectors.base import parse_incident_id

logger = logging.getLogger(__name__)


class EvidenceOrchestrator:
    """
    Orchestrates evidence collection for incidents.
    
    Responsibilities:
    1. Receive newly created incident
    2. Identify incident type
    3. Select appropriate playbook
    4. Execute collectors
    5. Track collection status
    6. Store evidence artifacts
    """
    
    def __init__(self):
        self.collectors = {
            "CloudTrailEvent": CloudTrailCollector(),
            "IAMUser": IAMCollector(),  
            # "IAMPolicy": IAMPolicyCollector(),  # Will add later
            # "IAMRole": IAMRoleCollector(),  # Will add later
        }
        self.logger = logging.getLogger(__name__)
    
    async def orchestrate(self, incident: Incident) -> Dict[str, Any]:
        """
        Orchestrate evidence collection for an incident.
        
        Args:
            incident: The incident to collect evidence for
            
        Returns:
            Dict with collection results
        """
        self.logger.info(f"🎯 Orchestrating evidence collection for incident {incident.id}")
        
        # 1. Get incident type from normalized event
        event_name = incident.normalized_event.get('event_name', '')
        if not event_name:
            self.logger.warning(f"⚠️ No event_name found for incident {incident.id}")
            return {
                "incident_id": incident.id,
                "status": "FAILED",
                "error": "No event_name found in incident"
            }
        
        # 2. Find matching playbook
        playbook = self._find_playbook(event_name)
        if not playbook:
            self.logger.info(f"ℹ️ No playbook found for event: {event_name}, skipping evidence collection")
            return {
                "incident_id": incident.id,
                "status": "SKIPPED",
                "reason": f"No playbook for event: {event_name}"
            }
        
        self.logger.info(f"📋 Using playbook: {playbook.name}")
        self.logger.info(f"   Required evidence: {playbook.evidence_required}")
        
        # 3. Collect evidence
        artifacts = []
        failed_collectors = []
        
        for evidence_type in playbook.evidence_required:
            self.logger.info(f"🔍 Collecting evidence type: {evidence_type}")
            
            if evidence_type in self.collectors:
                collector = self.collectors[evidence_type]
                try:
                    artifact = await collector.collect(incident)
                    if artifact:
                        # Save to database
                        saved = self._save_artifact(artifact)
                        if saved:
                            artifacts.append(artifact)
                            self.logger.info(f"✅ Collected {evidence_type} evidence")
                        else:
                            self.logger.error(f"❌ Failed to save {evidence_type} artifact")
                            failed_collectors.append(evidence_type)
                    else:
                        self.logger.warning(f"⚠️ No artifact returned for {evidence_type}")
                        failed_collectors.append(evidence_type)
                except Exception as e:
                    self.logger.error(f"❌ Error collecting {evidence_type}: {e}")
                    failed_collectors.append(evidence_type)
            else:
                self.logger.warning(f"⚠️ No collector registered for {evidence_type}")
                failed_collectors.append(evidence_type)
        
        # 4. Update incident with evidence count
        self._update_incident_evidence_count(incident.id, len(artifacts))
        
        # 5. Prepare result
        result = {
            "incident_id": incident.id,
            "status": "COMPLETED" if artifacts else "FAILED",
            "artifacts_collected": len(artifacts),
            "artifacts": [self._artifact_to_dict(a) for a in artifacts],
            "failed_collectors": failed_collectors,
            "playbook_used": playbook.name
        }
        
        self.logger.info(f"✅ Evidence orchestration complete for incident {incident.id}")
        self.logger.info(f"   Collected: {len(artifacts)} artifacts")
        self.logger.info(f"   Failed: {len(failed_collectors)} collectors")
        
        return result
    
    def _find_playbook(self, event_name: str) -> Optional[EvidencePlaybook]:
        """
        Find a playbook that matches the event name.
        
        Args:
            event_name: The event name to match
            
        Returns:
            EvidencePlaybook or None
        """
        db = SessionLocal()
        try:
            # Get all enabled playbooks
            playbooks = db.query(EvidencePlaybook).filter(
                EvidencePlaybook.enabled == True
            ).all()
            
            # Find matching playbook
            for playbook in playbooks:
                trigger_events = playbook.trigger_events or []
                if event_name in trigger_events:
                    self.logger.info(f"✅ Found playbook: {playbook.name} for event: {event_name}")
                    return playbook
            
            self.logger.info(f"ℹ️ No playbook found for event: {event_name}")
            return None
        except Exception as e:
            self.logger.error(f"❌ Error finding playbook: {e}")
            return None
        finally:
            db.close()
    
    def _save_artifact(self, artifact: EvidenceArtifact) -> bool:
        """
        Save artifact to database.
        
        Args:
            artifact: The artifact to save
            
        Returns:
            True if successful, False otherwise
        """
        db = SessionLocal()
        try:
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
            self.logger.info(f"✅ Artifact saved: {artifact.id} ({artifact.artifact_type})")
            return True
        except Exception as e:
            self.logger.error(f"❌ Failed to save artifact: {e}")
            db.rollback()
            return False
        finally:
            db.close()
    
    def _update_incident_evidence_count(self, incident_id: str, count: int):
        """
        Update the evidence count on the incident.
        
        Args:
            incident_id: The incident ID
            count: Number of evidence artifacts
        """
        db = SessionLocal()
        try:
            # Use the helper to parse the incident ID
            incident_uuid = parse_incident_id(incident_id)
            
            incident = db.query(IncidentModel).filter(
                IncidentModel.id == incident_uuid
            ).first()
            
            if incident:
                incident.evidence_count = count
                db.commit()
                self.logger.info(f"✅ Updated incident {incident_id} evidence count to {count}")
            else:
                self.logger.warning(f"⚠️ Incident not found for ID: {incident_id} (UUID: {incident_uuid})")
                
                # Try to find by display ID if UUID didn't work
                # This is a fallback for inc-xxx format
                if incident_id.startswith('inc-'):
                    # Search by title or extract from metadata
                    incidents = db.query(IncidentModel).all()
                    for inc in incidents:
                        if hasattr(inc, 'extra_data') and inc.extra_data:
                            if inc.extra_data.get('incident_display_id') == incident_id:
                                inc.evidence_count = count
                                db.commit()
                                self.logger.info(f"✅ Updated incident by display ID: {incident_id}")
                                return
                    
                    self.logger.warning(f"⚠️ Could not find incident with display ID: {incident_id}")
        except Exception as e:
            self.logger.error(f"❌ Failed to update incident evidence count: {e}")
            db.rollback()
        finally:
            db.close()
    
    def _artifact_to_dict(self, artifact: EvidenceArtifact) -> Dict[str, Any]:
        """
        Convert artifact to dictionary.
        
        Args:
            artifact: The artifact to convert
            
        Returns:
            Dictionary representation
        """
        return {
            "id": str(artifact.id),
            "artifact_type": artifact.artifact_type,
            "source": artifact.source,
            "collector": artifact.collector,
            "collection_status": artifact.collection_status,
            "collected_at": artifact.collected_at.isoformat() if artifact.collected_at else None,
            "hash": artifact.hash,
            "integrity_verified": artifact.integrity_verified
        }