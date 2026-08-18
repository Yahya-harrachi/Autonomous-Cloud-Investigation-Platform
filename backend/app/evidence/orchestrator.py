# app/evidence/orchestrator.py
"""
Evidence Orchestrator - Coordinates evidence collection for incidents
"""
import logging
import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from app.domain.models.incident import Incident
from app.models.evidence import EvidenceArtifact, EvidencePlaybook
from app.evidence.collectors.cloudtrail_collector import CloudTrailCollector
from app.evidence.collectors.iam_collector import IAMCollector
from app.evidence.collectors.iam_policy_collector import IAMPolicyCollector
from app.evidence.collectors.iam_role_collector import IAMRoleCollector
from app.core.database import SessionLocal
from app.models.incident import IncidentModel
from app.evidence.collectors.base import parse_incident_id

logger = logging.getLogger(__name__)


class EvidenceOrchestrator:
    """Orchestrates evidence collection for incidents."""

    def __init__(self):
        self.collectors = {
            "CloudTrailEvent": CloudTrailCollector(),
            "IAMUser": IAMCollector(),
            "IAMPolicy": IAMPolicyCollector(),
            "IAMRole": IAMRoleCollector(),
        }
        self.logger = logging.getLogger(__name__)
        self.logger.info("=" * 60)
        self.logger.info("✅ Evidence Orchestrator Initialized")
        self.logger.info("📋 Registered Collectors:")
        for key in self.collectors:
            self.logger.info(f"   ✅ {key}: {self.collectors[key].__class__.__name__}")
        self.logger.info("=" * 60)

    async def orchestrate(self, incident: Incident) -> Dict[str, Any]:
        """Orchestrate evidence collection for an incident."""
        self.logger.info("=" * 60)
        self.logger.info(f"🎯 ORCHESTRATOR STARTING for incident: {incident.id}")
        self.logger.info("=" * 60)

        event_data = incident.normalized_event
        event_name = event_data.get('event_name', '')
        actor = event_data.get('actor', 'Unknown')
        provider = event_data.get('provider', 'Unknown')

        self.logger.info(f"📋 Incident Details:")
        self.logger.info(f"   Event: {event_name}")
        self.logger.info(f"   Actor: {actor}")
        self.logger.info(f"   Provider: {provider}")
        self.logger.info("-" * 40)

        if not event_name:
            return {"incident_id": incident.id, "status": "FAILED", "error": "No event_name found"}

        # Determine which evidence types to collect
        evidence_types = self._determine_evidence_types(event_name, provider, actor)

        self.logger.info(f"📋 Evidence types to collect: {evidence_types}")

        # Collect evidence in parallel
        tasks = []
        for evidence_type in evidence_types:
            if evidence_type in self.collectors:
                self.logger.info(f"🔍 Starting collection for: {evidence_type}")
                tasks.append(self._collect_with_logging(evidence_type, incident))
            else:
                self.logger.warning(f"⚠️ No collector registered for {evidence_type}")
                # Create empty artifact for missing collector
                empty = self._create_empty_artifact(incident.id, evidence_type, f"No collector registered")
                if empty:
                    self._save_artifact(empty)

        if not tasks:
            return {"incident_id": incident.id, "status": "FAILED", "error": "No collectors available"}

        self.logger.info(f"⏳ Waiting for {len(tasks)} collectors to complete...")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        artifacts = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"❌ Collector failed: {result}")
                # Create empty artifact on exception
                empty = self._create_empty_artifact(incident.id, "Unknown", f"Collection error: {str(result)}")
                if empty:
                    self._save_artifact(empty)
                    artifacts.append(empty)
                continue

            if result and result.get('artifact'):
                saved = self._save_artifact(result['artifact'])
                if saved:
                    artifacts.append(result['artifact'])
                    self.logger.info(f"   ✅ {result['type']}: SAVED")
                else:
                    self.logger.error(f"   ❌ {result['type']}: FAILED TO SAVE")
                    # Try to save empty artifact as fallback
                    empty = self._create_empty_artifact(incident.id, result['type'], "Failed to save artifact")
                    if empty:
                        self._save_artifact(empty)
                        artifacts.append(empty)
            elif result and result.get('error'):
                self.logger.warning(f"   ⚠️ {result.get('type')}: {result.get('message', 'Unknown error')}")
                # ✅ CRITICAL: Always create empty artifact when collector returns error
                empty = self._create_empty_artifact(
                    incident.id,
                    result.get('type', 'Unknown'),
                    result.get('message', 'Collection failed')
                )
                if empty:
                    self._save_artifact(empty)
                    artifacts.append(empty)
            else:
                self.logger.warning(f"   ⚠️ Unknown result: {result}")

        self._update_incident_evidence_count(incident.id, len(artifacts))

        result = {
            "incident_id": incident.id,
            "status": "COMPLETED" if artifacts else "PARTIAL",
            "artifacts_collected": len(artifacts),
            "artifacts": [self._artifact_to_dict(a) for a in artifacts],
            "playbook_used": "DEFAULT"
        }

        self.logger.info("=" * 60)
        self.logger.info(f"✅ EVIDENCE ORCHESTRATION COMPLETE")
        self.logger.info(f"   ✅ Collected: {len(artifacts)} artifacts")
        if artifacts:
            self.logger.info(f"   📋 Types: {[a.artifact_type for a in artifacts]}")
        self.logger.info("=" * 60)

        return result

    def _determine_evidence_types(self, event_name: str, provider: str, actor: str) -> List[str]:
        """Determine which evidence types to collect based on event."""
        # Always collect CloudTrail
        types = ["CloudTrailEvent"]

        # Check if IAM-related
        is_iam = any([
            'User' in event_name,
            'Policy' in event_name,
            'Role' in event_name,
            'Group' in event_name,
            'iam' in provider.lower(),
            'IAM' in event_name
        ])

        if is_iam:
            types.extend(["IAMUser", "IAMPolicy", "IAMRole"])
            self.logger.info(f"🔍 IAM-related event detected: {event_name}")
            self.logger.info(f"   Collecting: {types}")

        # Check if S3-related (for future)
        if 'Bucket' in event_name or 'S3' in event_name:
            # types.append("S3Bucket")  # Future
            pass

        return types

    async def _collect_with_logging(self, evidence_type: str, incident: Incident) -> Dict[str, Any]:
        """Collect with error handling - ALWAYS returns something."""
        try:
            collector = self.collectors[evidence_type]
            self.logger.info(f"   🔄 Collecting {evidence_type}...")
            artifact = await collector.collect(incident)

            if artifact:
                self.logger.info(f"   ✅ Completed: {evidence_type}")
                return {'artifact': artifact, 'type': evidence_type}
            else:
                # ✅ Collector returned None - create empty artifact
                self.logger.warning(f"   ⚠️ Collector returned None for {evidence_type}")
                empty = self._create_empty_artifact(
                    incident.id,
                    evidence_type,
                    f"No data collected for {evidence_type}"
                )
                return {'artifact': empty, 'type': evidence_type}
        except Exception as e:
            self.logger.error(f"   ❌ Failed: {evidence_type} - {e}")
            # ✅ Create empty artifact on exception
            empty = self._create_empty_artifact(
                incident.id,
                evidence_type,
                f"Collection error: {str(e)}"
            )
            return {'artifact': empty, 'type': evidence_type}

    def _create_empty_artifact(self, incident_id: str, artifact_type: str, message: str) -> Optional[EvidenceArtifact]:
        """Create an empty artifact when collection fails or returns nothing."""
        try:
            incident_uuid = parse_incident_id(incident_id)

            empty_content = {
                "message": message,
                "summary": {
                    "total_events": 0,
                    "total_policies": 0,
                    "total_roles": 0,
                    "total_users": 0
                },
                "note": "No evidence collected for this artifact type"
            }

            artifact = EvidenceArtifact(
                id=uuid.uuid4(),
                incident_id=incident_uuid,
                artifact_type=artifact_type,
                source="aws",
                provider="aws",
                region="global",
                collector="EvidenceOrchestrator",
                content=empty_content,
                extra_data={"empty": True, "message": message},
                collection_status="COMPLETED",
                error_message=message if "error" in message.lower() else None,
                integrity_verified=False,
                collected_at=datetime.utcnow()
            )

            self.logger.info(f"   📝 Created empty artifact for: {artifact_type}")
            return artifact
        except Exception as e:
            self.logger.error(f"❌ Failed to create empty artifact: {e}")
            return None

    def _find_playbook(self, event_name: str) -> Optional[EvidencePlaybook]:
        db = SessionLocal()
        try:
            playbooks = db.query(EvidencePlaybook).filter(EvidencePlaybook.enabled == True).all()
            for playbook in playbooks:
                if event_name in (playbook.trigger_events or []):
                    return playbook
            return None
        except Exception as e:
            self.logger.error(f"❌ Error finding playbook: {e}")
            return None
        finally:
            db.close()

    def _save_artifact(self, artifact: EvidenceArtifact) -> bool:
        db = SessionLocal()
        try:
            db.add(artifact)
            db.commit()
            db.refresh(artifact)
            self.logger.info(f"   💾 Saved: {artifact.artifact_type} ({artifact.id})")
            return True
        except Exception as e:
            self.logger.error(f"   ❌ Failed to save artifact: {e}")
            db.rollback()
            return False
        finally:
            db.close()

    def _update_incident_evidence_count(self, incident_id: str, count: int):
        db = SessionLocal()
        try:
            incident_uuid = parse_incident_id(incident_id)
            incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
            if incident:
                incident.evidence_count = count
                db.commit()
                self.logger.info(f"📊 Updated incident evidence count to {count}")
        except Exception as e:
            self.logger.error(f"❌ Failed to update incident evidence count: {e}")
            db.rollback()
        finally:
            db.close()

    def _artifact_to_dict(self, artifact: EvidenceArtifact) -> Dict[str, Any]:
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