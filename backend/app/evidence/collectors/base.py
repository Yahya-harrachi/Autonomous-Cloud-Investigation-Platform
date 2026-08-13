# app/evidence/collectors/base.py
"""
Base collector interface for all evidence collectors
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from datetime import datetime
import json
import hashlib
import uuid
import re

from app.models.evidence import EvidenceArtifact
from app.domain.models.incident import Incident
from app.core.database import SessionLocal


def parse_incident_id(incident_id: str) -> uuid.UUID:
    """
    Parse incident ID string to UUID.
    
    Handles:
    - inc-abc123def456 -> UUID
    - abc123def456 -> UUID
    - Full UUID string -> UUID
    - Any other string -> deterministic UUID
    
    Args:
        incident_id: The incident ID string
        
    Returns:
        UUID object
    """
    # If it's already a UUID string, return it
    try:
        return uuid.UUID(incident_id)
    except (ValueError, TypeError):
        pass
    
    # Remove 'inc-' prefix if present
    clean_id = incident_id
    if incident_id.startswith('inc-'):
        clean_id = incident_id[4:]
    
    # Remove any non-hex characters
    clean_id = re.sub(r'[^a-fA-F0-9]', '', clean_id)
    
    # If we have a valid hex string, try to create UUID
    if clean_id:
        # Pad to 32 characters if needed
        if len(clean_id) < 32:
            clean_id = clean_id.ljust(32, '0')
        
        # If length is at least 32, it's a valid UUID
        if len(clean_id) >= 32:
            clean_id = clean_id[:32]
            try:
                return uuid.UUID(clean_id)
            except ValueError:
                pass
    
    # Fallback: generate deterministic UUID
    return uuid.uuid5(uuid.NAMESPACE_DNS, incident_id)


class BaseCollector(ABC):
    """
    Abstract base class for all evidence collectors.
    Each collector handles one type of evidence (CloudTrail, IAM, etc.)
    """
    
    def __init__(self):
        self.collector_name = self.__class__.__name__
    
    @abstractmethod
    async def collect(self, incident: Incident) -> Optional[EvidenceArtifact]:
        """
        Collect evidence for an incident.
        
        Args:
            incident: The incident to collect evidence for
            
        Returns:
            EvidenceArtifact or None if collection fails
        """
        pass
    
    @abstractmethod
    def get_artifact_type(self) -> str:
        """Return the type of artifact this collector produces"""
        pass
    
    @abstractmethod
    def get_source(self) -> str:
        """Return the source of the evidence (e.g., 'aws_cloudtrail')"""
        pass
    
    def create_artifact(
        self,
        incident_id: str,
        content: Dict[str, Any],
        extra_data: Optional[Dict[str, Any]] = None,
        region: Optional[str] = None,
    ) -> EvidenceArtifact:
        """
        Create an EvidenceArtifact from collected data.
        
        Args:
            incident_id: The incident ID
            content: The evidence content
            extra_data: Additional metadata
            region: AWS region (if applicable)
            
        Returns:
            EvidenceArtifact instance
        """
        # Convert content to canonical JSON for hashing
        canonical_content = json.dumps(content, sort_keys=True, default=str)
        
        # Calculate SHA-256 hash
        hash_value = hashlib.sha256(canonical_content.encode()).hexdigest()
        
        # Ensure incident_id is a valid UUID
        incident_uuid = self._parse_incident_id(incident_id)
        
        artifact = EvidenceArtifact(
            incident_id=incident_uuid,
            artifact_type=self.get_artifact_type(),
            source=self.get_source(),
            provider="aws",
            region=region,
            collector=self.collector_name,
            content=content,
            extra_data=extra_data or {},
            hash=f"SHA-256:{hash_value}",
            hash_algorithm="SHA-256",
            collection_status="COMPLETED",
            collected_at=datetime.utcnow(),
        )
        
        return artifact
    
    def _parse_incident_id(self, incident_id: str) -> uuid.UUID:
        """
        Parse incident ID to UUID using shared utility.
        
        Args:
            incident_id: The incident ID string
            
        Returns:
            UUID object
        """
        return parse_incident_id(incident_id)
    
    def save_artifact(self, artifact: EvidenceArtifact) -> bool:
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
            print(f"✅ Artifact saved: {artifact.id} ({artifact.artifact_type})")
            return True
        except Exception as e:
            print(f"❌ Failed to save artifact: {e}")
            db.rollback()
            return False
        finally:
            db.close()