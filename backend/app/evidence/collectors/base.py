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

from app.models.evidence import EvidenceArtifact
from app.domain.models.incident import Incident
from app.core.database import SessionLocal


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
        Parse incident ID string to UUID.
        Handles various formats:
        - UUID string: '550e8400-e29b-41d4-a716-446655440000'
        - Short ID: 'inc-abc123' or 'abc123'
        - Any other string: generates a new UUID
        
        Args:
            incident_id: The incident ID string
            
        Returns:
            UUID object
        """
        try:
            # If it's already a valid UUID, return it
            return uuid.UUID(incident_id)
        except (ValueError, TypeError):
            pass
        
        # Remove 'inc-' prefix if present
        clean_id = incident_id
        if isinstance(incident_id, str) and incident_id.startswith('inc-'):
            clean_id = incident_id[4:]  # Remove 'inc-'
        
        # Generate a deterministic UUID from the string
        # This ensures the same incident_id always produces the same UUID
        try:
            # Use the string to generate a deterministic UUID (v5)
            namespace = uuid.NAMESPACE_DNS
            # Use the clean ID as the name
            return uuid.uuid5(namespace, str(clean_id))
        except:
            # If all else fails, generate a random UUID
            return uuid.uuid4()
    
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