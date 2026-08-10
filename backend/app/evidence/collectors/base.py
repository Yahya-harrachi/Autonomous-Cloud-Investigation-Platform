# app/evidence/collectors/base.py
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from datetime import datetime
import json
import hashlib
import uuid

from app.domain.models.evidence import EvidenceArtifact
from app.domain.models.incident import Incident


class BaseCollector(ABC):
    """
    Base class for all evidence collectors.
    Each collector handles one type of evidence.
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
        metadata: Optional[Dict[str, Any]] = None,
        region: Optional[str] = None,
    ) -> EvidenceArtifact:
        """
        Create an EvidenceArtifact from collected data.
        
        Args:
            incident_id: The incident ID
            content: The evidence content
            metadata: Additional metadata
            region: AWS region (if applicable)
            
        Returns:
            EvidenceArtifact instance
        """
        # Convert content to canonical JSON for hashing
        canonical_content = json.dumps(content, sort_keys=True, default=str)
        
        # Calculate SHA-256 hash
        hash_value = hashlib.sha256(canonical_content.encode()).hexdigest()
        
        artifact = EvidenceArtifact(
            incident_id=uuid.UUID(incident_id) if isinstance(incident_id, str) else incident_id,
            artifact_type=self.get_artifact_type(),
            source=self.get_source(),
            provider="aws",
            region=region,
            collector=self.collector_name,
            content=content,
            metadata=metadata or {},
            hash=f"SHA-256:{hash_value}",
            hash_algorithm="SHA-256",
            collection_status="COMPLETED",
            collected_at=datetime.utcnow(),
        )
        
        return artifact