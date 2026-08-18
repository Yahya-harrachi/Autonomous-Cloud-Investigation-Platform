# app/api/routes/evidence.py
"""
Evidence API Routes
"""
import hashlib
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
import uuid

from app.core.database import get_db
from app.models.evidence import EvidenceArtifact
from app.evidence.collectors.base import parse_incident_id

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


@router.post("/evidence/{artifact_id}/verify")
async def verify_single_evidence(
    artifact_id: str,
    db: Session = Depends(get_db)
):
    """
    Verify a single evidence artifact by ID.
    """
    import hashlib
    import json
    from datetime import datetime
    import uuid
    
    try:
        artifact_uuid = uuid.UUID(artifact_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid artifact ID format")
    
    artifact = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.id == artifact_uuid
    ).first()
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    if not artifact.hash or artifact.hash == 'N/A':
        return {
            "artifact_id": str(artifact.id),
            "verified": False,
            "message": "No hash available to verify",
            "verified_at": None
        }
    
    canonical_content = json.dumps(artifact.content, sort_keys=True, default=str)
    new_hash = hashlib.sha256(canonical_content.encode()).hexdigest()
    
    stored_hash = artifact.hash
    if stored_hash and stored_hash.startswith("SHA-256:"):
        stored_hash = stored_hash.replace("SHA-256:", "")
    
    verified = new_hash == stored_hash
    
    artifact.integrity_verified = verified
    artifact.verified_at = datetime.utcnow()
    db.commit()
    
    return {
        "artifact_id": str(artifact.id),
        "verified": verified,
        "hash": stored_hash,
        "new_hash": new_hash,
        "verified_at": artifact.verified_at.isoformat() if artifact.verified_at else None,
        "message": "Integrity verified successfully" if verified else "Hash mismatch - evidence may be tampered!"
    }


@router.get("/{artifact_id}")
async def get_evidence(
    artifact_id: str,
    db: Session = Depends(get_db)
):
    """
    Get a single evidence artifact by ID.
    """
    try:
        artifact_uuid = uuid.UUID(artifact_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid artifact ID format")
    
    artifact = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.id == artifact_uuid
    ).first()
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    return artifact.to_dict()