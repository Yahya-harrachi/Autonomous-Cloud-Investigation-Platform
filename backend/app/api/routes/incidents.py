# app/api/routes/incidents.py
"""
Incident API Routes - Complete and Corrected
"""
from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, File, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import uuid
import hashlib
import json
from datetime import datetime

from app.services.pdf_generator import PDFReportGenerator

from ...core.database import get_db
from ...domain.models.incident import IncidentStatus
from ...schemas.incident import IncidentCreate, IncidentResponse
from ...models.incident import IncidentModel
from ...models.evidence import EvidenceArtifact
from ...infrastructure.repositories.incident_repository import IncidentRepository
from ...evidence.collectors.base import parse_incident_id

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


# ================================================================
# STATS ROUTE - MUST BE BEFORE /{incident_id}
# ================================================================

@router.get("/stats", response_model=None)
async def get_incident_stats(
    db: Session = Depends(get_db)
):
    """Get incident statistics"""
    repo = IncidentRepository(db)
    stats = repo.get_stats()
    
    return {
        "total": stats.get("total", 0),
        "pending": stats.get("pending", 0),
        "investigating": stats.get("investigating", 0),
        "resolved": stats.get("resolved", 0),
    }


# ================================================================
# LIST INCIDENTS WITH FILTER
# ================================================================

@router.get("/", response_model=List[IncidentResponse])
def list_incidents(
    skip: int = Query(0, description="Number of records to skip"),
    limit: int = Query(100, description="Maximum records to return"),
    status: Optional[str] = Query(None, description="Filter by status"),
    db: Session = Depends(get_db)
):
    """List all incidents with optional status filter"""
    query = db.query(IncidentModel)
    
    # Apply status filter if provided
    if status and status != 'all':
        try:
            status_enum = IncidentStatus(status)
            query = query.filter(IncidentModel.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    
    incidents = query.order_by(IncidentModel.created_at.desc()).offset(skip).limit(limit).all()
    
    return [
        {
            "id": str(i.id),
            "title": i.title,
            "description": i.description,
            "priority": i.priority.value if i.priority else "MEDIUM",
            "status": i.status.value if i.status else "pending",
            "source_type": i.source_type,
            "source_event_id": i.source_event_id,
            "tags": i.tags or [],
            "extra_data": i.extra_data or {},
            "evidence_count": i.evidence_count or 0,
            "created_at": i.created_at,
            "updated_at": i.updated_at
        }
        for i in incidents
    ]


# ================================================================
# CREATE INCIDENT (Manual)
# ================================================================

@router.post("/", response_model=IncidentResponse)
def create_incident(
    incident: IncidentCreate,
    db: Session = Depends(get_db)
):
    """Create a new incident manually"""
    db_incident = IncidentModel(
        title=incident.title,
        description=incident.description,
        priority=incident.priority,
        source_type=incident.source_type,
        source_event_id=incident.source_id,
        extra_data=incident.extra_data
    )
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    
    return {
        "id": str(db_incident.id),
        "title": db_incident.title,
        "description": db_incident.description,
        "priority": db_incident.priority.value if db_incident.priority else "MEDIUM",
        "status": db_incident.status.value if db_incident.status else "pending",
        "source_type": db_incident.source_type,
        "source_event_id": db_incident.source_event_id,
        "tags": db_incident.tags or [],
        "extra_data": db_incident.extra_data or {},
        "evidence_count": db_incident.evidence_count or 0,
        "created_at": db_incident.created_at,
        "updated_at": db_incident.updated_at
    }


# ================================================================
# GET INCIDENT BY ID
# ================================================================

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """Get incident by ID"""
    try:
        incident_uuid = parse_incident_id(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {
        "id": str(incident.id),
        "title": incident.title,
        "description": incident.description,
        "priority": incident.priority.value if incident.priority else "MEDIUM",
        "status": incident.status.value if incident.status else "pending",
        "source_type": incident.source_type,
        "source_event_id": incident.source_event_id,
        "tags": incident.tags or [],
        "extra_data": incident.extra_data or {},
        "evidence_count": incident.evidence_count or 0,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at
    }


# ================================================================
# UPDATE INCIDENT STATUS
# ================================================================

@router.put("/{incident_id}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_id: str,
    status: str,
    db: Session = Depends(get_db)
):
    """Update incident status"""
    try:
        incident_uuid = parse_incident_id(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # ✅ Fix: Accept both lowercase and uppercase
    status_lower = status.lower()
    valid_statuses = [s.value for s in IncidentStatus]  # ["pending", "investigating", "completed", "resolved"]
    
    if status_lower not in valid_statuses:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    incident.status = status_lower  # ✅ Store lowercase
    db.commit()
    db.refresh(incident)
    
    return {
        "id": str(incident.id),
        "title": incident.title,
        "description": incident.description,
        "priority": incident.priority.value if incident.priority else "MEDIUM",
        "status": incident.status.value if incident.status else "pending",
        "source_type": incident.source_type,
        "source_event_id": incident.source_event_id,
        "tags": incident.tags or [],
        "extra_data": incident.extra_data or {},
        "evidence_count": incident.evidence_count or 0,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at
    }


# Export Incident
@router.get("/{incident_id}/export")
async def export_incident(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """
    Export an incident with all its evidence as a complete package.
    """
    try:
        # Parse incident ID
        incident_uuid = parse_incident_id(incident_id)
        
        # Get incident
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_uuid
        ).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Get all evidence artifacts
        artifacts = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.incident_id == incident_uuid
        ).all()
        
        # Build export package
        export_data = {
            "export_metadata": {
                "exported_at": datetime.utcnow().isoformat(),
                "exporter": "ACIP Evidence Export",
                "version": "1.0.0",
                "incident_id": incident_id
            },
            "incident": {
                "id": str(incident.id),
                "title": incident.title,
                "description": incident.description,
                "status": incident.status.value if incident.status else None,
                "priority": incident.priority.value if incident.priority else None,
                "source_type": incident.source_type,
                "source_event_id": incident.source_event_id,
                "tags": incident.tags,
                "extra_data": incident.extra_data,
                "assigned_to": incident.assigned_to,
                "assigned_team": incident.assigned_team,
                "evidence_count": incident.evidence_count,
                "created_at": incident.created_at.isoformat() if incident.created_at else None,
                "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None
            },
            "evidence": []
        }
        
        # Add evidence artifacts
        for artifact in artifacts:
            export_data["evidence"].append({
                "id": str(artifact.id),
                "artifact_type": artifact.artifact_type,
                "source": artifact.source,
                "provider": artifact.provider,
                "region": artifact.region,
                "collector": artifact.collector,
                "collected_at": artifact.collected_at.isoformat() if artifact.collected_at else None,
                "content": artifact.content,
                "metadata": artifact.extra_data,
                "hash": artifact.hash,
                "hash_algorithm": artifact.hash_algorithm,
                "collection_status": artifact.collection_status,
                "integrity_verified": artifact.integrity_verified,
                "verified_at": artifact.verified_at.isoformat() if artifact.verified_at else None,
                "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
                "updated_at": artifact.updated_at.isoformat() if artifact.updated_at else None
            })
        
        # Generate filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"incident_{incident_id}_{timestamp}.json"
        
        # Return as downloadable JSON
        return JSONResponse(
            content=export_data,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/json"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error exporting incident: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{incident_id}/export/pdf")
async def export_incident_pdf(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """
    Export an incident with all evidence as a PDF report.
    """
    try:
        # Parse incident ID
        incident_uuid = parse_incident_id(incident_id)
        
        # Get incident
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_uuid
        ).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Get all evidence artifacts
        artifacts = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.incident_id == incident_uuid
        ).all()
        
        # Prepare incident data
        incident_data = {
            "id": str(incident.id),
            "title": incident.title,
            "description": incident.description,
            "status": incident.status.value if incident.status else "pending",
            "priority": incident.priority.value if incident.priority else "medium",
            "source_type": incident.source_type,
            "source_event_id": incident.source_event_id,
            "tags": incident.tags or [],
            "assigned_to": incident.assigned_to,
            "assigned_team": incident.assigned_team,
            "evidence_count": incident.evidence_count,
            "created_at": incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.created_at else None,
            "updated_at": incident.updated_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.updated_at else None,
            "resolved_at": incident.resolved_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.resolved_at else None,
            "extra_data": incident.extra_data or {}
        }
        
        # Prepare evidence data
        evidence_data = []
        for artifact in artifacts:
            evidence_data.append({
                "id": str(artifact.id),
                "artifact_type": artifact.artifact_type,
                "source": artifact.source,
                "provider": artifact.provider,
                "region": artifact.region,
                "collector": artifact.collector,
                "collected_at": artifact.collected_at.strftime("%Y-%m-%d %H:%M:%S UTC") if artifact.collected_at else None,
                "content": artifact.content,
                "hash": artifact.hash,
                "collection_status": artifact.collection_status,
                "integrity_verified": artifact.integrity_verified,
            })
        
        # Generate PDF
        pdf_generator = PDFReportGenerator()
        pdf_bytes = pdf_generator.generate_incident_report(incident_data, evidence_data)
        
        # Generate filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"incident_report_{incident_id}_{timestamp}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error exporting PDF: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
# ================================================================
# UPDATE INCIDENT PRIORITY
# ================================================================

@router.put("/{incident_id}/priority", response_model=IncidentResponse)
def update_incident_priority(
    incident_id: str,
    priority: str,
    db: Session = Depends(get_db)
):
    """Update incident priority"""
    from ...domain.models.incident import IncidentPriority
    
    try:
        incident_uuid = parse_incident_id(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    if priority not in [p.value for p in IncidentPriority]:
        raise HTTPException(status_code=400, detail="Invalid priority")
    
    incident.priority = priority
    db.commit()
    db.refresh(incident)
    
    return {
        "id": str(incident.id),
        "title": incident.title,
        "description": incident.description,
        "priority": incident.priority.value if incident.priority else "MEDIUM",
        "status": incident.status.value if incident.status else "pending",
        "source_type": incident.source_type,
        "source_event_id": incident.source_event_id,
        "tags": incident.tags or [],
        "extra_data": incident.extra_data or {},
        "evidence_count": incident.evidence_count or 0,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at
    }


# ================================================================
# DELETE INCIDENT
# ================================================================

@router.delete("/{incident_id}")
def delete_incident(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """Delete an incident"""
    try:
        incident_uuid = parse_incident_id(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    db.delete(incident)
    db.commit()
    return {"message": "Incident deleted successfully"}


# ================================================================
# ✅ EVIDENCE ROUTES - DATABASE BASED (NOT S3)
# ================================================================

@router.get("/{incident_id}/evidence")
def get_incident_evidence(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """
    Get evidence artifacts for an incident from the database.
    """
    try:
        incident_uuid = parse_incident_id(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    # Check if incident exists
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Get evidence artifacts from database
    artifacts = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.incident_id == incident_uuid
    ).order_by(EvidenceArtifact.collected_at.desc()).all()
    
    return [artifact.to_dict() for artifact in artifacts]


@router.post("/evidence/{artifact_id}/verify")
async def verify_evidence(
    artifact_id: str,
    db: Session = Depends(get_db)
):
    """
    Verify evidence integrity by recalculating SHA-256 hash.
    """
    try:
        # Parse artifact ID
        try:
            artifact_uuid = uuid.UUID(artifact_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid artifact ID format")
        
        # Get artifact
        artifact = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.id == artifact_uuid
        ).first()
        
        if not artifact:
            raise HTTPException(status_code=404, detail="Artifact not found")
        
        # If no hash, can't verify
        if not artifact.hash or artifact.hash == 'N/A':
            return {
                "artifact_id": str(artifact.id),
                "verified": False,
                "message": "No hash available to verify",
                "verified_at": None
            }
        
        # Recalculate hash
        canonical_content = json.dumps(artifact.content, sort_keys=True, default=str)
        new_hash = hashlib.sha256(canonical_content.encode()).hexdigest()
        
        # Get stored hash (remove "SHA-256:" prefix if present)
        stored_hash = artifact.hash
        if stored_hash and stored_hash.startswith("SHA-256:"):
            stored_hash = stored_hash.replace("SHA-256:", "")
        
        verified = new_hash == stored_hash
        
        # Update verification status
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
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error verifying evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# BATCH VERIFY ALL EVIDENCE FOR AN INCIDENT
# ============================================================

@router.post("/{incident_id}/evidence/verify-all")
async def batch_verify_evidence(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """
    Batch verify all evidence artifacts for an incident.
    """
    try:
        # Parse incident ID
        incident_uuid = parse_incident_id(incident_id)
        
        # Check if incident exists
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_uuid
        ).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Get all evidence artifacts
        artifacts = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.incident_id == incident_uuid
        ).all()
        
        results = []
        verified_count = 0
        failed_count = 0
        no_hash_count = 0
        
        for artifact in artifacts:
            if not artifact.hash or artifact.hash == 'N/A':
                no_hash_count += 1
                results.append({
                    "artifact_id": str(artifact.id),
                    "artifact_type": artifact.artifact_type,
                    "verified": False,
                    "message": "No hash available"
                })
                continue
            
            # Recalculate hash
            canonical_content = json.dumps(artifact.content, sort_keys=True, default=str)
            new_hash = hashlib.sha256(canonical_content.encode()).hexdigest()
            
            stored_hash = artifact.hash
            if stored_hash and stored_hash.startswith("SHA-256:"):
                stored_hash = stored_hash.replace("SHA-256:", "")
            
            verified = new_hash == stored_hash
            
            # Update verification status
            artifact.integrity_verified = verified
            artifact.verified_at = datetime.utcnow()
            
            if verified:
                verified_count += 1
            else:
                failed_count += 1
            
            results.append({
                "artifact_id": str(artifact.id),
                "artifact_type": artifact.artifact_type,
                "verified": verified,
                "message": "Verified" if verified else "Hash mismatch"
            })
        
        db.commit()
        
        return {
            "incident_id": incident_id,
            "total_artifacts": len(artifacts),
            "verified_count": verified_count,
            "failed_count": failed_count,
            "no_hash_count": no_hash_count,
            "results": results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error batch verifying evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/evidence/{artifact_id}/verify")
async def verify_single_evidence(
    artifact_id: str,
    db: Session = Depends(get_db)
):
    """
    Verify a single evidence artifact by ID (via incidents router).
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
# ============================================================
# GET SINGLE EVIDENCE
# ============================================================

@router.get("/evidence/{artifact_id}")
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


@router.get("/evidence/{artifact_id}/download")
def download_evidence(
    artifact_id: str,
    db: Session = Depends(get_db)
):
    """
    Download evidence artifact as JSON.
    """
    from fastapi.responses import JSONResponse
    
    try:
        artifact_uuid = uuid.UUID(artifact_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid artifact ID format")
    
    artifact = db.query(EvidenceArtifact).filter(
        EvidenceArtifact.id == artifact_uuid
    ).first()
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    return JSONResponse(
        content=artifact.to_dict(),
        headers={
            "Content-Disposition": f"attachment; filename=evidence_{artifact_id}.json"
        }
    )