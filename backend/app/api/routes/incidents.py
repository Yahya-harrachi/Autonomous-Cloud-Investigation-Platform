from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List
import uuid

from ...core.database import get_db
from ...domain.models.incident import IncidentStatus
from ...schemas.incident import IncidentCreate, IncidentResponse
from ...services.s3_service import S3Service
from ...models.incident import IncidentModel
from ...infrastructure.repositories.incident_repository import IncidentRepository

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

# ===== STATS ROUTE =====
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
        "resolved": stats.get("resolved", 0)
    }

# ===== FROM-INGESTION ROUTE =====
@router.get("/from-ingestion", response_model=None)
async def get_incidents_from_ingestion():
    """Get all incidents created by the ingestion pipeline"""
    from ...application.services.ingestion import IngestionService
    service = IngestionService()
    incidents = service.get_incidents()
    
    return {
        "total": len(incidents),
        "incidents": [
            {
                "id": i.id,
                "title": i.title,
                "description": i.description,
                "priority": i.priority.value,
                "status": i.status.value,
                "source_type": i.source_type,
                "created_at": i.created_at.isoformat(),
                "tags": i.tags,
                "metadata": i.metadata
            }
            for i in incidents
        ]
    }

# ===== LIST INCIDENTS - FIXED =====
@router.get("/", response_model=List[IncidentResponse])
def list_incidents(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """List all incidents"""
    incidents = db.query(IncidentModel).offset(skip).limit(limit).all()
    
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
            "created_at": i.created_at,
            "updated_at": i.updated_at
        }
        for i in incidents
    ]

# ===== CREATE INCIDENT =====
@router.post("/", response_model=IncidentResponse)
def create_incident(incident: IncidentCreate, db: Session = Depends(get_db)):
    """Create a new incident"""
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
        "id": db_incident.id,
        "title": db_incident.title,
        "description": db_incident.description,
        "priority": db_incident.priority.value if db_incident.priority else "MEDIUM",
        "status": db_incident.status.value if db_incident.status else "pending",
        "source_type": db_incident.source_type,
        "source_event_id": db_incident.source_event_id,
        "tags": db_incident.tags or [],
        "extra_data": db_incident.extra_data or {},
        "created_at": db_incident.created_at,
        "updated_at": db_incident.updated_at
    }

# ===== GET INCIDENT BY ID =====
@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Get incident by ID"""
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "priority": incident.priority.value if incident.priority else "MEDIUM",
        "status": incident.status.value if incident.status else "pending",
        "source_type": incident.source_type,
        "source_event_id": incident.source_event_id,
        "tags": incident.tags or [],
        "extra_data": incident.extra_data or {},
        "created_at": incident.created_at,
        "updated_at": incident.updated_at
    }

# ===== UPDATE INCIDENT STATUS =====
@router.put("/{incident_id}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_id: str, 
    status: str, 
    db: Session = Depends(get_db)
):
    """Update incident status"""
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    if status not in [s.value for s in IncidentStatus]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    incident.status = status
    db.commit()
    db.refresh(incident)
    
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "priority": incident.priority.value if incident.priority else "MEDIUM",
        "status": incident.status.value if incident.status else "pending",
        "source_type": incident.source_type,
        "source_event_id": incident.source_event_id,
        "tags": incident.tags or [],
        "extra_data": incident.extra_data or {},
        "created_at": incident.created_at,
        "updated_at": incident.updated_at
    }

# ===== UPLOAD EVIDENCE =====
@router.post("/{incident_id}/evidence")
def upload_evidence(
    incident_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload evidence file for an incident"""
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    s3 = S3Service()
    content = file.file.read()
    key = s3.upload_file(incident_id, file.filename, content)
    
    return {"message": "Evidence uploaded", "key": key}

# ===== UPDATE INCIDENT =====
@router.put("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: str,
    incident_update: IncidentCreate,
    db: Session = Depends(get_db)
):
    """Update an incident"""
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident.title = incident_update.title
    incident.description = incident_update.description
    incident.priority = incident_update.priority
    incident.source_type = incident_update.source_type
    incident.source_event_id = incident_update.source_id
    incident.extra_data = incident_update.extra_data
    
    db.commit()
    db.refresh(incident)
    
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "priority": incident.priority.value if incident.priority else "MEDIUM",
        "status": incident.status.value if incident.status else "pending",
        "source_type": incident.source_type,
        "source_event_id": incident.source_event_id,
        "tags": incident.tags or [],
        "extra_data": incident.extra_data or {},
        "created_at": incident.created_at,
        "updated_at": incident.updated_at
    }

# ===== DELETE INCIDENT =====
@router.delete("/{incident_id}")
def delete_incident(incident_id: str, db: Session = Depends(get_db)):
    """Delete an incident"""
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    db.delete(incident)
    db.commit()
    return {"message": "Incident deleted successfully"}

# ===== LIST EVIDENCE =====
@router.get("/{incident_id}/evidence")
def list_evidence(incident_id: str):
    """List all evidence files for an incident"""
    try:
        uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    s3 = S3Service()
    files = s3.list_files(incident_id)
    return {"incident_id": incident_id, "evidence_files": files}

# ===== DELETE EVIDENCE =====
@router.delete("/{incident_id}/evidence/{filename}")
def delete_evidence(incident_id: str, filename: str):
    """Delete an evidence file from S3"""
    try:
        uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    s3 = S3Service()
    key = f"incidents/{incident_id}/{filename}"
    
    try:
        s3.client.delete_object(Bucket=s3.bucket, Key=key)
        return {"message": f"Evidence file {filename} deleted"}
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")