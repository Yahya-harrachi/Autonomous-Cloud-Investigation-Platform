from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List
import uuid
from ...core.database import get_db
from ...domain.models.incident import Incident, IncidentStatus
from ...schemas.incident import IncidentCreate, IncidentResponse
from ...services.s3_service import S3Service

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

@router.post("/", response_model=IncidentResponse)
def create_incident(incident: IncidentCreate, db: Session = Depends(get_db)):
    """Create a new incident"""
    db_incident = Incident(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        source_type=incident.source_type,
        source_id=incident.source_id,
        extra_data=incident.extra_data
    )
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident

@router.get("/", response_model=List[IncidentResponse])
def list_incidents(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """List all incidents"""
    incidents = db.query(Incident).offset(skip).limit(limit).all()
    return incidents

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Get incident by ID"""
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(Incident).filter(Incident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

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
    
    incident = db.query(Incident).filter(Incident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    if status not in [s.value for s in IncidentStatus]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    incident.status = status
    db.commit()
    db.refresh(incident)
    return incident

@router.post("/{incident_id}/evidence")
def upload_evidence(
    incident_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload evidence file for an incident"""
    # Verify incident exists
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(Incident).filter(Incident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Upload to S3
    s3 = S3Service()
    content = file.file.read()
    key = s3.upload_file(incident_id, file.filename, content)
    
    return {"message": "Evidence uploaded", "key": key}
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
    
    incident = db.query(Incident).filter(Incident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident.title = incident_update.title
    incident.description = incident_update.description
    incident.severity = incident_update.severity
    incident.source_type = incident_update.source_type
    incident.source_id = incident_update.source_id
    incident.extra_data = incident_update.extra_data
    
    db.commit()
    db.refresh(incident)
    return incident

@router.delete("/{incident_id}")
def delete_incident(incident_id: str, db: Session = Depends(get_db)):
    """Delete an incident"""
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    
    incident = db.query(Incident).filter(Incident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    db.delete(incident)
    db.commit()
    return {"message": "Incident deleted successfully"}

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

@router.get("/from-ingestion")
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