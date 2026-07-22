from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from ...application.services.ingestion import IngestionService
from ...core.database import get_db

router = APIRouter(prefix="/api/ingestion", tags=["ingestion"])

# ✅ Use Depends to get fresh DB session for each request

@router.post("/run")
async def run_ingestion(
    count: int = Query(3, description="Number of events to generate"),
    db: Session = Depends(get_db)
):
    """Trigger mock event ingestion with PostgreSQL storage"""
    service = IngestionService(db_session=db)
    result = service.run(count=count)
    return result

@router.get("/incidents")
async def get_ingestion_incidents(
    db: Session = Depends(get_db)
):
    """Get all incidents (from memory)"""
    service = IngestionService(db_session=db)
    incidents = service.get_incidents()
    
    return {
        "total": len(incidents),
        "source": "in-memory",
        "incidents": [
            {
                "id": i.id,
                "title": i.title,
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

@router.get("/stats")
async def get_stats(
    db: Session = Depends(get_db)
):
    """Get ingestion statistics"""
    service = IngestionService(db_session=db)
    return service.get_stats()

@router.post("/clear")
async def clear_events(
    db: Session = Depends(get_db)
):
    """Clear all events and incidents (memory + PostgreSQL)"""
    service = IngestionService(db_session=db)
    service.clear()
    return {"message": "All events and incidents cleared"}

@router.get("/events")
async def get_events(
    db: Session = Depends(get_db)
):
    """Get all received raw events"""
    service = IngestionService(db_session=db)
    events = service.get_events()
    return {
        "total": len(events),
        "events": [
            {
                "source": e.source,
                "provider": e.provider,
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat(),
                "data": e.data
            }
            for e in events
        ]
    }

@router.get("/normalized")
async def get_normalized_events(
    db: Session = Depends(get_db)
):
    """Get all normalized events"""
    service = IngestionService(db_session=db)
    events = service.get_normalized_events()
    return {
        "total": len(events),
        "events": [
            {
                "event_id": e.event_id,
                "provider": e.provider,
                "provider_type": e.provider_type,
                "event_type": e.event_type,
                "event_name": e.event_name,
                "event_description": e.event_description,
                "event_category": e.event_category,
                "actor": e.actor,
                "actor_type": e.actor_type,
                "actor_arn": e.actor_arn,
                "actor_ip": e.actor_ip,
                "resource": e.resource,
                "resource_type": e.resource_type,
                "resource_details": e.resource_details,
                "action": e.action,
                "action_details": e.action_details,
                "result": e.result,
                "result_details": e.result_details,
                "severity": e.severity,
                "severity_score": e.severity_score,
                "severity_reason": e.severity_reason,
                "timestamp": e.timestamp.isoformat(),
                "region": e.region,
                "account_id": e.account_id,
                "tags": e.tags,
                "metadata": e.metadata
            }
            for e in events
        ]
    }