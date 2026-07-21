from fastapi import APIRouter, Query
from ...application.services.ingestion import IngestionService

router = APIRouter(prefix="/api/ingestion", tags=["ingestion"])

# Create a single instance that persists
_ingestion_service = None

def get_ingestion_service():
    global _ingestion_service
    if _ingestion_service is None:
        _ingestion_service = IngestionService()
    return _ingestion_service

@router.post("/run")
async def run_ingestion(
    count: int = Query(3, description="Number of events to generate")
):
    """Trigger mock event ingestion with normalization"""
    service = get_ingestion_service()
    result = service.run(count=count)
    return result

@router.get("/events")
async def get_events():
    """Get all received raw events"""
    service = get_ingestion_service()
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
async def get_normalized_events():
    """Get all normalized events (ACIP Internal format)"""
    service = get_ingestion_service()
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
                "actor_ip": e.actor_ip,  # ✅ FIXED: was "source_ip"
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
@router.post("/clear")
async def clear_events():
    """Clear all events"""
    service = get_ingestion_service()
    service.clear()
    return {"message": "All events cleared"}

@router.get("/stats")
async def get_stats():
    """Get ingestion statistics"""
    service = get_ingestion_service()
    return service.get_stats()