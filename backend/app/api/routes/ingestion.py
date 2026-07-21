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
    """Trigger mock event ingestion"""
    service = get_ingestion_service()
    result = service.run(count=count)
    return result

@router.get("/events")
async def get_events():
    """Get all received events"""
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

@router.post("/clear")
async def clear_events():
    """Clear all received events"""
    service = get_ingestion_service()
    service.clear()
    return {"message": "All events cleared"}

@router.get("/stats")
async def get_stats():
    """Get ingestion statistics"""
    service = get_ingestion_service()
    return service.get_stats()