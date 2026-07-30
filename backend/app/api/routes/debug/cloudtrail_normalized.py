"""
Debug endpoints for normalized CloudTrail events
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import logging
from datetime import datetime, timedelta, timezone

from ....infrastructure.clients.aws_client import AWSClient
from ....infrastructure.connectors.cloudtrail_connector import CloudTrailConnector
from ....infrastructure.normalizers.aws_normalizer import AWSNormalizer
from ....domain.models.event import RawEvent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/debug/cloudtrail", tags=["debug"])


@router.get("/normalized")
async def get_normalized_cloudtrail_events(
    count: int = Query(10, description="Number of events to retrieve", ge=1, le=50),
    hours_back: int = Query(24, description="Hours back to look", ge=1, le=168),
):
    """
    Debug endpoint: Retrieve and normalize CloudTrail events.
    """
    try:
        # 1. Initialize AWS Client and Connector
        aws_client = AWSClient()
        connector = CloudTrailConnector(aws_client)
        
        # 2. Fetch raw events
        start_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        raw_events = connector.fetch_events(
            max_results=count,
            start_time=start_time,
            end_time=datetime.utcnow(),
        )
        
        # 3. Normalize each event
        normalizer = AWSNormalizer()
        normalized_events = []
        errors = []
        
        for idx, raw_event in enumerate(raw_events):
            try:
                # ✅ FIX: Handle None/Null event_time safely
                event_time = raw_event.get("EventTime")
                
                # If event_time is None or "null", use current time
                if not event_time or event_time == "null":
                    timestamp = datetime.now(timezone.utc)
                else:
                    # Try to parse the timestamp
                    try:
                        # Remove "Z" and replace with "+00:00" for ISO parsing
                        clean_time = event_time.replace("Z", "+00:00")
                        timestamp = datetime.fromisoformat(clean_time)
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Could not parse timestamp '{event_time}': {e}")
                        timestamp = datetime.now(timezone.utc)
                
                # Create RawEvent
                raw_event_obj = RawEvent(
                    source="aws",
                    provider="cloudtrail",
                    event_type=raw_event.get("EventName", "unknown"),
                    data=raw_event,
                    timestamp=timestamp,
                    received_at=datetime.now(timezone.utc),
                )
                
                # Normalize
                normalized = normalizer.normalize(raw_event_obj)
                
                # Convert to dict
                normalized_dict = normalized.to_dict()
                if hasattr(normalized, 'metadata') and normalized.metadata:
                    normalized_dict['identity_type'] = normalized.metadata.get('identity_type', 'unknown')
                
                normalized_events.append(normalized_dict)
                
            except Exception as e:
                import traceback
                error_msg = f"Event #{idx+1} ({raw_event.get('EventName', 'unknown')}): {str(e)}"
                errors.append(error_msg)
                logger.error(f"Error normalizing event: {error_msg}")
                logger.error(f"Full traceback:\n{traceback.format_exc()}")
        
        # 4. Build response
        return {
            "source": "aws_cloudtrail_normalized",
            "account_id": aws_client.get_account_id(),
            "region": aws_client.region,
            "total_raw": len(raw_events),
            "total_normalized": len(normalized_events),
            "errors": errors if errors else None,
            "events": normalized_events,
        }
        
    except Exception as e:
        import traceback
        logger.error(f"Error in normalized endpoint: {str(e)}")
        logger.error(f"Full traceback:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/normalized/health")
async def check_normalized_health():
    """
    Check if the normalized endpoint is working.
    """
    try:
        aws_client = AWSClient()
        connector = CloudTrailConnector(aws_client)
        is_available = connector.is_available()
        
        return {
            "status": "healthy" if is_available else "unhealthy",
            "provider": connector.get_provider(),
            "available": is_available,
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
        }