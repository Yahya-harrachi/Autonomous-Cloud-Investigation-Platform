"""
Debug endpoints for AWS CloudTrail
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import logging

from ....infrastructure.clients.aws_client import AWSClient
from ....infrastructure.connectors.cloudtrail_connector import CloudTrailConnector, CloudTrailConnectorError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/debug/cloudtrail", tags=["debug"])

def get_cloudtrail_connector():
    """Dependency for CloudTrail connector"""
    try:
        aws_client = AWSClient()
        return CloudTrailConnector(aws_client)
    except Exception as e:
        logger.error(f"Failed to create CloudTrail connector: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to connect to AWS: {str(e)}"
        )

@router.get("/events")
async def get_cloudtrail_events(
    count: int = Query(10, description="Number of events to retrieve (max 100)", ge=1, le=100),
    event_name: Optional[str] = Query(None, description="Filter by event name (e.g., ConsoleLogin)"),
    username: Optional[str] = Query(None, description="Filter by username"),
    event_source: Optional[str] = Query(None, description="Filter by event source (e.g., ec2.amazonaws.com)"),
    hours_back: int = Query(24, description="Look back hours for events", ge=1, le=168),
):
    """
    Debug endpoint: Retrieve real CloudTrail events from AWS.
    
    This endpoint is for testing and debugging only.
    It returns raw CloudTrail events in a readable format.
    """
    try:
        connector = get_cloudtrail_connector()
        
        # Calculate start time
        from datetime import datetime, timedelta
        start_time = datetime.utcnow() - timedelta(hours=hours_back)
        
        # Fetch events
        events = connector.fetch_events(
            max_results=count,
            start_time=start_time,
            end_time=datetime.utcnow(),
            event_name=event_name,
            username=username,
            event_source=event_source,
        )
        
        # Get account info
        aws_client = AWSClient()
        account_id = aws_client.get_account_id()
        
        # Build response
        return {
            "source": "aws_cloudtrail",
            "account_id": account_id,
            "region": aws_client.region,
            "total_events": len(events),
            "filters": {
                "event_name": event_name,
                "username": username,
                "event_source": event_source,
                "hours_back": hours_back,
            },
            "events": [
                {
                    "event_id": e.get("EventId"),
                    "event_name": e.get("EventName"),
                    "event_source": e.get("EventSource"),
                    "event_time": e.get("EventTime"),
                    "username": e.get("Username"),
                    "region": e.get("AwsRegion"),
                    "resources": e.get("Resources", []),
                    "cloudtrail_event": e.get("CloudTrailEvent", {}),
                    "summary": connector.get_event_summary(e),
                }
                for e in events
            ],
        }
        
    except CloudTrailConnectorError as e:
        logger.error(f"CloudTrail connector error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.get("/health")
async def check_cloudtrail_health():
    """
    Check if CloudTrail connector is healthy.
    """
    try:
        connector = get_cloudtrail_connector()
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