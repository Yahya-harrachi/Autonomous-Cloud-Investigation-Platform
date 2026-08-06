"""
SQS Consumer Management API Routes
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from ...services.sqs_consumer import get_consumer, start_consumer, stop_consumer

router = APIRouter(prefix="/api/sqs", tags=["sqs"])


@router.post("/start")
async def start_sqs_consumer() -> Dict[str, Any]:
    """Start the SQS consumer"""
    try:
        consumer = start_consumer()
        return {
            "message": "SQS Consumer started",
            "stats": consumer.get_stats()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_sqs_consumer() -> Dict[str, Any]:
    """Stop the SQS consumer"""
    try:
        stop_consumer()
        return {"message": "SQS Consumer stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_sqs_status() -> Dict[str, Any]:
    """Get SQS consumer status"""
    try:
        consumer = get_consumer()
        return consumer.get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/broadcast-test")
async def broadcast_test_event():
    """Test endpoint to broadcast a test event to WebSocket"""
    from ...services.websocket_manager import websocket_manager
    import asyncio
    
    test_event = {
        "event_id": "test-123",
        "event_name": "TestBroadcast",
        "actor": "test-user",
        "severity": "INFO",
        "severity_score": 10,
        "timestamp": "2026-08-05T10:00:00Z",
        "region": "us-east-1",
        "actor_ip": "8.8.8.8",
    }
    
    # Broadcast to WebSocket
    asyncio.create_task(websocket_manager.broadcast_event(test_event))
    
    return {
        "message": "Test event broadcasted",
        "event": test_event,
        "connections": len(websocket_manager.active_connections)
    }