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