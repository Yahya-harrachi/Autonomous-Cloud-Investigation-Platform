# app/api/routes/ai.py
"""
AI Assistant API Routes
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging
from datetime import datetime

from app.ai.orchestrator import llm_orchestrator

from app.services.ollama_service import ollama_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai"])


# ============================================================
# REQUEST MODELS
# ============================================================

class ChatRequest(BaseModel):
    """Chat request model."""
    message: str
    conversation_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None


class ChatResponse(BaseModel):
    """Chat response model."""
    response: str
    conversation_id: str
    timestamp: str
    model: str
    tokens: int


# ============================================================
# HEALTH CHECK
# ============================================================

@router.get("/health")
async def ai_health():
    """Check if the AI service is available."""
    is_available = ollama_service.is_available()
    
    if is_available:
        models = ollama_service.list_models()
        return {
            "status": "available",
            "ollama": "connected",
            "models": models,
            "active_model": "llama3.2:3b"
        }
    else:
        return {
            "status": "unavailable",
            "ollama": "disconnected",
            "error": "Ollama service not available"
        }


# ============================================================
# CHAT ENDPOINT
# ============================================================

@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Send a message to the AI assistant with tool support.
    """
    logger.info(f"AI Chat request: {request.message[:50]}...")
    
    conversation_id = request.conversation_id or f"conv-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    # Process with orchestrator
    result = llm_orchestrator.process_message(
        message=request.message,
        history=request.history or []
    )
    
    if not result.get("success"):
        logger.error(f"AI Chat failed: {result.get('error')}")
        raise HTTPException(status_code=500, detail=result.get("error", "AI service error"))
    
    return ChatResponse(
        response=result.get("response", ""),
        conversation_id=conversation_id,
        timestamp=datetime.utcnow().isoformat(),
        model=result.get("model", "llama3.2:3b"),
        tokens=0  # We'll track this later
    )


# ============================================================
# SYSTEM INFORMATION
# ============================================================

@router.get("/info")
async def ai_info():
    """Get information about the AI system."""
    is_available = ollama_service.is_available()
    
    return {
        "name": "ACIP-AI",
        "version": "1.0.0",
        "phase": "Phase 1 - Local AI Foundation",
        "model": "llama3.2:3b",
        "status": "online" if is_available else "offline",
        "capabilities": [
            "General chat about cloud security",
            "Incident investigation guidance (coming soon)",
            "Evidence analysis (coming soon)",
            "Timeline analysis (coming soon)"
        ]
    }