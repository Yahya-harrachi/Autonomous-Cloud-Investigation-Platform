"""
WebSocket Routes - Real-time event streaming
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ...services.websocket_manager import websocket_manager
import json
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    WebSocket endpoint for real-time events.
    
    Clients connect to: ws://localhost:8000/ws/events
    """
    print("🔌 WebSocket connection attempt")
    await websocket_manager.connect(websocket)
    
    try:
        print("✅ WebSocket connected, waiting for messages...")
        # Keep connection alive and listen for messages from client
        while True:
            # Wait for messages from client (heartbeat, etc.)
            data = await websocket.receive_text()
            print(f"📩 Received from client: {data}")
            
            # Handle ping/pong
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
                print("✅ Sent pong")
            
            # Client can request historical events
            elif data.startswith('{"type": "get_recent"'):
                # TODO: Send recent events
                pass
    
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
        print("❌ WebSocket disconnected")
    except Exception as e:
        print(f"❌ WebSocket error: {e}")
        websocket_manager.disconnect(websocket)


