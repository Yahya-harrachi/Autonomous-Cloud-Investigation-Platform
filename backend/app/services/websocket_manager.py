"""
WebSocket Manager - Manages WebSocket connections and broadcasts events
"""
import json
import logging
from typing import List, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages WebSocket connections and broadcasts messages to all connected clients.
    """
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._running = True
    
    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"✅ WebSocket connected. Total connections: {len(self.active_connections)}")
        logger.info(f"✅ WebSocket connected. Total connections: {len(self.active_connections)}")
        
        # Send connection confirmation
        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "Connected to ACIP real-time events",
            "total_connections": len(self.active_connections)
        }))
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"❌ WebSocket disconnected. Total connections: {len(self.active_connections)}")
        logger.info(f"❌ WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """
        Broadcast a message to all connected clients.
        
        Args:
            message: Dictionary to send to all clients
        """
        if not self.active_connections:
            print("⚠️ No active connections to broadcast")
            return
        
        message_json = json.dumps(message)
        print(f"📡 Broadcasting to {len(self.active_connections)} clients: {message.get('type', 'unknown')}")
        
        # Send to all connections
        for connection in self.active_connections:
            try:
                await connection.send_text(message_json)
                print(f"✅ Sent to client")
            except Exception as e:
                print(f"❌ Error broadcasting to WebSocket: {e}")
                self.disconnect(connection)
    
    async def broadcast_event(self, event: Dict[str, Any]):
        """
        Broadcast a new event to all connected clients.
        
        Args:
            event: Normalized event dictionary
        """
        print(f"📡 Broadcasting event: {event.get('event_name', 'unknown')}")
        await self.broadcast({
            "type": "new_event",
            "data": event
        })
    
    async def broadcast_incident(self, incident: Dict[str, Any]):
        """
        Broadcast a new incident to all connected clients.
        
        Args:
            incident: Incident dictionary
        """
        await self.broadcast({
            "type": "new_incident",
            "data": incident
        })
    
    async def broadcast_health(self, status: Dict[str, Any]):
        """
        Broadcast health status to all connected clients.
        
        Args:
            status: Health status dictionary
        """
        await self.broadcast({
            "type": "health_update",
            "data": status
        })
    
    async def close_all(self):
        """Close all connections"""
        self._running = False
        for connection in self.active_connections:
            try:
                await connection.close()
            except:
                pass
        self.active_connections.clear()


# Singleton instance
websocket_manager = WebSocketManager()