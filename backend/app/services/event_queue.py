"""
Event Queue - Async queue for broadcasting events to WebSocket
"""
import asyncio
import logging
from typing import Dict, Any
from collections import deque

logger = logging.getLogger(__name__)


class EventQueue:
    """
    Async queue that collects events from the SQS consumer
    and broadcasts them to WebSocket clients.
    """
    
    def __init__(self):
        self._queue: deque = deque()
        self._running = False
        self._worker_task: asyncio.Task = None
        self._processor = None
    
    def set_processor(self, processor):
        """Set the WebSocket processor (WebSocketManager)"""
        self._processor = processor
        # Start the worker immediately if we have a processor
        if processor and not self._running:
            self._start_worker()
    
    def add_event(self, event: Dict[str, Any]):
        """Add an event to the queue (called from sync thread)"""
        print(f"📥 Event added to queue: {event.get('event_name', 'unknown')}")
        self._queue.append(event)
        if not self._running:
            self._start_worker()
    
    def _start_worker(self):
        """Start the async worker"""
        if self._running:
            return
        
        self._running = True
        print("🚀 Starting event queue worker...")
        
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            self._worker_task = loop.create_task(self._process_queue())
        except RuntimeError as e:
            print(f"⚠️ No event loop, creating one: {e}")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._worker_task = loop.create_task(self._process_queue())
    
    async def _process_queue(self):
        """Process events from the queue"""
        print("📡 Event queue worker started")
        
        while self._running or self._queue:
            if not self._queue:
                await asyncio.sleep(0.1)
                continue
            
            # Get next event
            event = self._queue.popleft()
            print(f"📤 Processing event from queue: {event.get('event_name', 'unknown')}")
            
            # Broadcast to WebSocket
            if self._processor:
                try:
                    await self._processor.broadcast_event(event)
                    print(f"✅ Broadcasted event: {event.get('event_name')}")
                except Exception as e:
                    print(f"❌ Error broadcasting event: {e}")
            else:
                print("⚠️ No WebSocket processor set!")
        
        print("📡 Event queue worker stopped")
        self._running = False
    
    def stop(self):
        """Stop the event queue worker"""
        self._running = False
        if self._worker_task:
            try:
                self._worker_task.cancel()
            except:
                pass


# Singleton instance
event_queue = EventQueue()