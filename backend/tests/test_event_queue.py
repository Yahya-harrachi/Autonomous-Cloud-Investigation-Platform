"""
Test Event Queue
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from app.services.event_queue import event_queue
from app.services.websocket_manager import websocket_manager


async def test_event_queue():
    """Test the event queue"""
    print("🧪 Testing event queue...")
    
    # Set processor
    event_queue.set_processor(websocket_manager)
    
    # Add a test event
    test_event = {
        "event_name": "TestEvent",
        "actor": "test-user",
        "severity": "INFO",
        "timestamp": "2026-08-05T10:00:00Z"
    }
    
    print(f"📥 Adding event: {test_event['event_name']}")
    event_queue.add_event(test_event)
    
    # Wait for processing
    await asyncio.sleep(2)
    print("✅ Test complete")


if __name__ == "__main__":
    asyncio.run(test_event_queue())