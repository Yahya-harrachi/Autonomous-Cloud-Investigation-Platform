"""
Ingestion service orchestrates the flow
"""
from ...infrastructure.sources.mock_source import MockEventSource
from ...infrastructure.receivers.console_receiver import ConsoleReceiver


class IngestionService:
    """Orchestrates event ingestion"""
    
    def __init__(self):
        self.source = MockEventSource()
        self.receiver = ConsoleReceiver()
        self.total_processed = 0
    
    def run(self, count: int = 3) -> dict:
        """
        Run the ingestion pipeline
        Returns stats about what was processed
        """
        # Get events from source
        events = self.source.get_events(count=count)
        
        # Send each event to receiver
        for event in events:
            self.receiver.receive(event)
            self.total_processed += 1
        
        return {
            "message": f"✅ Processed {len(events)} events",
            "events_processed": len(events),
            "total_processed": self.total_processed,
            "source": "mock",
            "events": [
                {
                    "source": e.source,
                    "event_type": e.event_type,
                    "timestamp": e.timestamp.isoformat()
                }
                for e in events
            ]
        }
    
    def get_stats(self) -> dict:
        """Get ingestion statistics"""
        return {
            "total_processed": self.total_processed,
            "events_in_buffer": len(self.receiver.get_all()),
            "source": "mock"
        }
    
    def get_events(self) -> list:
        """Get all received events"""
        return self.receiver.get_all()
    
    def clear(self) -> None:
        """Clear all events"""
        self.receiver.clear()
        self.total_processed = 0