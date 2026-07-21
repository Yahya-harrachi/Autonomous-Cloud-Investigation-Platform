"""
Ingestion service orchestrates the flow
"""
from ...infrastructure.sources.mock_source import MockEventSource
from ...infrastructure.receivers.console_receiver import ConsoleReceiver
from ...infrastructure.normalizers import NormalizerFactory


class IngestionService:
    """Orchestrates event ingestion with normalization"""
    
    def __init__(self):
        self.source = MockEventSource()
        self.receiver = ConsoleReceiver()
        self.normalizer_factory = NormalizerFactory()
        self.total_processed = 0
        self.normalized_events = []  # Store normalized events
    
    def run(self, count: int = 3) -> dict:
        """
        Run the ingestion pipeline with normalization.
        """
        # 1. Get raw events from source
        raw_events = self.source.get_events(count=count)
        
        # 2. Process each event
        for raw_event in raw_events:
            # Receive
            self.receiver.receive(raw_event)
            
            # Normalize
            normalized = self.normalizer_factory.normalize(raw_event)
            self.normalized_events.append(normalized)
            
            self.total_processed += 1
        
        return {
            "message": f"✅ Processed and normalized {len(raw_events)} events",
            "events_processed": len(raw_events),
            "total_processed": self.total_processed,
            "source": "mock",
            "events": [
                {
                    "source": e.source,
                    "event_type": e.event_type,
                    "normalized": {
                        "event_id": n.event_id,
                        "severity": n.severity,
                        "actor": n.actor,
                        "resource": n.resource
                    }
                }
                for e, n in zip(raw_events, self.normalized_events[-len(raw_events):])
            ]
        }
    
    def get_stats(self) -> dict:
        """Get ingestion statistics"""
        return {
            "total_processed": self.total_processed,
            "events_in_buffer": len(self.receiver.get_all()),
            "normalized_events": len(self.normalized_events),
            "source": "mock"
        }
    
    def get_events(self) -> list:
        """Get all received raw events"""
        return self.receiver.get_all()
    
    def get_normalized_events(self) -> list:
        """Get all normalized events"""
        return self.normalized_events
    
    def clear(self) -> None:
        """Clear all events"""
        self.receiver.clear()
        self.normalized_events.clear()
        self.total_processed = 0