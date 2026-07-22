"""
Ingestion service orchestrates the flow with PostgreSQL storage
"""
from sqlalchemy.orm import Session
from ...infrastructure.sources.mock_source import MockEventSource
from ...infrastructure.receivers.console_receiver import ConsoleReceiver
from ...infrastructure.normalizers import NormalizerFactory
from ...infrastructure.incident_creators.default_incident_creator import DefaultIncidentCreator
from ...infrastructure.repositories.incident_repository import IncidentRepository
from ...models.incident import IncidentModel

class IngestionService:
    """Orchestrates event ingestion with PostgreSQL storage"""
    
    def __init__(self, db_session: Session = None):
        self.source = MockEventSource()
        self.receiver = ConsoleReceiver()
        self.normalizer_factory = NormalizerFactory()
        self.incident_creator = DefaultIncidentCreator()
        self.db_session = db_session
        
        # In-memory storage (always works)
        self.total_processed = 0
        self.normalized_events = []
        self.incidents = []  # In-memory storage
    
    def run(self, count: int = 3) -> dict:
        """
        Run the ingestion pipeline with PostgreSQL storage.
        """
        # 1. Get raw events from source
        raw_events = self.source.get_events(count=count)
        
        created_incidents = []
        
        # 2. Process each event
        for raw_event in raw_events:
            # Receive
            self.receiver.receive(raw_event)
            
            # Normalize
            normalized = self.normalizer_factory.normalize(raw_event)
            self.normalized_events.append(normalized)
            
            # 3. Decision: Should this become an incident?
            should_create = self.incident_creator.should_create_incident(normalized)
            
            if should_create:
                # 4. Create incident (domain object)
                incident = self.incident_creator.create_incident(normalized)
                
                # 5. STORE IN MEMORY (always works)
                self.incidents.append(incident)
                created_incidents.append(incident)
                print(f"✅ Incident stored in memory: {incident.id}")
                
                # 6. STORE IN POSTGRESQL (if session available)
                if self.db_session:
                    try:
                        repo = IncidentRepository(self.db_session)
                        saved = repo.save(incident)
                        print(f"✅ Incident saved to PostgreSQL: {saved.id}")
                    except Exception as e:
                        print(f"❌ Error saving to PostgreSQL: {e}")
                        # Continue - data is already in memory
                else:
                    print("⚠️ No DB session - incident only in memory")
                
                # Print incident creation
                print("\n" + "="*70)
                print("🚨 NEW INCIDENT CREATED!")
                print("="*70)
                print(f"ID:          {incident.id}")
                print(f"Title:       {incident.title}")
                print(f"Priority:    {incident.priority.value.upper()}")
                print(f"Status:      {incident.status.value}")
                print(f"Source:      {incident.source_type}")
                print(f"Tags:        {', '.join(incident.tags)}")
                print(f"Stored in:   {'Memory + PostgreSQL' if self.db_session else 'Memory only'}")
                print("="*70 + "\n")
            
            self.total_processed += 1
        
        # 7. Return results
        return {
            "message": f"✅ Processed {len(raw_events)} events",
            "events_processed": len(raw_events),
            "incidents_created": len(created_incidents),
            "total_processed": self.total_processed,
            "source": "mock",
            "storage": "Memory + PostgreSQL" if self.db_session else "Memory only",
            "incidents": [
                {
                    "id": i.id,
                    "title": i.title,
                    "priority": i.priority.value,
                    "status": i.status.value,
                    "source_type": i.source_type,
                    "stored_in": "Memory + PostgreSQL" if self.db_session else "Memory only"
                }
                for i in created_incidents
            ]
        }
    
    def get_stats(self) -> dict:
        """Get ingestion statistics"""
        return {
            "total_processed": self.total_processed,
            "events_in_buffer": len(self.receiver.get_all()),
            "normalized_events": len(self.normalized_events),
            "incidents_in_memory": len(self.incidents),
            "source": "mock",
            "has_db_session": self.db_session is not None
        }
    
    def get_events(self) -> list:
        """Get all received raw events"""
        return self.receiver.get_all()
    
    def get_normalized_events(self) -> list:
        """Get all normalized events"""
        return self.normalized_events
    
    def get_incidents(self) -> list:
        """Get all created incidents (from memory)"""
        return self.incidents
    
    def clear(self) -> None:
        """Clear all events and incidents"""
        self.receiver.clear()
        self.normalized_events.clear()
        self.incidents.clear()
        self.total_processed = 0
        
        # Also clear PostgreSQL if session exists
        if self.db_session:
            try:
                repo = IncidentRepository(self.db_session)
                # Delete all incidents
                self.db_session.query(IncidentModel).delete()
                self.db_session.commit()
                print("✅ PostgreSQL cleared")
            except Exception as e:
                print(f"❌ Error clearing PostgreSQL: {e}")