"""
Abstract interface for all event connectors
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

class EventConnector(ABC):
    """Abstract base class for all event connectors"""
    
    @abstractmethod
    def fetch_events(
        self,
        max_results: int = 50,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        event_name: Optional[str] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Fetch events from the source.
        
        Args:
            max_results: Maximum number of events to return
            start_time: Start time filter (ISO format)
            end_time: End time filter (ISO format)
            event_name: Filter by event name
            **kwargs: Additional provider-specific filters
            
        Returns:
            List of raw event dictionaries
        """
        pass
    
    @abstractmethod
    def get_provider(self) -> str:
        """Return provider name"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the connector can connect to the provider"""
        pass