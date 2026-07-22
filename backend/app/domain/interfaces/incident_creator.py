"""
Abstract interface for incident creation
"""
from abc import ABC, abstractmethod
from ..models.event import NormalizedEvent
from ...domain.models.incident import Incident


class IncidentCreator(ABC):
    """
    Abstract base class for incident creators.
    Determines if an event becomes an incident and creates it.
    """
    
    @abstractmethod
    def should_create_incident(self, normalized_event: NormalizedEvent) -> bool:
        """
        Decision engine: Should this event become an incident?
        
        Args:
            normalized_event: The normalized event
            
        Returns:
            True if incident should be created
        """
        pass
    
    @abstractmethod
    def create_incident(self, normalized_event: NormalizedEvent) -> Incident:
        """
        Create an incident from a normalized event.
        
        Args:
            normalized_event: The normalized event
            
        Returns:
            Incident object
        """
        pass
    
    @abstractmethod
    def get_decision_reason(self, normalized_event: NormalizedEvent) -> str:
        """
        Return the reason why an incident was or wasn't created.
        
        Args:
            normalized_event: The normalized event
            
        Returns:
            Human readable reason
        """
        pass