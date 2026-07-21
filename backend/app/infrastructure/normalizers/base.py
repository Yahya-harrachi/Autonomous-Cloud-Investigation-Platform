"""
Base normalizer interface.
All provider normalizers must implement this.
"""
from abc import ABC, abstractmethod
from ...domain.models.event import RawEvent, NormalizedEvent


class Normalizer(ABC):
    """
    Abstract base class for all normalizers.
    Each provider (AWS, Azure, GCP) has its own implementation.
    """
    
    @abstractmethod
    def normalize(self, raw_event: RawEvent) -> NormalizedEvent:
        """
        Convert a raw event to ACIP Internal format.
        
        Args:
            raw_event: Raw event from provider
            
        Returns:
            NormalizedEvent in ACIP internal format
        """
        pass
    
    @abstractmethod
    def can_normalize(self, raw_event: RawEvent) -> bool:
        """
        Check if this normalizer can handle this event.
        
        Args:
            raw_event: Raw event to check
            
        Returns:
            True if this normalizer can handle it
        """
        pass
    
    @abstractmethod
    def get_provider(self) -> str:
        """Return the provider name (aws, azure, gcp, etc.)"""
        pass