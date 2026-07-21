"""
Normalizers package - converts provider events to ACIP internal format
"""
from .base import Normalizer
from .aws_normalizer import AWSNormalizer
from .azure_normalizer import AzureNormalizer
from .gcp_normalizer import GCPNormalizer


class NormalizerFactory:
    """
    Factory that returns the correct normalizer for each provider.
    """
    
    def __init__(self):
        # Register all normalizers
        self._normalizers = [
            AWSNormalizer(),
            AzureNormalizer(),
            GCPNormalizer(),
        ]
    
    def get_normalizer(self, raw_event) -> Normalizer:
        """
        Find the right normalizer for the event.
        """
        for normalizer in self._normalizers:
            if normalizer.can_normalize(raw_event):
                return normalizer
        raise ValueError(f"No normalizer found for provider: {raw_event.source}")
    
    def normalize(self, raw_event):
        """
        Normalize an event using the correct normalizer.
        """
        normalizer = self.get_normalizer(raw_event)
        return normalizer.normalize(raw_event)