"""
Debug routes for development and testing
"""
from .cloudtrail import router as cloudtrail_router
from .cloudtrail_normalized import router as cloudtrail_normalized_router  

__all__ = [
    "cloudtrail_router",
    "cloudtrail_normalized_router"
]