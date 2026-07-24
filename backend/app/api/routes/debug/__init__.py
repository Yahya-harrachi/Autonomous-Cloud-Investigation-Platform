"""
Debug routes for development and testing
"""
from .cloudtrail import router as cloudtrail_router

__all__ = ["cloudtrail_router"]