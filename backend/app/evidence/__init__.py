# app/evidence/collectors/__init__.py
"""
Evidence Collectors Module
"""
from app.evidence.collectors.base import BaseCollector
from app.evidence.collectors.cloudtrail_collector import CloudTrailCollector

__all__ = [
    'BaseCollector',
    'CloudTrailCollector',
]