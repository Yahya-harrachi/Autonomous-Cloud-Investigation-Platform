from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict
from uuid import UUID

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str
    source_type: str
    source_id: Optional[str] = None
    extra_data: Optional[Dict] = {}

class IncidentCreate(IncidentBase):
    pass

class IncidentStatsResponse(BaseModel):
    total: int
    pending: int
    investigating: int
    resolved: int

class IncidentResponse(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    priority: str  # Changed from severity
    status: str
    source_type: str
    source_event_id: Optional[str] = None
    tags: Optional[list] = []
    extra_data: Optional[Dict] = {}
    created_at: datetime
    updated_at: Optional[datetime] = None

    
    class Config:
        from_attributes = True