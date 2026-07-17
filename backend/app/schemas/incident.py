from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict
from uuid import UUID

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    source_type: str
    source_id: Optional[str] = None
    extra_data: Optional[Dict] = {}

class IncidentCreate(IncidentBase):
    pass

class IncidentResponse(IncidentBase):
    id: UUID
    status: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True