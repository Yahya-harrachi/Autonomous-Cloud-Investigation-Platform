# app/ai/tools.py
"""
AI Tool Registry - Defines controlled tools for the AI assistant
"""
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json

from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.incident import IncidentModel
from app.models.evidence import EvidenceArtifact
from app.domain.models.incident import IncidentStatus, IncidentPriority
from app.evidence.collectors.base import parse_incident_id

logger = logging.getLogger(__name__)


@dataclass
class Tool:
    """Definition of a tool that the AI can use."""
    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Callable
    require_auth: bool = True
    read_only: bool = True


class ToolRegistry:
    """
    Registry of all tools available to the AI assistant.
    All tools are read-only and controlled by the backend.
    """
    
    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        self._register_tools()
    
    def _register_tools(self):
        """Register all available tools."""
        
        # Tool 1: Search Incidents
        self.register(Tool(
            name="search_incidents",
            description="Search for security incidents with optional filters",
            parameters={
                "severity": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                    "description": "Filter by severity levels"
                },
                "status": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["pending", "investigating", "completed", "resolved"]},
                    "description": "Filter by status"
                },
                "date_from": {
                    "type": "string",
                    "format": "date-time",
                    "description": "Start date for incident search"
                },
                "date_to": {
                    "type": "string",
                    "format": "date-time",
                    "description": "End date for incident search"
                },
                "search_term": {
                    "type": "string",
                    "description": "Search term to match against title, description, or tags"
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 20,
                    "description": "Maximum number of results to return"
                }
            },
            handler=self._search_incidents
        ))
        
        # Tool 2: Get Incident Details
        self.register(Tool(
            name="get_incident",
            description="Get detailed information about a specific incident",
            parameters={
                "incident_id": {
                    "type": "string",
                    "description": "The ID of the incident to retrieve (e.g., inc-abc123 or UUID)"
                }
            },
            handler=self._get_incident
        ))
        
        # Tool 3: Get Incident Stats
        self.register(Tool(
            name="get_incident_stats",
            description="Get summary statistics for incidents",
            parameters={},
            handler=self._get_incident_stats
        ))
    
    def register(self, tool: Tool):
        """Register a tool."""
        self._tools[tool.name] = tool
        logger.info(f"✅ Registered tool: {tool.name}")
    
    def get_tool(self, name: str) -> Optional[Tool]:
        """Get a tool by name."""
        return self._tools.get(name)
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools with their schemas."""
        tools = []
        for name, tool in self._tools.items():
            tools.append({
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters
            })
        return tools
    
    # ============================================================
    # TOOL HANDLERS
    # ============================================================
    
    def _search_incidents(self, **kwargs) -> Dict[str, Any]:
        """
        Search for incidents with optional filters.
        
        Args:
            severity: List of severity levels
            status: List of status values
            date_from: Start date
            date_to: End date
            search_term: Text search
            limit: Max results
            
        Returns:
            Dict with incidents and metadata
        """
        db = next(get_db())
        try:
            query = db.query(IncidentModel)
            
            # Apply severity filter
            if kwargs.get('severity'):
                try:
                    priorities = [IncidentPriority(s.upper()) for s in kwargs['severity']]
                    query = query.filter(IncidentModel.priority.in_(priorities))
                except ValueError:
                    pass
            
            # Apply status filter
            if kwargs.get('status'):
                try:
                    statuses = [IncidentStatus(s.lower()) for s in kwargs['status']]
                    query = query.filter(IncidentModel.status.in_(statuses))
                except ValueError:
                    pass
            
            # Apply date filter
            if kwargs.get('date_from'):
                try:
                    date_from = datetime.fromisoformat(kwargs['date_from'])
                    query = query.filter(IncidentModel.created_at >= date_from)
                except ValueError:
                    pass
            
            if kwargs.get('date_to'):
                try:
                    date_to = datetime.fromisoformat(kwargs['date_to'])
                    query = query.filter(IncidentModel.created_at <= date_to)
                except ValueError:
                    pass
            
            # Apply search term
            if kwargs.get('search_term'):
                search = f"%{kwargs['search_term']}%"
                query = query.filter(
                    IncidentModel.title.ilike(search) |
                    IncidentModel.description.ilike(search) |
                    IncidentModel.tags.cast(str).ilike(search)
                )
            
            # Apply limit
            limit = kwargs.get('limit', 20)
            incidents = query.order_by(
                IncidentModel.created_at.desc()
            ).limit(limit).all()
            
            # Format results
            results = []
            for incident in incidents:
                results.append({
                    "id": str(incident.id),
                    "display_id": f"inc-{str(incident.id)[:12]}",
                    "title": incident.title,
                    "description": incident.description[:200] + "..." if len(incident.description) > 200 else incident.description,
                    "priority": incident.priority.value if incident.priority else "UNKNOWN",
                    "status": incident.status.value if incident.status else "pending",
                    "source_type": incident.source_type,
                    "tags": incident.tags or [],
                    "evidence_count": incident.evidence_count or 0,
                    "created_at": incident.created_at.isoformat() if incident.created_at else None,
                    "assigned_to": incident.assigned_to
                })
            
            return {
                "success": True,
                "count": len(results),
                "incidents": results,
                "total": len(results)
            }
            
        except Exception as e:
            logger.error(f"Error searching incidents: {e}")
            return {
                "success": False,
                "error": str(e),
                "count": 0,
                "incidents": []
            }
        finally:
            db.close()
    
    def _get_incident(self, **kwargs) -> Dict[str, Any]:
        """
        Get detailed information about a specific incident.
        
        Args:
            incident_id: The ID of the incident
            
        Returns:
            Incident details with evidence summary
        """
        incident_id = kwargs.get('incident_id')
        if not incident_id:
            return {
                "success": False,
                "error": "incident_id is required"
            }
        
        db = next(get_db())
        try:
            # Parse incident ID
            try:
                incident_uuid = parse_incident_id(incident_id)
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Invalid incident ID: {str(e)}"
                }
            
            # Get incident
            incident = db.query(IncidentModel).filter(
                IncidentModel.id == incident_uuid
            ).first()
            
            if not incident:
                return {
                    "success": False,
                    "error": f"Incident not found: {incident_id}"
                }
            
            # Get evidence summary
            evidence_count = db.query(EvidenceArtifact).filter(
                EvidenceArtifact.incident_id == incident_uuid
            ).count()
            
            evidence_types = db.query(
                EvidenceArtifact.artifact_type,
                EvidenceArtifact.collection_status
            ).filter(
                EvidenceArtifact.incident_id == incident_uuid
            ).all()
            
            evidence_summary = {}
            for ev_type, status in evidence_types:
                if ev_type not in evidence_summary:
                    evidence_summary[ev_type] = {"total": 0, "completed": 0, "failed": 0}
                evidence_summary[ev_type]["total"] += 1
                if status == "COMPLETED":
                    evidence_summary[ev_type]["completed"] += 1
                elif status == "FAILED":
                    evidence_summary[ev_type]["failed"] += 1
            
            return {
                "success": True,
                "incident": {
                    "id": str(incident.id),
                    "display_id": f"inc-{str(incident.id)[:12]}",
                    "title": incident.title,
                    "description": incident.description,
                    "priority": incident.priority.value if incident.priority else "UNKNOWN",
                    "status": incident.status.value if incident.status else "pending",
                    "source_type": incident.source_type,
                    "source_event_id": incident.source_event_id,
                    "tags": incident.tags or [],
                    "extra_data": incident.extra_data or {},
                    "assigned_to": incident.assigned_to,
                    "assigned_team": incident.assigned_team,
                    "evidence_count": evidence_count,
                    "evidence_summary": evidence_summary,
                    "created_at": incident.created_at.isoformat() if incident.created_at else None,
                    "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
                    "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting incident: {e}")
            return {
                "success": False,
                "error": str(e)
            }
        finally:
            db.close()
    
    def _get_incident_stats(self, **kwargs) -> Dict[str, Any]:
        """
        Get summary statistics for incidents.
        
        Returns:
            Statistics about incidents
        """
        db = next(get_db())
        try:
            total = db.query(IncidentModel).count()
            pending = db.query(IncidentModel).filter(
                IncidentModel.status == IncidentStatus.PENDING
            ).count()
            investigating = db.query(IncidentModel).filter(
                IncidentModel.status == IncidentStatus.INVESTIGATING
            ).count()
            completed = db.query(IncidentModel).filter(
                IncidentModel.status == IncidentStatus.COMPLETED
            ).count()
            resolved = db.query(IncidentModel).filter(
                IncidentModel.status == IncidentStatus.RESOLVED
            ).count()
            
            # Priority breakdown
            critical = db.query(IncidentModel).filter(
                IncidentModel.priority == IncidentPriority.CRITICAL
            ).count()
            high = db.query(IncidentModel).filter(
                IncidentModel.priority == IncidentPriority.HIGH
            ).count()
            medium = db.query(IncidentModel).filter(
                IncidentModel.priority == IncidentPriority.MEDIUM
            ).count()
            low = db.query(IncidentModel).filter(
                IncidentModel.priority == IncidentPriority.LOW
            ).count()
            
            return {
                "success": True,
                "stats": {
                    "total": total,
                    "pending": pending,
                    "investigating": investigating,
                    "completed": completed,
                    "resolved": resolved,
                    "by_priority": {
                        "critical": critical,
                        "high": high,
                        "medium": medium,
                        "low": low
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting incident stats: {e}")
            return {
                "success": False,
                "error": str(e)
            }
        finally:
            db.close()


# Singleton instance
tool_registry = ToolRegistry()