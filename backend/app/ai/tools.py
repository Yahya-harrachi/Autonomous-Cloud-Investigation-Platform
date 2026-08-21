# app/ai/tools.py
"""
AI Tool Registry - Defines controlled tools for the AI assistant
"""
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import uuid
import re

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
            description="Search for security incidents with optional filters like severity, status, date range, or search term",
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
            description="Get detailed information about a specific incident by ID",
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
            description="Get summary statistics for all incidents",
            parameters={},
            handler=self._get_incident_stats
        ))

        # Tool 4: Get Incident Evidence
        self.register(Tool(
            name="get_incident_evidence",
            description="Get all evidence artifacts for a specific incident",
            parameters={
                "incident_id": {
                    "type": "string",
                    "description": "The ID of the incident (e.g., inc-abc123 or UUID)"
                }
            },
            handler=self._get_incident_evidence
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
            
            # Apply search term
            if kwargs.get('search_term'):
                search = f"%{kwargs['search_term']}%"
                query = query.filter(
                    IncidentModel.title.ilike(search) |
                    IncidentModel.description.ilike(search)
                )
            
            # Apply limit
            limit = kwargs.get('limit', 20)
            incidents = query.order_by(
                IncidentModel.created_at.desc()
            ).limit(limit).all()
            
            # Format results
            results = []
            for incident in incidents:
                priority_value = incident.priority.value if incident.priority else "UNKNOWN"
                
                results.append({
                    "id": str(incident.id),
                    "display_id": f"inc-{str(incident.id)[:12]}",
                    "title": incident.title,
                    "description": incident.description[:200] + "..." if len(incident.description) > 200 else incident.description,
                    "priority": priority_value.upper(),
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
        """
        incident_id = kwargs.get('incident_id')
        if not incident_id:
            return {
                "success": False,
                "error": "incident_id is required"
            }
        
        db = next(get_db())
        try:
            # Try to find the incident by various ID formats
            incident = None
            
            # METHOD 1: Check if it's a display ID (inc-xxx format)
            if incident_id.startswith('inc-'):
                display_suffix = incident_id[4:]
                
                # Search for incident where display ID matches
                all_incidents = db.query(IncidentModel).all()
                for inc in all_incidents:
                    inc_display = f"inc-{str(inc.id)[:12]}"
                    if inc_display == incident_id:
                        incident = inc
                        break
                
                if not incident and display_suffix:
                    for inc in all_incidents:
                        if str(inc.id).startswith(display_suffix):
                            incident = inc
                            break
                
                if not incident:
                    return {
                        "success": False,
                        "error": f"Incident not found with ID: {incident_id}"
                    }
            
            # METHOD 2: Try as full UUID
            else:
                try:
                    incident_uuid = parse_incident_id(incident_id)
                    incident = db.query(IncidentModel).filter(
                        IncidentModel.id == incident_uuid
                    ).first()
                except Exception:
                    if len(incident_id) == 12:
                        all_incidents = db.query(IncidentModel).all()
                        for inc in all_incidents:
                            inc_display = f"inc-{str(inc.id)[:12]}"
                            if inc_display == f"inc-{incident_id}":
                                incident = inc
                                break
                
                if not incident:
                    return {
                        "success": False,
                        "error": f"Incident not found: {incident_id}"
                    }
            
            # Get evidence summary
            evidence_count = db.query(EvidenceArtifact).filter(
                EvidenceArtifact.incident_id == incident.id
            ).count()
            
            evidence_types = db.query(
                EvidenceArtifact.artifact_type,
                EvidenceArtifact.collection_status
            ).filter(
                EvidenceArtifact.incident_id == incident.id
            ).all()
            
            evidence_summary = {}
            for ev_type, status in evidence_types:
                if ev_type not in evidence_summary:
                    evidence_summary[ev_type] = {"total": 0, "completed": 0, "failed": 0, "pending": 0}
                evidence_summary[ev_type]["total"] += 1
                if status == "COMPLETED":
                    evidence_summary[ev_type]["completed"] += 1
                elif status == "FAILED":
                    evidence_summary[ev_type]["failed"] += 1
                elif status == "PENDING":
                    evidence_summary[ev_type]["pending"] += 1
            
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


    def _get_incident_evidence(self, **kwargs) -> Dict[str, Any]:
        """
        Get all evidence artifacts for a specific incident.
        
        Args:
            incident_id: The ID of the incident
            
        Returns:
            Evidence artifacts with details
        """
        incident_id = kwargs.get('incident_id')
        if not incident_id:
            return {
                "success": False,
                "error": "incident_id is required"
            }
        
        db = next(get_db())
        try:
            # Find the incident first
            incident = None
            
            # Try as display ID
            if incident_id.startswith('inc-'):
                display_suffix = incident_id[4:]
                all_incidents = db.query(IncidentModel).all()
                for inc in all_incidents:
                    inc_display = f"inc-{str(inc.id)[:12]}"
                    if inc_display == incident_id:
                        incident = inc
                        break
                
                if not incident and display_suffix:
                    for inc in all_incidents:
                        if str(inc.id).startswith(display_suffix):
                            incident = inc
                            break
            
            # Try as UUID
            if not incident:
                try:
                    incident_uuid = parse_incident_id(incident_id)
                    incident = db.query(IncidentModel).filter(
                        IncidentModel.id == incident_uuid
                    ).first()
                except Exception:
                    pass
            
            if not incident:
                return {
                    "success": False,
                    "error": f"Incident not found: {incident_id}"
                }
            
            # Get all evidence artifacts
            artifacts = db.query(EvidenceArtifact).filter(
                EvidenceArtifact.incident_id == incident.id
            ).all()
            
            # Format evidence
            evidence_list = []
            for artifact in artifacts:
                artifact_data = {
                    "id": str(artifact.id),
                    "artifact_type": artifact.artifact_type,
                    "source": artifact.source,
                    "collector": artifact.collector,
                    "collection_status": artifact.collection_status,
                    "collected_at": artifact.collected_at.isoformat() if artifact.collected_at else None,
                    "hash": artifact.hash,
                    "integrity_verified": artifact.integrity_verified,
                    "content": artifact.content
                }
                
                # Add summary based on type
                content = artifact.content or {}
                
                if artifact.artifact_type == 'CloudTrailEvent':
                    summary = content.get('summary', {})
                    timeline = content.get('timeline', [])
                    artifact_data['summary'] = {
                        "total_events": summary.get('total_events', 0),
                        "timeline_events": len(timeline),
                        "patterns_found": summary.get('patterns_found', 0)
                    }
                    if timeline:
                        artifact_data['timeline_preview'] = [
                            {
                                "time": e.get('event_time', 'N/A')[:16] if e.get('event_time') else 'N/A',
                                "event": e.get('event_name', 'Unknown'),
                                "actor": e.get('actor', 'Unknown')
                            }
                            for e in timeline[:5]
                        ]
                
                elif artifact.artifact_type == 'IAMUser':
                    user = content.get('user', {})
                    summary = content.get('summary', {})
                    artifact_data['summary'] = {
                        "user_name": user.get('user_name', 'N/A'),
                        "user_id": user.get('user_id', 'N/A'),
                        "mfa_active": user.get('mfa_active', False),
                        "attached_policies": summary.get('total_attached_policies', 0),
                        "access_keys": summary.get('total_access_keys', 0)
                    }
                
                elif artifact.artifact_type == 'IAMPolicy':
                    policies = content.get('policies', [])
                    security_analysis = content.get('security_analysis', {})
                    artifact_data['summary'] = {
                        "total_policies": len(policies),
                        "high_risk_findings": len(security_analysis.get('high_risk_findings', [])),
                        "policies": [
                            {
                                "name": p.get('policy_name', 'Unknown'),
                                "admin_access": p.get('summary', {}).get('has_administrator_access', False)
                            }
                            for p in policies[:5]
                        ]
                    }
                
                elif artifact.artifact_type == 'IAMRole':
                    roles = content.get('roles', [])
                    artifact_data['summary'] = {
                        "total_roles": len(roles),
                        "roles": [r.get('role_name', 'Unknown') for r in roles[:5]]
                    }
                
                evidence_list.append(artifact_data)
            
            return {
                "success": True,
                "incident_id": incident_id,
                "display_id": f"inc-{str(incident.id)[:12]}",
                "total_evidence": len(evidence_list),
                "evidence": evidence_list
            }
            
        except Exception as e:
            logger.error(f"Error getting incident evidence: {e}")
            return {
                "success": False,
                "error": str(e)
            }
        finally:
            db.close()


# Singleton instance
tool_registry = ToolRegistry()