# app/evidence/collectors/cloudtrail_collector.py
"""
CloudTrail Collector - Collects CloudTrail evidence for incidents
"""
import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from botocore.exceptions import ClientError
import uuid

from app.evidence.collectors.base import BaseCollector
from app.domain.models.incident import Incident
from app.models.evidence import EvidenceArtifact
from app.core.config import settings

logger = logging.getLogger(__name__)


class CloudTrailCollector(BaseCollector):
    """
    Collects CloudTrail evidence for an incident.
    
    Collects:
    1. Original triggering event
    2. Related events (30 minutes before and after)
    3. Builds investigation timeline
    """
    
    def __init__(self):
        super().__init__()
        self.collector_name = "CloudTrailCollector"
        
        # Initialize AWS clients
        self.cloudtrail = boto3.client(
            'cloudtrail',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,
            region_name=settings.AWS_DEFAULT_REGION
        )
    
    def get_artifact_type(self) -> str:
        return "CloudTrailEvent"
    
    def get_source(self) -> str:
        return "aws_cloudtrail"
    
    async def collect(self, incident: Incident) -> Optional[EvidenceArtifact]:
        """
        Collect CloudTrail evidence for an incident.
        """
        logger.info(f"🔍 CloudTrailCollector collecting evidence for incident {incident.id}")
        
        try:
            # 1. Extract event details from incident
            event_data = incident.normalized_event
            event_name = event_data.get('event_name')
            event_time_str = event_data.get('timestamp') or event_data.get('event_time')
            actor = event_data.get('actor')
            region = event_data.get('region', settings.AWS_DEFAULT_REGION)
            
            if not event_name:
                logger.error(f"❌ No event_name found in incident {incident.id}")
                return self._create_failed_artifact(incident.id, "No event_name found in incident")
            
            # 2. Parse event time
            if isinstance(event_time_str, str):
                try:
                    event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                except ValueError:
                    event_time = datetime.utcnow()
            else:
                event_time = event_time_str or datetime.utcnow()
            
            # 3. Calculate time window (30 minutes before and after)
            start_time = event_time - timedelta(minutes=30)
            end_time = event_time + timedelta(minutes=30)
            
            logger.info(f"📅 Time window: {start_time} to {end_time}")
            logger.info(f"🎯 Event: {event_name}, Actor: {actor}")
            
            # 4. Collect original event
            original_event = await self._get_original_event(
                event_name=event_name,
                event_time=event_time,
                actor=actor
            )
            
            # 5. Collect related events
            related_events = await self._get_related_events(
                start_time=start_time,
                end_time=end_time,
                actor=actor,
                event_name=event_name
            )
            
            # 6. Build timeline
            timeline = self._build_timeline(original_event, related_events)
            
            # 7. Create artifact content
            content = {
                "original_event": original_event,
                "related_events": related_events,
                "timeline": timeline,
                "time_window": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "trigger": event_time.isoformat()
                },
                "summary": {
                    "total_events": len(related_events) + (1 if original_event else 0),
                    "unique_actors": self._get_unique_actors(related_events),
                    "event_types": self._get_event_types(related_events)
                }
            }
            
            # 8. Create metadata
            extra_data = {
                "event_name": event_name,
                "actor": actor,
                "region": region,
                "time_window": "30min",
                "event_count": len(related_events) + 1,
                "original_event_found": original_event is not None
            }
            
            # 9. Create artifact
            artifact = self.create_artifact(
                incident_id=incident.id,
                content=content,
                extra_data=extra_data,
                region=region
            )
            
            logger.info(f"✅ CloudTrail evidence collected for incident {incident.id}")
            logger.info(f"   📊 Collected {len(related_events)} related events")
            logger.info(f"   🕐 Time range: {start_time} to {end_time}")
            
            return artifact
            
        except ClientError as e:
            logger.error(f"❌ AWS API error collecting CloudTrail evidence: {e}")
            return self._create_failed_artifact(incident.id, f"AWS Error: {str(e)}")
            
        except Exception as e:
            logger.error(f"❌ Error collecting CloudTrail evidence: {e}")
            return self._create_failed_artifact(incident.id, str(e))
    
    async def _get_original_event(
        self,
        event_name: str,
        event_time: datetime,
        actor: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get the original triggering event from CloudTrail."""
        try:
            response = self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': event_name
                    }
                ],
                StartTime=event_time - timedelta(minutes=1),
                EndTime=event_time + timedelta(minutes=1),
                MaxResults=1
            )
            
            events = response.get('Events', [])
            
            if events:
                event_data = json.loads(events[0].get('CloudTrailEvent', '{}'))
                
                if actor:
                    user_identity = event_data.get('userIdentity', {})
                    user_name = user_identity.get('userName') or user_identity.get('principalId')
                    if user_name and user_name != actor:
                        logger.warning(f"⚠️ Actor mismatch: {user_name} != {actor}")
                
                logger.info(f"✅ Found original event: {event_name}")
                return event_data
            
            logger.warning(f"⚠️ Original event not found: {event_name}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting original event: {e}")
            return None
    
    async def _get_related_events(
        self,
        start_time: datetime,
        end_time: datetime,
        actor: Optional[str] = None,
        event_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get related events within the time window."""
        try:
            events = []
            
            # Strategy 1: Look by actor if available
            if actor:
                try:
                    response = self.cloudtrail.lookup_events(
                        LookupAttributes=[
                            {
                                'AttributeKey': 'Username',
                                'AttributeValue': actor
                            }
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50
                    )
                    events = response.get('Events', [])
                    logger.info(f"📊 Found {len(events)} events by actor: {actor}")
                except:
                    pass
            
            # Strategy 2: If no events found, look by event name
            if not events and event_name:
                try:
                    response = self.cloudtrail.lookup_events(
                        LookupAttributes=[
                            {
                                'AttributeKey': 'EventName',
                                'AttributeValue': event_name
                            }
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50
                    )
                    events = response.get('Events', [])
                    logger.info(f"📊 Found {len(events)} events by event name: {event_name}")
                except:
                    pass
            
            # Strategy 3: Get all events in time window
            if not events:
                try:
                    response = self.cloudtrail.lookup_events(
                        LookupAttributes=[],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50
                    )
                    events = response.get('Events', [])
                    logger.info(f"📊 Found {len(events)} events in time window")
                except:
                    pass
            
            # Parse events
            parsed_events = []
            for event in events:
                try:
                    event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                    parsed_events.append(event_data)
                except:
                    continue
            
            return parsed_events
            
        except Exception as e:
            logger.error(f"❌ Error getting related events: {e}")
            return []
    
    def _build_timeline(
        self,
        original_event: Optional[Dict[str, Any]],
        related_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Build a chronological timeline of events."""
        timeline = []
        
        if original_event:
            timeline.append({
                "event_name": original_event.get('eventName', 'Unknown'),
                "event_time": original_event.get('eventTime'),
                "actor": self._get_actor_from_event(original_event),
                "source_ip": original_event.get('sourceIPAddress'),
                "region": original_event.get('awsRegion'),
                "event_id": original_event.get('eventID'),
                "is_trigger": True
            })
        
        for event in related_events:
            if original_event and event.get('eventID') == original_event.get('eventID'):
                continue
                
            timeline.append({
                "event_name": event.get('eventName', 'Unknown'),
                "event_time": event.get('eventTime'),
                "actor": self._get_actor_from_event(event),
                "source_ip": event.get('sourceIPAddress'),
                "region": event.get('awsRegion'),
                "event_id": event.get('eventID'),
                "is_trigger": False
            })
        
        timeline.sort(key=lambda x: x.get('event_time', ''))
        return timeline
    
    def _get_actor_from_event(self, event: Dict[str, Any]) -> str:
        """Extract actor name from event."""
        user_identity = event.get('userIdentity', {})
        return user_identity.get('userName') or user_identity.get('principalId') or 'Unknown'
    
    def _get_unique_actors(self, events: List[Dict[str, Any]]) -> List[str]:
        """Get unique actors from events."""
        actors = set()
        for event in events:
            actor = self._get_actor_from_event(event)
            if actor and actor != 'Unknown':
                actors.add(actor)
        return list(actors)
    
    def _get_event_types(self, events: List[Dict[str, Any]]) -> List[str]:
        """Get unique event types from events."""
        event_types = set()
        for event in events:
            event_name = event.get('eventName', 'Unknown')
            if event_name:
                event_types.add(event_name)
        return list(event_types)
    
    def _create_failed_artifact(self, incident_id: str, error_message: str) -> EvidenceArtifact:
        """Create a failed artifact when collection fails."""
        incident_uuid = self._parse_incident_id(incident_id)
        
        artifact = EvidenceArtifact(
            incident_id=incident_uuid,
            artifact_type=self.get_artifact_type(),
            source=self.get_source(),
            provider="aws",
            collector=self.collector_name,
            content={"error": error_message},
            collection_status="FAILED",
            error_message=error_message,
            extra_data={"failure_time": datetime.utcnow().isoformat()}
        )
        
        return artifact