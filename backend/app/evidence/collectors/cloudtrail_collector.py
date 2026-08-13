# app/evidence/collectors/cloudtrail_collector.py
"""
CloudTrail Collector - Collects and organizes CloudTrail evidence
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
    Collects CloudTrail evidence for an incident with smart filtering.
    
    Collects:
    1. Original triggering event (with full context)
    2. Related events (5 minutes before and after)
    3. Builds attack chain timeline
    4. Identifies patterns
    """
    
    # High-priority event types (likely part of attack chain)
    HIGH_PRIORITY_EVENTS = {
        'ConsoleLogin', 'CreateUser', 'DeleteUser', 'CreateAccessKey', 
        'DeleteAccessKey', 'AttachUserPolicy', 'AttachRolePolicy', 
        'PutUserPolicy', 'PutRolePolicy', 'CreatePolicy', 'DeletePolicy',
        'UpdateAssumeRolePolicy', 'CreateRole', 'DeleteRole',
        'UpdateUserPolicy', 'DetachUserPolicy', 'DetachRolePolicy',
        'CreateLoginProfile', 'DeleteLoginProfile'
    }
    
    # Medium-priority events (reconnaissance)
    MEDIUM_PRIORITY_EVENTS = {
        'ListUsers', 'ListGroups', 'ListPolicies', 'GetUser',
        'GetPolicy', 'ListAttachedUserPolicies', 'ListAccessKeys',
        'GetAccessKeyLastUsed', 'ListSigningCertificates'
    }
    
    def __init__(self):
        super().__init__()
        self.collector_name = "CloudTrailCollector"
        
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
        Collect CloudTrail evidence with smart filtering.
        """
        logger.info(f"🔍 CloudTrailCollector collecting evidence for incident {incident.id}")
        
        try:
            # 1. Extract event details
            event_data = incident.normalized_event
            event_name = event_data.get('event_name')
            event_time_str = event_data.get('timestamp') or event_data.get('event_time')
            actor = event_data.get('actor')
            region = event_data.get('region', settings.AWS_DEFAULT_REGION)
            
            if not event_name:
                return self._create_failed_artifact(incident.id, "No event_name found")
            
            # 2. Parse event time
            if isinstance(event_time_str, str):
                try:
                    event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                except ValueError:
                    event_time = datetime.utcnow()
            else:
                event_time = event_time_str or datetime.utcnow()
            
            # 3. Expanded time window (10 minutes before, 5 minutes after for better context)
            start_time = event_time - timedelta(minutes=10)
            end_time = event_time + timedelta(minutes=5)
            
            logger.info(f"📅 Time window: {start_time} to {end_time}")
            logger.info(f"🎯 Event: {event_name}, Actor: {actor}")
            
            # 4. Collect all events in window
            all_events = await self._get_events_in_window(
                start_time=start_time,
                end_time=end_time,
                actor=actor
            )
            
            # 5. Categorize and prioritize events
            categorized = self._categorize_events(all_events, event_name, actor)
            
            # 6. Build attack chain timeline
            timeline = self._build_attack_chain(categorized, event_name, event_time)
            
            # 7. Detect patterns
            patterns = self._detect_patterns(timeline, categorized)
            
            # 8. Create summary
            summary = self._create_summary(categorized, timeline, patterns)
            
            # 9. Build content
            content = {
                "original_event": self._find_original_event(all_events, event_name, event_time),
                "categorized_events": categorized,
                "timeline": timeline,
                "patterns": patterns,
                "summary": summary,
                "time_window": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "trigger": event_time.isoformat()
                }
            }
            
            # 10. Create metadata
            extra_data = {
                "event_name": event_name,
                "actor": actor,
                "region": region,
                "total_events": len(all_events),
                "high_priority_count": len(categorized.get('high_priority', [])),
                "medium_priority_count": len(categorized.get('medium_priority', [])),
                "patterns_found": len(patterns)
            }
            
            # 11. Create artifact
            artifact = self.create_artifact(
                incident_id=incident.id,
                content=content,
                extra_data=extra_data,
                region=region
            )
            
            logger.info(f"✅ CloudTrail evidence collected for incident {incident.id}")
            logger.info(f"   📊 Total events: {len(all_events)}")
            logger.info(f"   🎯 High priority: {len(categorized.get('high_priority', []))}")
            logger.info(f"   🔍 Patterns found: {len(patterns)}")
            
            return artifact
            
        except ClientError as e:
            logger.error(f"❌ AWS API error: {e}")
            return self._create_failed_artifact(incident.id, str(e))
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return self._create_failed_artifact(incident.id, str(e))
    
    async def _get_events_in_window(
        self,
        start_time: datetime,
        end_time: datetime,
        actor: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get all events in the time window."""
        all_events = []
        
        try:
            # Try to get events by actor first
            if actor:
                try:
                    response = self.cloudtrail.lookup_events(
                        LookupAttributes=[
                            {'AttributeKey': 'Username', 'AttributeValue': actor}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=100
                    )
                    events = response.get('Events', [])
                    for event in events:
                        try:
                            event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                            all_events.append(event_data)
                        except:
                            continue
                except Exception as e:
                    logger.warning(f"⚠️ Error getting events by actor: {e}")
            
            # If no events found, get all events in window
            if not all_events:
                response = self.cloudtrail.lookup_events(
                    LookupAttributes=[],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=100
                )
                events = response.get('Events', [])
                for event in events:
                    try:
                        event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                        all_events.append(event_data)
                    except:
                        continue
            
            return all_events
            
        except Exception as e:
            logger.error(f"❌ Error getting events: {e}")
            return []
    
    def _categorize_events(
        self,
        events: List[Dict[str, Any]],
        trigger_event: str,
        actor: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorize events by priority.
        """
        result = {
            'trigger': [],
            'high_priority': [],
            'medium_priority': [],
            'other': [],
            'reconnaissance': []
        }
        
        for event in events:
            event_name = event.get('eventName', 'Unknown')
            
            # Check if this is the trigger event
            if event_name == trigger_event:
                result['trigger'].append(event)
            elif event_name in self.HIGH_PRIORITY_EVENTS:
                result['high_priority'].append(event)
            elif event_name in self.MEDIUM_PRIORITY_EVENTS:
                result['medium_priority'].append(event)
            elif self._is_reconnaissance_event(event_name):
                result['reconnaissance'].append(event)
            else:
                result['other'].append(event)
        
        return result
    
    def _is_reconnaissance_event(self, event_name: str) -> bool:
        """Check if event is reconnaissance."""
        recon_patterns = ['Describe', 'List', 'Get', 'Lookup', 'Search']
        return any(event_name.startswith(pattern) for pattern in recon_patterns)
    
    def _find_original_event(
        self,
        events: List[Dict[str, Any]],
        event_name: str,
        event_time: datetime
    ) -> Optional[Dict[str, Any]]:
        """Find the original triggering event."""
        for event in events:
            if event.get('eventName') == event_name:
                # Check if it's within 1 minute of the trigger time
                event_time_str = event.get('eventTime')
                if event_time_str:
                    try:
                        event_dt = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                        if abs((event_dt - event_time).total_seconds()) < 60:
                            return event
                    except:
                        pass
        return None
    
    def _build_attack_chain(
        self,
        categorized: Dict[str, List[Dict[str, Any]]],
        trigger_event: str,
        trigger_time: datetime
    ) -> List[Dict[str, Any]]:
        """
        Build attack chain timeline with priorities.
        """
        timeline = []
        
        # Start with trigger event
        trigger_events = categorized.get('trigger', [])
        for event in trigger_events:
            timeline.append({
                'event_name': event.get('eventName', 'Unknown'),
                'event_time': event.get('eventTime'),
                'actor': self._get_actor_from_event(event),
                'source_ip': event.get('sourceIPAddress'),
                'region': event.get('awsRegion'),
                'event_id': event.get('eventID'),
                'priority': 'trigger',
                'icon': '🚨',
                'label': 'TRIGGER'
            })
        
        # Add high priority events (attack chain)
        high_priority = categorized.get('high_priority', [])
        for event in high_priority:
            event_time = event.get('eventTime')
            is_before = True
            if event_time:
                try:
                    event_dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                    is_before = event_dt < trigger_time
                except:
                    pass
            
            timeline.append({
                'event_name': event.get('eventName', 'Unknown'),
                'event_time': event_time,
                'actor': self._get_actor_from_event(event),
                'source_ip': event.get('sourceIPAddress'),
                'region': event.get('awsRegion'),
                'event_id': event.get('eventID'),
                'priority': 'high',
                'icon': '🔴' if not is_before else '🟠',
                'label': 'POST-ACTION' if not is_before else 'PRE-ACTION'
            })
        
        # Add reconnaissance events
        recon = categorized.get('reconnaissance', [])
        for event in recon[:5]:  # Limit recon events
            timeline.append({
                'event_name': event.get('eventName', 'Unknown'),
                'event_time': event.get('eventTime'),
                'actor': self._get_actor_from_event(event),
                'source_ip': event.get('sourceIPAddress'),
                'region': event.get('awsRegion'),
                'event_id': event.get('eventID'),
                'priority': 'recon',
                'icon': '🔍',
                'label': 'RECON'
            })
        
        # Sort by time
        timeline.sort(key=lambda x: x.get('event_time', ''))
        
        return timeline
    
    def _detect_patterns(
        self,
        timeline: List[Dict[str, Any]],
        categorized: Dict[str, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """
        Detect attack patterns.
        """
        patterns = []
        event_names = [e.get('event_name', '') for e in timeline]
        
        # Pattern 1: User creation + access key creation
        if 'CreateUser' in event_names and 'CreateAccessKey' in event_names:
            patterns.append({
                'type': 'privilege_escalation',
                'severity': 'high',
                'description': 'User created then access key created',
                'recommendation': 'Check if user was legitimate'
            })
        
        # Pattern 2: Policy attachment after user creation
        if 'CreateUser' in event_names and any(p in event_names for p in ['AttachUserPolicy', 'PutUserPolicy']):
            patterns.append({
                'type': 'privilege_escalation',
                'severity': 'critical',
                'description': 'User created then policy attached - possible privilege escalation',
                'recommendation': 'Review attached policies immediately'
            })
        
        # Pattern 3: Reconnaissance followed by action
        recon_count = len(categorized.get('reconnaissance', []))
        high_priority_count = len(categorized.get('high_priority', []))
        if recon_count > 2 and high_priority_count > 0:
            patterns.append({
                'type': 'attack_pattern',
                'severity': 'high',
                'description': f'Reconnaissance ({recon_count} events) followed by destructive action',
                'recommendation': 'Investigate actor behavior pattern'
            })
        
        # Pattern 4: Multiple access keys
        if event_names.count('CreateAccessKey') > 1:
            patterns.append({
                'type': 'credential_misuse',
                'severity': 'medium',
                'description': 'Multiple access keys created - possible credential theft',
                'recommendation': 'Review all access keys and rotate immediately'
            })
        
        # Pattern 5: Off-hours activity
        # Check if activity occurred outside business hours (assuming 9-5)
        off_hours_events = []
        for event in timeline:
            event_time = event.get('event_time')
            if event_time:
                try:
                    dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                    hour = dt.hour
                    if hour < 8 or hour > 18 or dt.weekday() > 4:
                        off_hours_events.append(event)
                except:
                    pass
        
        if len(off_hours_events) > 2:
            patterns.append({
                'type': 'off_hours_activity',
                'severity': 'medium',
                'description': f'{len(off_hours_events)} events occurred outside business hours',
                'recommendation': 'Verify if activity was authorized'
            })
        
        return patterns
    
    def _create_summary(
        self,
        categorized: Dict[str, List[Dict[str, Any]]],
        timeline: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create a summary of the evidence."""
        return {
            'total_events': len(timeline),
            'high_priority_events': len(categorized.get('high_priority', [])),
            'reconnaissance_events': len(categorized.get('reconnaissance', [])),
            'patterns_found': len(patterns),
            'unique_actors': self._get_unique_actors(timeline),
            'event_types': self._get_event_types(timeline),
            'security_alerts': [
                {
                    'severity': p.get('severity'),
                    'description': p.get('description'),
                    'recommendation': p.get('recommendation')
                }
                for p in patterns
            ]
        }
    
    def _get_actor_from_event(self, event: Dict[str, Any]) -> str:
        """Extract actor name from event."""
        user_identity = event.get('userIdentity', {})
        return user_identity.get('userName') or user_identity.get('principalId') or 'Unknown'
    
    def _get_unique_actors(self, events: List[Dict[str, Any]]) -> List[str]:
        """Get unique actors."""
        actors = set()
        for event in events:
            actor = event.get('actor')
            if actor and actor != 'Unknown':
                actors.add(actor)
        return list(actors)
    
    def _get_event_types(self, events: List[Dict[str, Any]]) -> List[str]:
        """Get unique event types."""
        types = set()
        for event in events:
            event_name = event.get('event_name')
            if event_name:
                types.add(event_name)
        return list(types)
    
    def _create_failed_artifact(self, incident_id: str, error_message: str) -> EvidenceArtifact:
        """Create a failed artifact."""
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