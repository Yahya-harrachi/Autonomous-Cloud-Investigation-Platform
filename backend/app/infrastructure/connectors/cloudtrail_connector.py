"""
CloudTrail Connector - Handles retrieving events from AWS CloudTrail
"""
import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from botocore.exceptions import ClientError

from .interfaces.event_connector import EventConnector
from ..clients.aws_client import AWSClient, AWSError

logger = logging.getLogger(__name__)


class CloudTrailConnector(EventConnector):
    """
    Connector for AWS CloudTrail API.
    Retrieves CloudTrail events and converts them to RawEvent format.
    """
    
    def __init__(self, aws_client: AWSClient):
        """
        Initialize CloudTrail connector.
        
        Args:
            aws_client: AWS Client wrapper
        """
        self.aws_client = aws_client
        self.cloudtrail = None
    
    def _get_client(self):
        """Get CloudTrail client (lazy-loaded)"""
        if self.cloudtrail is None:
            self.cloudtrail = self.aws_client.get_client("cloudtrail")
        return self.cloudtrail
    
    def fetch_events(
        self,
        max_results: int = 50,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        event_name: Optional[str] = None,
        username: Optional[str] = None,
        event_source: Optional[str] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Fetch CloudTrail events from AWS.
        
        Args:
            max_results: Maximum number of events to return (default 50)
            start_time: Start time (ISO format or datetime object)
            end_time: End time (ISO format or datetime object)
            event_name: Filter by event name (e.g., "ConsoleLogin")
            username: Filter by username
            event_source: Filter by event source (e.g., "ec2.amazonaws.com")
            **kwargs: Additional filters (LookupAttributes)
            
        Returns:
            List of raw CloudTrail events
        """
        try:
            client = self._get_client()
            
            # Build lookup attributes
            lookup_attributes = []
            
            if event_name:
                lookup_attributes.append({
                    "AttributeKey": "EventName",
                    "AttributeValue": event_name
                })
            
            if username:
                lookup_attributes.append({
                    "AttributeKey": "Username",
                    "AttributeValue": username
                })
            
            if event_source:
                lookup_attributes.append({
                    "AttributeKey": "EventSource",
                    "AttributeValue": event_source
                })
            
            # Build request parameters
            params = {
                "MaxResults": min(max_results, 50),  # AWS Max is 50
                "LookupAttributes": lookup_attributes
            }
            
            # Add time filters if provided
            if start_time:
                params["StartTime"] = self._parse_time(start_time)
            if end_time:
                params["EndTime"] = self._parse_time(end_time)
            
            logger.info(f"Fetching CloudTrail events with params: {params}")
            
            # Call AWS API
            response = client.lookup_events(**params)
            events = response.get("Events", [])
            
            # Handle pagination if more events requested
            all_events = list(events)
            next_token = response.get("NextToken")
            
            while next_token and len(all_events) < max_results:
                params["NextToken"] = next_token
                response = client.lookup_events(**params)
                all_events.extend(response.get("Events", []))
                next_token = response.get("NextToken")
            
            # Limit to max_results
            result_events = all_events[:max_results]
            
            logger.info(f"Retrieved {len(result_events)} CloudTrail events")
            
            # Parse the CloudTrailEvent JSON string into a dict
            for event in result_events:
                if "CloudTrailEvent" in event:
                    try:
                        event["CloudTrailEvent"] = json.loads(event["CloudTrailEvent"])
                    except json.JSONDecodeError:
                        # Keep as string if not valid JSON
                        pass
            
            return result_events
            
        except AWSError as e:
            logger.error(f"AWS error fetching CloudTrail events: {str(e)}")
            raise CloudTrailConnectorError(f"AWS error: {str(e)}")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))
            logger.error(f"CloudTrail API error: {error_code} - {error_message}")
            raise CloudTrailConnectorError(f"CloudTrail API error: {error_code} - {error_message}")
        except Exception as e:
            logger.error(f"Unexpected error fetching CloudTrail events: {str(e)}")
            raise CloudTrailConnectorError(f"Unexpected error: {str(e)}")
    
    def get_provider(self) -> str:
        return "aws_cloudtrail"
    
    def is_available(self) -> bool:
        """Check if CloudTrail is accessible"""
        try:
            client = self._get_client()
            client.lookup_events(MaxResults=1)
            return True
        except Exception:
            return False
    
    def get_event_summary(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract a summary from a CloudTrail event.
        
        Args:
            event: Raw CloudTrail event
            
        Returns:
            Summary dictionary with key fields
        """
        cloudtrail_event = event.get("CloudTrailEvent", {})
        if isinstance(cloudtrail_event, str):
            try:
                cloudtrail_event = json.loads(cloudtrail_event)
            except json.JSONDecodeError:
                cloudtrail_event = {}
        
        return {
            "event_id": event.get("EventId"),
            "event_name": event.get("EventName"),
            "event_source": event.get("EventSource"),
            "event_time": event.get("EventTime"),
            "username": event.get("Username"),
            "aws_region": event.get("AwsRegion"),
            "source_ip": cloudtrail_event.get("sourceIPAddress"),
            "user_agent": cloudtrail_event.get("userAgent"),
            "resources": event.get("Resources", []),
        }
    
    def _parse_time(self, time_val):
        """Parse time from string or datetime to datetime object"""
        if isinstance(time_val, datetime):
            return time_val
        if isinstance(time_val, str):
            # Try ISO format
            try:
                return datetime.fromisoformat(time_val.replace("Z", "+00:00"))
            except ValueError:
                # Try common formats
                for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"]:
                    try:
                        return datetime.strptime(time_val, fmt)
                    except ValueError:
                        continue
                raise ValueError(f"Unable to parse time: {time_val}")
        raise ValueError(f"Invalid time value: {time_val}")


class CloudTrailConnectorError(Exception):
    """CloudTrail connector specific errors"""
    pass