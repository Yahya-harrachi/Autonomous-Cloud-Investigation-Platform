"""
SQS Consumer Service - Continuously polls SQS and processes events
"""
import json
import logging
import threading
import time
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime

from botocore.exceptions import ClientError

from ..infrastructure.clients.aws_client import AWSClient
from ..infrastructure.normalizers.aws_normalizer import AWSNormalizer
from ..domain.models.event import RawEvent
from ..services.websocket_manager import websocket_manager
from ..services.incident_creator import IncidentCreator

logger = logging.getLogger(__name__)


class SQSConsumer:
    """
    Continuous SQS consumer that processes CloudTrail events in real-time.
    Runs in a background thread.
    """
    
    def __init__(
        self,
        queue_url: str,
        region: str = "us-east-1",
        poll_interval: int = 1,
        max_messages: int = 10,
        wait_time: int = 20,
    ):
        self.queue_url = queue_url
        self.region = region
        self.poll_interval = poll_interval
        self.max_messages = max_messages
        self.wait_time = wait_time
        
        self._aws_client = AWSClient(region=region)
        self._sqs = self._aws_client.get_client('sqs')
        self._normalizer = AWSNormalizer()
        self._incident_creator = IncidentCreator()
        self._main_loop = None  # Store the main event loop
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._processed_count = 0
        self._error_count = 0
        
        if not self.queue_url:
            self.queue_url = self._get_queue_url()
        
        print(f"SQS Consumer initialized with queue: {self.queue_url}")
    
    def set_event_loop(self, loop):
        """Set the main event loop for async operations"""
        self._main_loop = loop
        print(f"✅ Event loop set: {loop}")
    
    def _get_queue_url(self) -> str:
        try:
            response = self._sqs.get_queue_url(QueueName='acip-events-queue')
            return response['QueueUrl']
        except ClientError as e:
            print(f"Failed to get queue URL: {e}")
            raise
    
    def start(self) -> None:
        if self._running:
            print("Consumer already running")
            return
        
        self._running = True
        self._thread = threading.Thread(
            target=self._consumer_loop,
            daemon=True,
            name="sqs-consumer"
        )
        self._thread.start()
        print("✅ SQS Consumer started")
    
    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("SQS Consumer stopped")
    
    def _consumer_loop(self) -> None:
        print("SQS Consumer loop started")
        while self._running:
            try:
                self._poll_and_process()
            except Exception as e:
                print(f"Error in consumer loop: {e}")
                time.sleep(self.poll_interval * 5)
    
    def _poll_and_process(self) -> None:
        try:
            response = self._sqs.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=self.max_messages,
                WaitTimeSeconds=self.wait_time,
                VisibilityTimeout=60,
            )
            
            messages = response.get('Messages', [])
            
            if not messages:
                time.sleep(self.poll_interval)
                return
            
            print(f"Received {len(messages)} messages from SQS")
            
            for message in messages:
                try:
                    self._process_message(message)
                except Exception as e:
                    print(f"Error processing message: {e}")
                    self._error_count += 1
                    
        except ClientError as e:
            print(f"SQS error: {e}")
            time.sleep(self.poll_interval * 2)
        except Exception as e:
            print(f"Unexpected error in poll: {e}")
            time.sleep(self.poll_interval * 2)
    
    def _create_raw_event(self, body: Dict[str, Any]) -> RawEvent:
        detail = body.get('detail', {})
        event_time = detail.get('eventTime', '')
        
        try:
            if event_time:
                timestamp = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            else:
                timestamp = datetime.utcnow()
        except Exception:
            timestamp = datetime.utcnow()
        
        return RawEvent(
            source='aws',
            provider='cloudtrail',
            event_type=detail.get('eventName', 'unknown'),
            data=detail,
            timestamp=timestamp,
            received_at=datetime.utcnow(),
        )
    
    def _process_message(self, message: Dict[str, Any]) -> None:
        try:
            body = json.loads(message.get('Body', '{}'))
            receipt_handle = message.get('ReceiptHandle')
            
            detail = body.get('detail', {})
            event_name = detail.get('eventName', 'unknown')
            
            print(f"📩 Processing: {event_name}")
            
            raw_event = self._create_raw_event(body)
            normalized = self._normalizer.normalize(raw_event)
            print(f"✅ Normalized: {normalized.event_name}")
            
            # ✅ BROADCAST using the main event loop
            if self._main_loop:
                try:
                    asyncio.run_coroutine_threadsafe(
                        websocket_manager.broadcast_event(normalized.to_dict()),
                        self._main_loop
                    )
                    print(f"📡 Broadcasted: {event_name} (Severity: {normalized.severity})")
                except Exception as e:
                    print(f"❌ Broadcast failed: {e}")
            else:
                print("❌ No event loop available for broadcast")
            
            # ✅ Create incident
            incident = self._incident_creator.process_event(normalized)
            
            if incident:
                print(f"🚨 INCIDENT CREATED: {incident.title} ({incident.priority.value})")
                
                # ✅ Broadcast incident using the main event loop
                if self._main_loop:
                    try:
                        asyncio.run_coroutine_threadsafe(
                            websocket_manager.broadcast_incident({
                                "id": incident.id,
                                "title": incident.title,
                                "priority": incident.priority.value,
                                "severity": incident.priority.value,
                                "score": incident.severity_score if hasattr(incident, 'severity_score') else 0,
                                "created_at": incident.created_at.isoformat(),
                            }),
                            self._main_loop
                        )
                        print("📡 Broadcasted incident")
                    except Exception as e:
                        print(f"❌ Incident broadcast failed: {e}")
            else:
                print(f"⚪ No incident: {event_name} (Severity: {normalized.severity})")
            
            # ✅ Delete from SQS
            if receipt_handle:
                self._sqs.delete_message(
                    QueueUrl=self.queue_url,
                    ReceiptHandle=receipt_handle
                )
                self._processed_count += 1
                print(f"🗑️ Deleted from queue")
            
        except Exception as e:
            print(f"❌ Error processing message: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "processed_count": self._processed_count,
            "error_count": self._error_count,
            "queue_url": self.queue_url,
            "region": self.region,
        }


_consumer_instance: Optional[SQSConsumer] = None


def get_consumer() -> SQSConsumer:
    global _consumer_instance
    if _consumer_instance is None:
        _consumer_instance = SQSConsumer(
            queue_url="https://sqs.us-east-1.amazonaws.com/251388487402/acip-events-queue",
        )
    return _consumer_instance


def start_consumer():
    consumer = get_consumer()
    # ✅ Set the main event loop
    try:
        loop = asyncio.get_event_loop()
        consumer.set_event_loop(loop)
        print("✅ Main event loop set in consumer")
    except Exception as e:
        print(f"⚠️ Could not get event loop: {e}")
    consumer.start()
    return consumer


def stop_consumer():
    consumer = get_consumer()
    consumer.stop()