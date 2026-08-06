"""
SQS Consumer Service - Continuously polls SQS and processes events
"""
import json
import logging
import threading
import time
from typing import Optional, Dict, Any
from datetime import datetime

from botocore.exceptions import ClientError

from ..infrastructure.clients.aws_client import AWSClient
from ..infrastructure.normalizers.aws_normalizer import AWSNormalizer
from ..domain.models.event import RawEvent
from ..services.incident_creator import IncidentCreator
from ..services.event_queue import event_queue
from ..services.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)


# Set the processor for the event queue
event_queue.set_processor(websocket_manager)


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
        """
        Initialize SQS Consumer.
        
        Args:
            queue_url: SQS queue URL
            region: AWS region
            poll_interval: Seconds between polls when empty (1)
            max_messages: Max messages per receive (1-10)
            wait_time: Long polling wait time in seconds (1-20)
        """
        self.queue_url = queue_url
        self.region = region
        self.poll_interval = poll_interval
        self.max_messages = max_messages
        self.wait_time = wait_time
        
        # AWS clients
        self._aws_client = AWSClient(region=region)
        self._sqs = self._aws_client.get_client('sqs')
        
        # Services
        self._normalizer = AWSNormalizer()
        self._incident_creator = IncidentCreator()
        
        # State
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._processed_count = 0
        self._error_count = 0
        
        # Get queue URL if not provided
        if not self.queue_url:
            self.queue_url = self._get_queue_url()
        
        logger.info(f"SQS Consumer initialized with queue: {self.queue_url}")
    
    def _get_queue_url(self) -> str:
        """Get queue URL from queue name"""
        try:
            response = self._sqs.get_queue_url(
                QueueName='acip-events-queue'
            )
            return response['QueueUrl']
        except ClientError as e:
            logger.error(f"Failed to get queue URL: {e}")
            raise
    
    def start(self) -> None:
        """Start the consumer in a background thread"""
        if self._running:
            logger.warning("Consumer already running")
            return
        
        self._running = True
        self._thread = threading.Thread(
            target=self._consumer_loop,
            daemon=True,
            name="sqs-consumer"
        )
        self._thread.start()
        logger.info("✅ SQS Consumer started")
    
    def stop(self) -> None:
        """Stop the consumer"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("SQS Consumer stopped")
    
    def _consumer_loop(self) -> None:
        """Main consumer loop"""
        logger.info("SQS Consumer loop started")
        
        while self._running:
            try:
                self._poll_and_process()
            except Exception as e:
                logger.error(f"Error in consumer loop: {e}")
                time.sleep(self.poll_interval * 5)
    
    def _poll_and_process(self) -> None:
        """Poll SQS and process messages"""
        try:
            # Receive messages from SQS
            response = self._sqs.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=self.max_messages,
                WaitTimeSeconds=self.wait_time,
                VisibilityTimeout=60,
            )
            
            messages = response.get('Messages', [])
            
            if not messages:
                # No messages, short sleep
                time.sleep(self.poll_interval)
                return
            
            logger.info(f"Received {len(messages)} messages from SQS")
            
            # Process each message
            for message in messages:
                try:
                    self._process_message(message)
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    self._error_count += 1
                    
        except ClientError as e:
            logger.error(f"SQS error: {e}")
            time.sleep(self.poll_interval * 2)
        except Exception as e:
            logger.error(f"Unexpected error in poll: {e}")
            time.sleep(self.poll_interval * 2)
    
    def _process_message(self, message: Dict[str, Any]) -> None:
        """
        Process a single SQS message.
        """
        try:
            # 1. Parse message
            body = json.loads(message.get('Body', '{}'))
            receipt_handle = message.get('ReceiptHandle')
            
            print(f"📩 Processing message: {body.get('detail', {}).get('eventName', 'unknown')}")
            
            # 2. Create RawEvent
            raw_event = self._create_raw_event(body)
            
            # 3. Normalize
            normalized = self._normalizer.normalize(raw_event)
            print(f"✅ Normalized: {normalized.event_name}")
            
            # 4. Convert to dict for broadcasting
            event_dict = normalized.to_dict()
            
            # 5. Add to event queue
            print(f"📤 Adding to event queue: {event_dict.get('event_name')}")
            event_queue.add_event(event_dict)
            print(f"✅ Added to queue")
            
            # 6. Create incident if needed
            # incident = self._incident_creator.process_event(normalized)
            # if incident:
            #    print(f"🚨 Incident created: {incident.title}")
            
            # 7. Delete message from queue
            if receipt_handle:
                self._sqs.delete_message(
                    QueueUrl=self.queue_url,
                    ReceiptHandle=receipt_handle
                )
                self._processed_count += 1
                print(f"🗑️ Message deleted from queue")
            
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse message JSON: {e}")
            receipt_handle = message.get('ReceiptHandle')
            if receipt_handle:
                self._sqs.delete_message(
                    QueueUrl=self.queue_url,
                    ReceiptHandle=receipt_handle
                )
        except Exception as e:
            print(f"❌ Error processing message: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def _create_raw_event(self, body: Dict[str, Any]) -> RawEvent:
        """Create RawEvent from SQS message body"""
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
    
    def get_stats(self) -> Dict[str, Any]:
        """Get consumer statistics"""
        return {
            "running": self._running,
            "processed_count": self._processed_count,
            "error_count": self._error_count,
            "queue_url": self.queue_url,
            "region": self.region,
        }


# Singleton instance
_consumer_instance: Optional[SQSConsumer] = None


def get_consumer() -> SQSConsumer:
    """Get or create the singleton consumer"""
    global _consumer_instance
    if _consumer_instance is None:
        _consumer_instance = SQSConsumer(
            queue_url="https://sqs.us-east-1.amazonaws.com/251388487402/acip-events-queue",
        )
    return _consumer_instance


def start_consumer():
    """Start the SQS consumer"""
    consumer = get_consumer()
    consumer.start()
    return consumer


def stop_consumer():
    """Stop the SQS consumer"""
    consumer = get_consumer()
    consumer.stop()