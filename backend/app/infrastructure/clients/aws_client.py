"""
AWS Client - Wrapper for boto3 with proper error handling, retry logic, and logging.
This is the ONLY place that directly interacts with boto3.
"""
import boto3
import logging
import time
from typing import Optional, Dict, Any
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    CredentialRetrievalError,
    EndpointConnectionError,
    ConnectTimeoutError,
    ReadTimeoutError,
)
from botocore.config import Config
from ...core.config import settings

logger = logging.getLogger(__name__)


class AWSClient:
    """
    AWS Client wrapper that provides:
    - Credential management
    - Automatic retry with exponential backoff
    - Consistent error handling
    - Logging
    - Service clients (CloudTrail, EC2, S3, etc.)
    """
    
    def __init__(
        self,
        region: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
    ):
        """
        Initialize AWS Client.
        
        Priority for credentials:
        1. Explicit parameters (highest)
        2. Environment variables
        3. AWS credentials file (~/.aws/credentials)
        """
        self.region = region or settings.AWS_DEFAULT_REGION
        
        # Session configuration
        self.session = boto3.Session(
            aws_access_key_id=access_key or settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=secret_key or settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=session_token or settings.AWS_SESSION_TOKEN,
            region_name=self.region,
        )
        
        # Boto3 config with retry strategy
        self.config = Config(
            region_name=self.region,
            retries={
                "max_attempts": 3,
                "mode": "standard",
            },
            connect_timeout=10,
            read_timeout=30,
        )
        
        # Lazy-loaded service clients
        self._clients: Dict[str, Any] = {}
        
        # Log initialization
        logger.info(f"AWS Client initialized for region: {self.region}")
    
    def get_client(self, service_name: str) -> boto3.client:
        """
        Get or create a boto3 client for a specific AWS service.
        
        Args:
            service_name: e.g., 'cloudtrail', 'ec2', 's3'
            
        Returns:
            boto3 client
            
        Raises:
            Exception: If client creation fails (wrapped in domain error)
        """
        if service_name in self._clients:
            logger.debug(f"Reusing cached client for: {service_name}")
            return self._clients[service_name]
        
        try:
            client = self.session.client(
                service_name,
                config=self.config,
                region_name=self.region,
            )
            self._clients[service_name] = client
            logger.info(f"AWS client created for service: {service_name}")
            return client
        except (NoCredentialsError, CredentialRetrievalError) as e:
            logger.error(f"AWS credentials error: {str(e)}")
            raise AWSCredentialError(f"AWS credentials not found: {str(e)}")
        except Exception as e:
            logger.error(f"Error creating AWS client: {str(e)}")
            raise AWSClientError(f"Failed to create AWS client: {str(e)}")
    
    def test_credentials(self) -> bool:
        """
        Test if credentials are valid.
        
        Returns:
            True if valid, False otherwise
        """
        try:
            sts = self.get_client("sts")
            identity = sts.get_caller_identity()
            logger.info(f"AWS credentials valid. Account ID: {identity.get('Account')}")
            return True
        except Exception as e:
            logger.error(f"AWS credentials test failed: {str(e)}")
            return False
    
    def get_account_id(self) -> Optional[str]:
        """
        Get the AWS account ID from credentials.
        
        Returns:
            Account ID or None if not available
        """
        try:
            sts = self.get_client("sts")
            identity = sts.get_caller_identity()
            return identity.get("Account")
        except Exception:
            return None


class AWSError(Exception):
    """Base AWS exception"""
    pass


class AWSCredentialError(AWSError):
    """AWS credential related errors"""
    pass


class AWSClientError(AWSError):
    """AWS client related errors"""
    pass


class AWSAPIRateLimitError(AWSError):
    """AWS API rate limit exceeded"""
    pass


class AWSApiError(AWSError):
    """Generic AWS API error"""
    pass