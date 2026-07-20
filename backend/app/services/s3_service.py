import boto3
from botocore.client import Config
import os

class S3Service:
    def __init__(self):
        endpoint_url = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")
        
        self.client = boto3.client(
            's3',
            endpoint_url=endpoint_url,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
            region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            config=Config(signature_version='s3v4')
        )
        self.bucket = "acip-evidence-dev"
    
    def upload_file(self, incident_id: str, filename: str, content: bytes):
        key = f"incidents/{incident_id}/{filename}"
        self.client.put_object(Bucket=self.bucket, Key=key, Body=content)
        return f"s3://{self.bucket}/{key}"
    
    def get_file(self, incident_id: str, filename: str):
        key = f"incidents/{incident_id}/{filename}"
        response = self.client.get_object(Bucket=self.bucket, Key=key)
        return response['Body'].read()
    
    def list_files(self, incident_id: str):
        prefix = f"incidents/{incident_id}/"
        response = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        return [obj['Key'] for obj in response.get('Contents', [])]