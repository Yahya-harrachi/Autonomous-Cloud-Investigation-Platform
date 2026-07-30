import os
from typing import Optional

class Settings:
    
    # ===== AWS Configuration =====
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_SESSION_TOKEN: Optional[str] = os.getenv("AWS_SESSION_TOKEN", None)
    AWS_DEFAULT_REGION: str = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    AWS_ACCOUNT_ID: str = os.getenv("AWS_ACCOUNT_ID", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY")

settings = Settings()