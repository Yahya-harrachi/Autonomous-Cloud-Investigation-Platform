# app/core/utils.py
"""
Utility functions for ACIP
"""
import uuid
import re
from typing import Optional


def parse_incident_id(incident_id: str) -> uuid.UUID:
    """
    Parse incident ID string to UUID.
    
    Handles:
    - inc-abc123def456 -> UUID
    - abc123def456 -> UUID
    - Full UUID string -> UUID
    - Any other string -> deterministic UUID
    
    Args:
        incident_id: The incident ID string
        
    Returns:
        UUID object
    """
    # If it's already a UUID string, return it
    try:
        return uuid.UUID(incident_id)
    except (ValueError, TypeError):
        pass
    
    # Remove 'inc-' prefix if present
    clean_id = incident_id
    if incident_id.startswith('inc-'):
        clean_id = incident_id[4:]
    
    # Remove any non-hex characters
    clean_id = re.sub(r'[^a-fA-F0-9]', '', clean_id)
    
    # If we have a valid hex string, try to create UUID
    if clean_id:
        # Pad to 32 characters if needed
        if len(clean_id) < 32:
            clean_id = clean_id.ljust(32, '0')
        
        # If length is at least 32, it's a valid UUID
        if len(clean_id) >= 32:
            clean_id = clean_id[:32]
            try:
                return uuid.UUID(clean_id)
            except ValueError:
                pass
    
    # Fallback: generate deterministic UUID
    return uuid.uuid5(uuid.NAMESPACE_DNS, incident_id)


def generate_incident_display_id() -> str:
    """
    Generate a human-readable incident display ID.
    
    Returns:
        String like inc-abc123def456
    """
    import hashlib
    import time
    
    # Generate a unique hash based on timestamp and random
    unique_string = f"{time.time()}{uuid.uuid4()}"
    hash_obj = hashlib.md5(unique_string.encode())
    hex_hash = hash_obj.hexdigest()[:12]
    
    return f"inc-{hex_hash}"


def truncate_text(text: str, max_length: int = 200) -> str:
    """
    Truncate text to a maximum length with ellipsis.
    
    Args:
        text: The text to truncate
        max_length: Maximum length
        
    Returns:
        Truncated text
    """
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."