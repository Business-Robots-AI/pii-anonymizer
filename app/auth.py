"""
Authentication module for PII Anonymizer web interface.
"""
import os
import secrets
import hashlib
from typing import Optional
from datetime import datetime, timedelta

from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials

# Web interface credentials. No fallbacks: an unset variable disables the
# check below rather than silently accepting a value baked into the source.
WEB_USERNAME = os.getenv("PII_WEB_USERNAME", "")
WEB_PASSWORD = os.getenv("PII_WEB_PASSWORD", "")

# API Key for platform integration (more secure than Basic Auth)
API_KEY = os.getenv("PII_API_KEY", "")

# Security
security = HTTPBasic()


def verify_web_credentials(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """Verify web interface credentials."""
    if not WEB_USERNAME or not WEB_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Basic auth is not configured (PII_WEB_USERNAME / PII_WEB_PASSWORD)",
        )

    is_correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"),
        WEB_USERNAME.encode("utf8")
    )
    is_correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"),
        WEB_PASSWORD.encode("utf8")
    )

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def verify_api_key(request: Request) -> bool:
    """Verify API key for platform integration."""
    # Check header
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")

    if not api_key:
        # Check query param
        api_key = request.query_params.get("api_key")

    if not API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API key auth is not configured (PII_API_KEY)",
        )

    if not api_key or not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
    return True


async def get_api_key_optional(request: Request) -> Optional[str]:
    """Get API key if provided (for optional auth)."""
    api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not api_key:
        api_key = request.query_params.get("api_key")
    return api_key
